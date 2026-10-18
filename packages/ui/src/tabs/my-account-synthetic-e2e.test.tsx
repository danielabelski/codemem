import { once } from "node:events";
import { createServer, request } from "node:http";
import { createRequire } from "node:module";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import type {
	CoordinatorAccountLinkStatusRead,
	changeCoordinatorAccount,
	linkCoordinatorAccount,
} from "@codemem/core";
import { CoordinatorAccountLinkError } from "@codemem/core";
import { render } from "preact";
import { act } from "preact/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountContextResult } from "../../../viewer-server/src/account/context";
import { createAccountGuard } from "../../../viewer-server/src/account/guard";
import { createAccountLinkRegistry } from "../../../viewer-server/src/account/link-registry";
import { accountOperationRoutes } from "../../../viewer-server/src/routes/account-operations";
import { accountStatusRoutes } from "../../../viewer-server/src/routes/account-status";
import type { RecipientPolicyIntentGraphV1 } from "../lib/api/sync";

// Synthetic end-to-end: production Sharing -> API client -> real loopback HTTP ->
// protected production router/registry. Only coordinator, profile and popup are fake.
// This does not exercise Google, a real browser popup, capture, or peer sync.
const PRIVATE = "https://coordinator.example.test/auth/link/start?request=synthetic-private";
const PRIVATE_CHANGE =
	"https://coordinator.example.test/auth/link-change/start?request=synthetic-private-change";
const PATH = "/api/account/link-operations";
const requireServer = createRequire(
	resolve(import.meta.dirname, "../../../viewer-server/package.json"),
);
const { Hono } = requireServer("hono") as {
	Hono: new () => ReturnType<typeof createAccountGuard>["routes"];
};
const context = {
	contextId: "context-a",
	groupId: "group-a",
	deviceId: "device-a",
	fingerprint: "a".repeat(64),
	identityId: "identity-a",
	identityLabel: "Synthetic identity",
	deviceLabel: "Synthetic device",
	dbPath: "/synthetic/never-open.sqlite",
	keysDir: "/synthetic/never-open-keys",
	coordinatorUrl: "https://coordinator.example.test",
	fileIdentity: { dev: "1", ino: "2" },
};
const ready = {
	setup: "ready" as const,
	groups: [context.groupId],
	selectedGroupId: context.groupId,
	coordinator: { origin: context.coordinatorUrl },
	context,
};
const graph: RecipientPolicyIntentGraphV1 = {
	version: 1,
	identities: [],
	teams: [],
	teamMemberships: [],
	identityDevices: [],
	projectRecipients: [],
};
type RemoteState =
	| "unlinked"
	| "disconnected"
	| "linked"
	| "review_required"
	| "conflict"
	| "revoked";
function remote(state: RemoteState = "unlinked"): CoordinatorAccountLinkStatusRead {
	const subject = {
		version: 3 as const,
		coordinatorId: "coordinator-a",
		groupId: context.groupId,
		deviceId: context.deviceId,
		fingerprint: context.fingerprint,
		profile: { state: "unavailable" as const },
		actions: { connect: false, disconnect: false, refresh: false },
	};
	if (state === "review_required" || state === "conflict")
		return {
			kind: "status",
			status: { ...subject, state, identityId: null, authority: null },
		};
	return {
		kind: "status",
		status: {
			...subject,
			identityId: context.identityId,
			authority: "device_claim",
			state,
			profile:
				state === "linked"
					? {
							state: "verified",
							verifiedAtMs: 1,
							displayName: "Synthetic person",
							email: "fake@example.test",
						}
					: { state: "unavailable" },
			actions: {
				connect: state === "unlinked" || state === "disconnected",
				disconnect: state === "linked",
				refresh: state === "linked",
			},
		},
	};
}
function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (error: Error) => void;
	const promise = new Promise<T>((yes, no) => {
		resolve = yes;
		reject = no;
	});
	return { promise, resolve, reject };
}
const finalResult = {
	coordinatorId: "coordinator-a",
	identityId: context.identityId,
	attemptId: "synthetic-attempt",
	state: "finalized" as const,
};
const cleanup: (() => Promise<unknown>)[] = [];
let mount: HTMLDivElement;
beforeEach(() => {
	vi.resetModules(); // Every client bootstraps its own in-memory CSRF token.
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	mount = document.createElement("div");
	document.body.append(mount);
});
afterEach(async () => {
	try {
		act(() => render(null, mount));
		mount.remove();
		for (const close of cleanup.splice(0).reverse()) await close();
		expect(vi.getTimerCount()).toBe(0);
	} finally {
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
		vi.useRealTimers();
	}
});
function button(name: string) {
	const node = [...mount.querySelectorAll<HTMLButtonElement>("button")].find(
		(candidate) => candidate.textContent === name,
	);
	if (!node) throw new Error(`Missing synthetic E2E button: ${name}`);
	return node;
}
async function httpBridge(app: ReturnType<typeof createAccountGuard>["routes"]) {
	const server = createServer(async (req, res) => {
		try {
			const chunks: Buffer[] = [];
			for await (const chunk of req) chunks.push(Buffer.from(chunk));
			const body = Buffer.concat(chunks).toString();
			const response = await app.request(`http://${req.headers.host}${req.url}`, {
				method: req.method,
				headers: req.headers as Record<string, string>,
				...(body ? { body } : {}),
			});
			res.writeHead(response.status, Object.fromEntries(response.headers));
			res.end(await response.text());
		} catch {
			res.writeHead(500);
			res.end("Synthetic HTTP bridge failure");
		}
	});
	cleanup.push(async () => {
		const closed = new Promise<void>((resolve, reject) =>
			server.close((error) => (error ? reject(error) : resolve())),
		);
		server.closeAllConnections();
		await closed;
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	const port = (server.address() as AddressInfo).port;
	const origin = `http://127.0.0.1:${port}`;
	const seen: {
		path: string;
		method: string;
		headers: Headers;
		status: number;
		body: string;
		requestBody: string | null;
	}[] = [];
	const pending = new Set<Promise<Response>>();
	function send(path: string, init: RequestInit = {}) {
		// This is the simulated document origin. Never derive it from arbitrary input.
		const headers = new Headers(init.headers);
		if (!headers.has("Origin")) headers.set("Origin", origin);
		const response = new Promise<Response>((resolve, reject) => {
			const req = request(
				{
					hostname: "127.0.0.1",
					port,
					path,
					agent: false,
					method: init.method ?? "GET",
					headers: Object.fromEntries(headers),
				},
				(res) => {
					const chunks: Buffer[] = [];
					res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
					res.on("end", () => {
						const body = Buffer.concat(chunks).toString();
						seen.push({
							path,
							method: init.method ?? "GET",
							headers,
							status: res.statusCode ?? 500,
							body,
							requestBody: typeof init.body === "string" ? init.body : null,
						});
						resolve(
							new Response(body, {
								status: res.statusCode,
								headers: res.headers as Record<string, string>,
							}),
						);
					});
				},
			);
			req.on("error", reject);
			if (init.signal?.aborted) req.destroy(new Error("Synthetic request aborted"));
			else
				init.signal?.addEventListener(
					"abort",
					() => req.destroy(new Error("Synthetic request aborted")),
					{ once: true },
				);
			req.end(init.body);
		});
		pending.add(response);
		void response.then(
			() => pending.delete(response),
			() => pending.delete(response),
		);
		return response;
	}
	return { port, origin, seen, pending, send };
}
function syntheticCoordinator() {
	let coordinator = remote();
	const readRemoteStatus = vi.fn(
		async (): Promise<CoordinatorAccountLinkStatusRead> => structuredClone(coordinator),
	);
	const done = deferred<Awaited<ReturnType<typeof linkCoordinatorAccount>>>();
	const started = deferred<Parameters<typeof linkCoordinatorAccount>[0]>();
	type RuntimeOptions =
		| Parameters<typeof linkCoordinatorAccount>[0]
		| Parameters<typeof changeCoordinatorAccount>[0];
	const runs: {
		intent: "connect" | "disconnect" | "refresh";
		options: RuntimeOptions;
		finish(): void;
	}[] = [];
	let abortError: Error | null = new CoordinatorAccountLinkError("link_stopped");
	let browserUrl: string | undefined;
	const link = vi.fn<typeof linkCoordinatorAccount>((options) => {
		const completion =
			runs.length === 0 ? done : deferred<Awaited<ReturnType<typeof linkCoordinatorAccount>>>();
		runs.push({ intent: "connect", options, finish: () => completion.resolve(finalResult) });
		started.resolve(options);
		options.signal?.addEventListener("abort", () => {
			if (abortError) completion.reject(abortError);
		});
		options.onBrowserStart?.(browserUrl ?? PRIVATE);
		return completion.promise;
	});
	const change = vi.fn<typeof changeCoordinatorAccount>((options) => {
		const completion = deferred<Awaited<ReturnType<typeof changeCoordinatorAccount>>>();
		runs.push({
			intent: options.intent,
			options,
			finish: () => completion.resolve({ ...finalResult, state: "completed" }),
		});
		options.signal?.addEventListener("abort", () => {
			if (abortError) completion.reject(abortError);
		});
		options.onBrowserStart?.(browserUrl ?? PRIVATE_CHANGE);
		return completion.promise;
	});
	// Coordinator effects below are synthetic: only an explicitly completed, current,
	// non-cancelled matching ceremony changes the fake coordinator's status.
	function complete(
		intent: "connect" | "disconnect" | "refresh",
		options: { emptyProfile?: boolean } = {},
	) {
		const run = runs.at(-1);
		if (
			!run ||
			run.intent !== intent ||
			run.options.signal?.aborted ||
			!run.options.assertCurrentContext?.()
		)
			throw new Error("Synthetic ceremony is not current");
		if (
			coordinator.kind !== "status" ||
			(intent === "connect"
				? !["unlinked", "disconnected"].includes(coordinator.status.state)
				: coordinator.status.state !== "linked")
		)
			throw new Error("Synthetic intent is not allowed");
		coordinator = remote(intent === "disconnect" ? "disconnected" : "linked");
		if (options.emptyProfile && coordinator.kind === "status")
			coordinator.status.profile = { state: "verified", verifiedAtMs: 2 };
		run.finish();
	}
	return {
		readRemoteStatus,
		done,
		started,
		link,
		change,
		complete,
		finishPending() {
			done.resolve(finalResult);
			for (const run of runs) run.finish();
		},
		setAbortError(error: Error | null) {
			abortError = error;
		},
		setBrowserUrl(url: string) {
			browserUrl = url;
		},
	};
}
async function fixture() {
	const readContext = vi.fn((_group?: string): AccountContextResult => structuredClone(ready));
	const runtime = syntheticCoordinator();
	const { readRemoteStatus, link, change } = runtime;
	const registry = createAccountLinkRegistry({ readContext, link, change });
	const address = { host: "127.0.0.1", port: 0 };
	const options = { getListenerAddress: () => address, readContext, readRemoteStatus, registry };
	// Same middleware and router order as registerAccountRoutes; no store is involved.
	const guard = createAccountGuard(options);
	const app = new Hono();
	app.use("*", guard.middleware);
	app.route("/", guard.routes);
	app.route("/", accountStatusRoutes(options));
	app.route("/", accountOperationRoutes(options));
	const { port, origin, seen, pending, send } = await httpBridge(app);
	address.port = port;
	cleanup.push(async () => {
		// Release even an intentionally uncooperative late-completion fixture.
		runtime.finishPending();
		await registry.close();
	});
	vi.stubGlobal(
		"fetch",
		vi.fn((input: string, init?: RequestInit) => {
			if (!input.startsWith("/api/account/"))
				throw new Error("Unexpected external network request");
			return send(input, init);
		}),
	);
	const storage = vi.spyOn(Storage.prototype, "setItem");
	const popup = { opener: {}, closed: false, close: vi.fn(), location: { replace: vi.fn() } };
	const open = vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);
	async function drain() {
		// Drain actual socket completions plus Preact effects; no wall-clock sleeps.
		for (let turn = 0; turn < 8; turn++) {
			await act(async () => {
				await Promise.allSettled([...pending]);
				await vi.advanceTimersByTimeAsync(0);
			});
		}
	}
	async function show() {
		const { mountRecipientPolicySharing } = await import("./recipient-policy-sharing");
		await act(async () => mountRecipientPolicySharing(mount, [], graph));
		await drain();
	}
	async function click(name: string) {
		act(() => button(name).click());
		await drain();
	}
	async function poll() {
		await act(async () => {
			await vi.advanceTimersByTimeAsync(1000);
		});
		await drain();
	}
	function noLeaks() {
		expect(mount.innerHTML).not.toContain(PRIVATE);
		expect(mount.innerHTML).not.toContain(PRIVATE_CHANGE);
		expect(mount.innerHTML).not.toContain(context.dbPath);
		const session = seen.find((entry) => entry.path === "/api/account/session");
		if (session) expect(mount.innerHTML).not.toContain(JSON.parse(session.body).csrfToken);
		expect(storage).not.toHaveBeenCalled();
		expect(
			seen
				.filter((entry) => !entry.path.endsWith("/browser-url"))
				.map((entry) => entry.body)
				.join(""),
		).not.toContain(PRIVATE);
		expect(
			seen
				.filter((entry) => !entry.path.endsWith("/browser-url"))
				.map((entry) => entry.body)
				.join(""),
		).not.toContain(PRIVATE_CHANGE);
		expect(seen.map((entry) => entry.path).join("")).not.toContain("synthetic-private");
	}
	return {
		...runtime,
		readContext,
		registry,
		send,
		seen,
		origin,
		storage,
		popup,
		open,
		show,
		click,
		poll,
		drain,
		noLeaks,
	};
}

describe("My Account synthetic end-to-end over protected loopback HTTP", () => {
	it("reads status without starting and hands off only after an authorized user gesture", async () => {
		// Arrange
		const f = await fixture();
		await f.show();
		expect(mount.textContent).toContain("No Google account is linked");
		expect(f.link).not.toHaveBeenCalled();
		expect(f.open).not.toHaveBeenCalled();
		expect(f.seen.map((entry) => entry.path)).toEqual([
			"/api/account/session",
			"/api/account/link-status",
		]);
		// Act
		await f.click("Link Google account");
		await f.poll();
		// Assert: the real CSRF bootstrap, start, registry and private POST delivery all ran.
		expect(f.link).toHaveBeenCalledOnce();
		expect(await f.started.promise).toMatchObject({
			dbPath: context.dbPath,
			expectedIdentityId: context.identityId,
			expectedAuthority: "device_claim",
		});
		expect(f.open).toHaveBeenCalledExactlyOnceWith("about:blank", "_blank");
		expect(f.popup.opener).toBeNull();
		expect(f.popup.location.replace).toHaveBeenCalledExactlyOnceWith(PRIVATE);
		expect(f.seen.find((entry) => entry.path === PATH)).toMatchObject({
			method: "POST",
			status: 202,
		});
		expect(f.seen.find((entry) => entry.path.endsWith("/browser-url"))).toMatchObject({
			method: "POST",
			status: 200,
		});
		f.noLeaks();
	});
	it("offers a URL-free fallback when popup reservation is blocked, then verifies success by status", async () => {
		// Arrange
		const f = await fixture();
		f.open.mockReturnValue(null);
		await f.show();
		// Act
		await f.click("Link Google account");
		await f.poll();
		expect(button("Open Google sign-in")).toBeTruthy();
		f.noLeaks();
		f.open.mockReturnValue(f.popup as unknown as Window);
		await f.click("Open Google sign-in");
		f.readRemoteStatus.mockResolvedValue(remote("linked"));
		f.done.resolve(finalResult);
		await f.poll();
		// Assert
		expect(f.open).toHaveBeenLastCalledWith("about:blank", "_blank");
		expect(f.popup.opener).toBeNull();
		expect(f.popup.location.replace).toHaveBeenCalledWith(PRIVATE);
		expect(f.popup.close).toHaveBeenCalledTimes(1);
		expect(mount.textContent).toContain("fake@example.test");
		expect(
			[...mount.querySelectorAll("button")].some(
				(node) => node.textContent === "Link Google account",
			),
		).toBe(false);
		expect(button("Refresh profile").disabled).toBe(false);
		expect(button("Unlink Google account").disabled).toBe(false);
		expect(mount.textContent).not.toContain("Open Google sign-in");
		f.noLeaks();
	});
});

describe("My Account management through Viewer HTTP with a synthetic coordinator", () => {
	it("connects, replaces verified profile with an empty snapshot, disconnects, and connects again", async () => {
		// Arrange: only coordinator ceremonies/status and popup are fake, not Viewer authorization.
		const f = await fixture();
		await f.show();
		// Act / Assert: connecting requires an explicit gesture and completed matching ceremony.
		await f.click("Link Google account");
		expect(mount.textContent).not.toContain("fake@example.test");
		f.complete("connect");
		await f.poll();
		expect(mount.textContent).toContain("fake@example.test");
		expect(button("Refresh profile").disabled).toBe(false);
		// Act / Assert: refresh uses a distinct change ceremony and clears all earlier fields.
		await f.click("Refresh profile");
		await f.poll();
		expect(f.change).toHaveBeenCalledTimes(1);
		expect(f.change.mock.calls[0]?.[0]).toMatchObject({
			intent: "refresh",
			expectedIdentityId: context.identityId,
			expectedCoordinatorId: "coordinator-a",
		});
		expect(f.popup.location.replace).toHaveBeenLastCalledWith(PRIVATE_CHANGE);
		f.complete("refresh", { emptyProfile: true });
		await f.poll();
		expect(mount.textContent).not.toContain("fake@example.test");
		expect(mount.textContent).not.toContain("Synthetic person");
		expect(mount.querySelector(".my-account-profile strong")?.textContent).toBe("Google account");
		expect(mount.textContent).toContain(
			"This Google account is linked to the local Codemem Identity",
		);
		const refreshed = f.seen
			.filter((entry) => entry.path.startsWith("/api/account/link-status"))
			.at(-1);
		expect(JSON.parse(refreshed?.body ?? "null")).toMatchObject({
			version: 1,
			remote: { state: "linked", profile: { state: "verified", verifiedAtMs: 2 } },
			actions: { connect: false, disconnect: true, refresh: true },
		});
		// Act / Assert: unlink completion returns disconnected, preserving the selected local Identity.
		await f.click("Unlink Google account");
		f.complete("disconnect");
		await f.poll();
		expect(mount.textContent).toContain("Google account disconnected");
		expect(mount.textContent).toContain(context.identityLabel);
		expect(button("Link Google account").disabled).toBe(false);
		expect(mount.textContent).not.toContain("Refresh profile");
		// Act / Assert: reconnect is another operation, never an automatic unlink/relink side effect.
		await f.click("Link Google account");
		f.complete("connect");
		await f.poll();
		expect(mount.textContent).toContain("fake@example.test");
		expect(f.link).toHaveBeenCalledTimes(2);
		expect(f.change.mock.calls.map(([options]) => options.intent)).toEqual([
			"refresh",
			"disconnect",
		]);
		const starts = f.seen.filter((entry) => entry.path === PATH && entry.method === "POST");
		expect(starts.map((entry) => entry.status)).toEqual([202, 202, 202, 202]);
		expect(starts.map((entry) => JSON.parse(entry.requestBody ?? "null"))).toEqual(
			["connect", "refresh", "disconnect", "connect"].map((intent) => ({
				groupId: context.groupId,
				contextId: context.contextId,
				authority: "device_claim",
				coordinatorId: "coordinator-a",
				intent,
			})),
		);
		// No browser-nominated account, target link, generation or callback is sent to Viewer.
		expect(f.readContext()).toEqual(ready);
		f.noLeaks();
	});
});

describe("My Account synthetic management cancellation and private handoffs", () => {
	it.each(["refresh", "disconnect"] as const)(
		"cancelling %s does not unlink or silently retry",
		async (intent) => {
			// Arrange
			const f = await fixture();
			await f.show();
			await f.click("Link Google account");
			f.complete("connect");
			await f.poll();
			await f.click(intent === "refresh" ? "Refresh profile" : "Unlink Google account");
			// Act
			await f.click(intent === "refresh" ? "Cancel profile refresh" : "Cancel unlinking");
			await f.poll();
			await f.click("Check status");
			// Assert: cancelling the active change does not complete it or create a second change.
			expect(f.change.mock.calls[0]?.[0].signal?.aborted).toBe(true);
			expect(f.registry.forContext(context.contextId)).toMatchObject({
				intent,
				state: "cancelled",
				failure: "link_stopped",
			});
			expect(mount.textContent).toContain("fake@example.test");
			expect(mount.textContent).not.toContain("Google account disconnected");
			expect(f.change).toHaveBeenCalledTimes(1);
			expect(f.link).toHaveBeenCalledTimes(1);
			f.noLeaks();
		},
	);
	it.each([
		PRIVATE,
		"https://foreign.example.test/auth/link-change/start?request=synthetic-private-change",
	])("rejects a mismatched private change handoff %s", async (url) => {
		// Arrange: start from a linked account; the fake change runtime emits a wrong-purpose/origin URL.
		const f = await fixture();
		await f.show();
		await f.click("Link Google account");
		f.complete("connect");
		await f.poll();
		f.setBrowserUrl(url);
		f.popup.location.replace.mockClear();
		const deliveriesBefore = f.seen.filter((entry) => entry.path.endsWith("/browser-url")).length;
		// Act
		await f.click("Refresh profile");
		await f.poll();
		// Assert: production registry rejects the URL, not the mock transport.
		expect(f.registry.forContext(context.contextId)).toMatchObject({
			intent: "refresh",
			state: "failed",
			failure: "invalid_response",
			browserUrlAvailable: false,
		});
		expect(f.change.mock.calls[0]?.[0].signal?.aborted).toBe(true);
		expect(f.popup.location.replace).not.toHaveBeenCalled();
		expect(f.seen.filter((entry) => entry.path.endsWith("/browser-url"))).toHaveLength(
			deliveriesBefore,
		);
		expect(mount.innerHTML).not.toContain(url);
		expect(
			f.seen
				.filter((entry) => !entry.path.endsWith("/browser-url"))
				.map((entry) => entry.body)
				.join(""),
		).not.toContain(url);
		expect(mount.textContent).toContain("fake@example.test");
		f.noLeaks();
	});
});

async function authorizedStart(
	f: Awaited<ReturnType<typeof fixture>>,
	changes: Record<string, unknown>,
) {
	const token = f.seen.find((entry) => entry.path === "/api/account/session");
	if (!token) throw new Error("Expected real account session bootstrap");
	return f.send(PATH, {
		method: "POST",
		headers: {
			Origin: f.origin,
			"Content-Type": "application/json",
			"X-Codemem-Account-Csrf": JSON.parse(token.body).csrfToken,
		},
		body: JSON.stringify({
			groupId: context.groupId,
			contextId: context.contextId,
			coordinatorId: "coordinator-a",
			authority: "device_claim",
			intent: "connect",
			...changes,
		}),
	});
}

describe("My Account management rejects browser-nominated authority", () => {
	it.each([
		[{ intent: "refresh" }, 409, "account_link_not_allowed"],
		[{ intent: "disconnect" }, 409, "account_link_not_allowed"],
		[{ intent: "unlink" }, 400, "account_invalid_request"],
		[{ contextId: "stale-context" }, 409, "account_context_changed"],
		[{ targetLinkId: "browser-picked-link" }, 400, "account_invalid_request"],
	] as const)("denies %j without starting a ceremony", async (body, status, error) => {
		// Arrange: use the production CSRF bootstrap and an unlinked canonical V3 status.
		const f = await fixture();
		await f.show();
		// Act
		const response = await authorizedStart(f, body);
		// Assert
		expect(response.status).toBe(status);
		expect(await response.json()).toMatchObject({ error });
		expect(f.link).not.toHaveBeenCalled();
		expect(f.change).not.toHaveBeenCalled();
		expect(f.registry.hasActive()).toBe(false);
		f.noLeaks();
	});
});

describe("My Account synthetic end-to-end terminal states and context lifetime", () => {
	it.each(["review_required", "conflict", "revoked"] as const)(
		"keeps %s read-only and Sharing navigable",
		async (state) => {
			// Arrange
			const f = await fixture();
			f.readRemoteStatus.mockResolvedValue(remote(state));
			// Act
			await f.show();
			await f.click("Check status");
			const tabs = [...mount.querySelectorAll<HTMLButtonElement>('[role="tab"]')];
			act(() => tabs[1].click());
			// Assert
			expect(tabs[1].getAttribute("aria-selected")).toBe("true");
			expect(
				[...mount.querySelectorAll("button")].some((node) =>
					["Link Google account", "Refresh profile", "Unlink Google account"].includes(
						node.textContent ?? "",
					),
				),
			).toBe(false);
			expect(mount.textContent).toContain(
				{
					review_required: "Check the selected profile and group",
					conflict: "conflicting account link",
					revoked: "was revoked",
				}[state],
			);
			if (state === "review_required") {
				const details = mount.querySelector<HTMLDetailsElement>(
					"details.recipient-policy-management-details",
				);
				expect(details?.open).toBe(false);
				expect(details?.querySelector("summary")?.textContent).toBe("What to check before linking");
				expect(details?.textContent).toMatch(
					/person who runs the coordinator.*device.*existing account link/,
				);
				expect(mount.textContent).not.toMatch(
					/review-device-owner|enroll-owner|one-time owner review|administrator|credential/i,
				);
			}
			expect(f.link).not.toHaveBeenCalled();
			expect(f.open).not.toHaveBeenCalled();
			expect(f.seen.every((entry) => entry.method === "GET")).toBe(true);
			f.noLeaks();
		},
	);
	it.each(["cancelled", "outcome_unknown"] as const)(
		"shows %s without claiming a linked account",
		async (outcome) => {
			// Arrange
			const f = await fixture();
			if (outcome === "outcome_unknown") {
				f.setAbortError(
					Object.assign(new CoordinatorAccountLinkError("cancellation_unconfirmed"), {
						cause: PRIVATE,
					}),
				);
			}
			await f.show();
			await f.click("Link Google account");
			if (outcome === "outcome_unknown")
				f.readRemoteStatus.mockResolvedValue({
					kind: "unavailable",
					code: "coordinator_unreachable",
				});
			// Act
			await f.click("Cancel linking");
			await f.poll();
			// Assert
			expect((await f.started.promise).signal?.aborted).toBe(true);
			expect(f.registry.forContext(context.contextId)).toMatchObject({
				intent: "connect",
				state: outcome,
			});
			expect(mount.textContent).toContain(
				outcome === "cancelled"
					? "Cancellation was reported"
					: "couldn’t confirm whether the account operation finished",
			);
			expect(mount.textContent).not.toContain("fake@example.test");
			expect(f.seen.some((entry) => entry.path.endsWith("/cancel") && entry.status === 202)).toBe(
				true,
			);
			f.noLeaks();
		},
	);
});

describe("My Account synthetic end-to-end late context completion", () => {
	it("does not relabel a late old-context completion as the newly selected Identity", async () => {
		// Arrange: runtime deliberately ignores cancellation until explicitly completed.
		const f = await fixture();
		f.setAbortError(null);
		await f.show();
		await f.click("Link Google account");
		const old = f.registry.forContext(context.contextId);
		if (!old) throw new Error("Expected synthetic operation");
		f.readContext.mockReturnValue({
			...ready,
			context: {
				...context,
				contextId: "context-b",
				identityId: "identity-b",
				identityLabel: "New synthetic identity",
			},
		});
		f.readRemoteStatus.mockResolvedValue({ kind: "unavailable", code: "coordinator_unreachable" });
		// Act
		expect(button("Check status").disabled).toBe(true);
		await f.click("Check status");
		f.done.resolve(finalResult);
		await f.drain();
		await f.poll();
		// Assert
		expect(f.registry.get(old.operationId)).toMatchObject({
			contextId: "context-a",
			state: "succeeded",
		});
		expect(mount.textContent).toContain("New synthetic identity");
		expect(mount.textContent).toContain(
			"The earlier link finished for its original Identity. Check status there to confirm.",
		);
		expect(mount.textContent).not.toContain("fake@example.test");
		expect(
			[...mount.querySelectorAll("button")].some((node) =>
				["Link Google account", "Refresh profile", "Unlink Google account"].includes(
					node.textContent ?? "",
				),
			),
		).toBe(false);
		expect(f.link).toHaveBeenCalledOnce();
		f.noLeaks();
	});
});

describe("My Account synthetic end-to-end request authority", () => {
	it.each(["foreign-origin", "foreign-port", "foreign-host", "missing-csrf"] as const)(
		"denies %s before runtime start or private URL delivery",
		async (attack) => {
			// Arrange: use the genuine client-bootstrap token, not a bypass token.
			const f = await fixture();
			await f.show();
			const token = f.seen
				.find((entry) => entry.path.includes("link-status"))
				?.headers.get("X-Codemem-Account-Csrf");
			if (!token) throw new Error("Expected real account session token");
			const headers = {
				Origin: f.origin,
				"X-Codemem-Account-Csrf": token,
				"Content-Type": "application/json",
			};
			if (attack === "foreign-origin") headers.Origin = "https://foreign.example.test";
			if (attack === "foreign-port") headers.Origin = "http://127.0.0.1:1";
			if (attack === "foreign-host") Object.assign(headers, { Host: "127.0.0.1:1" });
			if (attack === "missing-csrf") headers["X-Codemem-Account-Csrf"] = "";
			const reads = f.readContext.mock.calls.length;
			// Act
			const start = await f.send(PATH, {
				method: "POST",
				headers,
				body: JSON.stringify({
					groupId: context.groupId,
					contextId: context.contextId,
					authority: "device_claim",
					coordinatorId: "coordinator-a",
					intent: "connect",
				}),
			});
			const delivery = await f.send(`${PATH}/00000000-0000-4000-8000-000000000000/browser-url`, {
				method: "POST",
				headers,
				body: "{}",
			});
			// Assert: Origin, exact Host port and CSRF are checked by production middleware.
			const expectedHeaders = Object.fromEntries(new Headers(headers));
			expect(f.seen.slice(-2).map((entry) => Object.fromEntries(entry.headers))).toEqual([
				expectedHeaders,
				expectedHeaders,
			]);
			for (const response of [start, delivery]) {
				expect(response.status).toBe(403);
				expect(response.headers.get("cache-control")).toBe("no-store");
				expect(response.headers.get("referrer-policy")).toBe("no-referrer");
				expect(
					[...response.headers.keys()].filter((key) => key.startsWith("access-control-")),
				).toEqual([]);
				const body = await response.text();
				expect(body).not.toContain(PRIVATE);
				expect(JSON.parse(body).error).toBe(
					{
						"foreign-origin": "account_request_rejected",
						"foreign-port": "account_request_rejected",
						"foreign-host": "account_request_rejected",
						"missing-csrf": "account_csrf_invalid",
					}[attack],
				);
			}
			expect(f.readContext).toHaveBeenCalledTimes(reads);
			expect(f.link).not.toHaveBeenCalled();
			// A real private URL exists now: the same hostile request still cannot retrieve it.
			const authorized = await f.send(PATH, {
				method: "POST",
				headers: {
					...headers,
					Origin: f.origin,
					Host: new URL(f.origin).host,
					"X-Codemem-Account-Csrf": token,
				},
				body: JSON.stringify({
					groupId: context.groupId,
					contextId: context.contextId,
					authority: "device_claim",
					coordinatorId: "coordinator-a",
					intent: "connect",
				}),
			});
			expect(authorized.status).toBe(202);
			expect(f.seen.slice(-1).map((entry) => entry.headers.get("Origin"))).toEqual([f.origin]);
			const active = f.registry.forContext(context.contextId);
			if (!active) throw new Error("Expected authorized synthetic operation");
			const protectedDelivery = await f.send(`${PATH}/${active.operationId}/browser-url`, {
				method: "POST",
				headers,
				body: "{}",
			});
			expect(protectedDelivery.status).toBe(403);
			expect(f.seen.slice(-1).map((entry) => entry.headers.get("Origin"))).toEqual([
				headers.Origin,
			]);
			expect(await protectedDelivery.text()).not.toContain(PRIVATE);
			expect(f.link).toHaveBeenCalledOnce();
			f.noLeaks();
		},
	);
});
