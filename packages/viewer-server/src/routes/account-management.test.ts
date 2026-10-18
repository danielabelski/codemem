import {
	CoordinatorAccountLinkError,
	type CoordinatorAccountLinkStatusRead,
	type changeCoordinatorAccount,
} from "@codemem/core";
import { afterEach, expect, it, vi } from "vitest";
import type { AccountContextResult } from "../account/context.js";
import { createAccountLinkRegistry } from "../account/link-registry.js";
import { createApp } from "../index.js";

const ORIGIN = "http://127.0.0.1:7441";
const ROOT = "/api/account/link-operations";
const context = {
	contextId: "context-a",
	groupId: "group-a",
	deviceId: "device-a",
	fingerprint: "a".repeat(64),
	identityId: "identity-a",
	dbPath: "/synthetic/never-open.sqlite",
	keysDir: "/synthetic/keys",
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
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const close of cleanup.splice(0)) await close();
});
function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (error: Error) => void;
	const promise = new Promise<T>((yes, no) => {
		resolve = yes;
		reject = no;
	});
	return { resolve, reject, promise };
}
async function fixture() {
	const readContext = vi.fn((): AccountContextResult => structuredClone(ready));
	const readRemoteStatus = vi.fn(
		async (): Promise<CoordinatorAccountLinkStatusRead> => ({
			kind: "status",
			status: {
				version: 3,
				coordinatorId: "coordinator-a",
				groupId: context.groupId,
				deviceId: context.deviceId,
				fingerprint: context.fingerprint,
				identityId: context.identityId,
				authority: "device_claim",
				state: "linked",
				profile: { state: "unavailable" },
				actions: { connect: false, disconnect: true, refresh: true },
			},
		}),
	);
	const done = deferred<Awaited<ReturnType<typeof changeCoordinatorAccount>>>();
	const started = deferred<Parameters<typeof changeCoordinatorAccount>[0]>();
	const link = vi.fn(async () => {
		throw new Error("management must not use the connect runtime");
	});
	const change = vi.fn<typeof changeCoordinatorAccount>((options) => {
		started.resolve(options);
		options.signal?.addEventListener("abort", () =>
			done.reject(new CoordinatorAccountLinkError("link_stopped")),
		);
		return done.promise;
	});
	const registry = createAccountLinkRegistry({ readContext, link, change });
	cleanup.push(() => registry.close());
	const storeFactory = vi.fn(() => {
		throw new Error("local account routes must not open a coordinator store");
	});
	const app = createApp({
		storeFactory,
		accountLink: {
			getListenerAddress: () => ({ host: "127.0.0.1", port: 7441 }),
			readContext,
			readRemoteStatus,
			registry,
		},
	});
	const session = await app.request(`${ORIGIN}/api/account/session`, {
		headers: { Host: "127.0.0.1:7441" },
	});
	const { csrfToken } = await session.json();
	const headers = {
		Host: "127.0.0.1:7441",
		Origin: ORIGIN,
		"X-Codemem-Account-Csrf": csrfToken,
		"Content-Type": "application/json",
	};
	const request = (path: string, body?: unknown, extra: Record<string, string> = {}) =>
		app.request(`${ORIGIN}${path}`, {
			method: body === undefined ? "GET" : "POST",
			headers: { ...headers, ...extra },
			body: body === undefined ? undefined : JSON.stringify(body),
		});
	const start = (intent: "disconnect" | "refresh", extra: Record<string, string> = {}) =>
		request(
			ROOT,
			{
				groupId: context.groupId,
				contextId: context.contextId,
				coordinatorId: "coordinator-a",
				authority: "device_claim",
				intent,
			},
			extra,
		);
	return {
		request,
		start,
		started,
		done,
		link,
		change,
		storeFactory,
		readContext,
		readRemoteStatus,
		registry,
	};
}
it.each(["disconnect", "refresh"] as const)(
	"brokers %s through the single private registry with trusted context pins",
	async (intent) => {
		const f = await fixture();
		const response = await f.start(intent);
		expect(response.status).toBe(202);
		const { operation } = await response.json();
		expect(operation).toMatchObject({ intent, state: "starting", contextId: context.contextId });
		const options = await f.started.promise;
		expect(options).toMatchObject({
			intent,
			dbPath: context.dbPath,
			expectedIdentityId: context.identityId,
			expectedCoordinatorId: "coordinator-a",
		});
		expect(options).not.toHaveProperty("expectedAuthority");
		options.onBrowserStart(
			`${context.coordinatorUrl}/auth/link-change/start?attempt_id=private&start_code=private`,
		);
		const status = await f.request("/api/account/link-status");
		const view = await status.json();
		expect(view).toMatchObject({
			version: 1,
			remote: { state: "linked", profile: { state: "unavailable" } },
			actions: { connect: false, disconnect: false, refresh: false },
			operation: { intent, state: "awaiting_browser" },
		});
		expect(view.remote).not.toHaveProperty("account");
		expect(view).not.toHaveProperty("canLink");
		expect(JSON.stringify(view)).not.toContain("start_code");
		const privateResponse = await f.request(`${ROOT}/${operation.operationId}/browser-url`, {});
		expect(privateResponse.status).toBe(200);
		expect((await privateResponse.json()).url).toContain("/auth/link-change/start");
		expect((await f.start(intent === "refresh" ? "disconnect" : "refresh")).status).toBe(409);
		f.done.resolve({
			coordinatorId: "coordinator-a",
			identityId: context.identityId,
			attemptId: "private",
			state: "completed",
		});
		await Promise.resolve();
		await Promise.resolve();
		expect(f.link).not.toHaveBeenCalled();
		expect(f.storeFactory).not.toHaveBeenCalled();
	},
);
it("requires the local origin and CSRF before dispatching an unlink gesture", async () => {
	const f = await fixture();
	expect((await f.start("disconnect", { Origin: "https://foreign.example.test" })).status).toBe(
		403,
	);
	expect((await f.start("disconnect", { "X-Codemem-Account-Csrf": "" })).status).toBe(403);
	expect(f.change).not.toHaveBeenCalled();
});
it("rejects stale local context even when a previous status allowed disconnect", async () => {
	const f = await fixture();
	f.readRemoteStatus.mockImplementationOnce(async () => {
		f.readContext.mockReturnValue({ ...ready, context: { ...context, contextId: "new-context" } });
		return {
			kind: "status",
			status: {
				version: 3,
				coordinatorId: "coordinator-a",
				groupId: context.groupId,
				deviceId: context.deviceId,
				fingerprint: context.fingerprint,
				identityId: context.identityId,
				authority: "device_claim",
				state: "linked",
				profile: { state: "unavailable" },
				actions: { connect: false, disconnect: true, refresh: true },
			},
		};
	});
	expect((await f.start("disconnect")).status).toBe(409);
	expect(f.change).not.toHaveBeenCalled();
});
it("retains an uncertain management outcome rather than claiming success", async () => {
	const f = await fixture();
	const response = await f.start("disconnect");
	const { operation } = await response.json();
	await f.started.promise;
	f.done.reject(new CoordinatorAccountLinkError("cancellation_unconfirmed"));
	await Promise.resolve();
	await Promise.resolve();
	await Promise.resolve();
	const retained = await f.request(`${ROOT}/${operation.operationId}`);
	expect(await retained.json()).toMatchObject({
		version: 1,
		operation: {
			intent: "disconnect",
			state: "outcome_unknown",
			failure: "cancellation_unconfirmed",
			browserUrlAvailable: false,
		},
	});
});
