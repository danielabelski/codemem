import { afterEach, expect, it, vi } from "vitest";
import { changeCoordinatorAccount } from "./coordinator-account-link-runtime.js";

const mocks = vi.hoisted(() => ({
	close: vi.fn(async () => {}),
	sign: vi.fn(() => ({ "X-Opencode-Signature": "fixture-signature" })),
}));
vi.mock("./coordinator-account-link-signer.js", () => ({
	readAccountLinkDevice: () => ({
		deviceId: "device-a",
		fingerprint: "a".repeat(64),
		publicKey: "fixture-key",
	}),
	signAccountLinkRequest: mocks.sign,
}));
vi.mock("./sync-identity.js", () => ({ loadPrivateKey: () => "fixture-private-key" }));
vi.mock("./coordinator-account-link-receiver.js", async (importOriginal) => {
	const original = await importOriginal<typeof import("./coordinator-account-link-receiver.js")>();
	return {
		...original,
		createCoordinatorAccountLinkReceiver: vi.fn(async () => ({
			destination: "http://127.0.0.1:4567/codemem/auth/complete",
			completion: Promise.resolve(Buffer.alloc(32, 9).toString("base64url")),
			close: mocks.close,
		})),
	};
});
afterEach(() => vi.clearAllMocks());
function fixture(intent: "disconnect" | "refresh", options: { wrongIntent?: boolean } = {}) {
	const calls: Request[] = [];
	let attemptId = "";
	const expiresAtMs = Date.now() + 600000;
	const fetch = vi.fn<typeof globalThis.fetch>(async (url, init) => {
		const request = new Request(url, init);
		calls.push(request.clone());
		const path = new URL(request.url).pathname;
		const body =
			request.method === "POST" ? ((await request.json()) as Record<string, string>) : null;
		let state = "confirmed";
		if (path === "/v1/auth/link-changes") {
			attemptId = body?.attempt_id ?? "";
			state = "pending";
		}
		if (path.endsWith("/finalize")) state = "completed";
		if (path.endsWith("/cancel")) state = "failed";
		const status = {
			attemptId,
			intent: options.wrongIntent ? "connect" : intent,
			state,
			expiresAtMs,
		};
		return Response.json(
			path === "/v1/auth/link-changes"
				? { status, identity_id: "identity-a", coordinator_id: "coordinator-a" }
				: { status },
		);
	});
	return { calls, fetch };
}
it.each(["disconnect", "refresh"] as const)(
	"pins the %s intent, uses signed change endpoints, and acknowledges only completed finalization",
	async (intent) => {
		const f = fixture(intent);
		const browserStart = vi.fn();
		const result = await changeCoordinatorAccount({
			intent,
			dbPath: "synthetic.sqlite",
			groupId: "group-a",
			coordinatorUrl: "https://coordinator.example.test",
			expectedIdentityId: "identity-a",
			expectedCoordinatorId: "coordinator-a",
			fetch: f.fetch,
			onBrowserStart: browserStart,
			assertCurrentContext: () => true,
		});
		expect(result).toMatchObject({
			state: "completed",
			identityId: "identity-a",
			coordinatorId: "coordinator-a",
		});
		expect(mocks.close).toHaveBeenCalledExactlyOnceWith({ completed: true });
		expect(new URL(browserStart.mock.calls[0]?.[0]).pathname).toBe("/auth/link-change/start");
		expect(f.calls.map((r) => new URL(r.url).pathname)).toEqual([
			"/v1/auth/link-changes",
			`/v1/auth/link-changes/${result.attemptId}`,
			`/v1/auth/link-changes/${result.attemptId}/finalize`,
		]);
		const creation = await f.calls[0]?.json();
		expect(Object.keys(creation).sort()).toEqual(
			[
				"group_id",
				"identity_id",
				"intent",
				"attempt_id",
				"runtime_verifier_hash",
				"browser_start_hash",
				"loopback_redirect",
			].sort(),
		);
		expect(creation.intent).toBe(intent);
		const finalized = await f.calls[2]?.json();
		expect(finalized.purpose).toBe("coordinator-account-link-change-v1");
		expect(finalized).not.toHaveProperty("intent");
		expect(mocks.sign).toHaveBeenCalledTimes(3);
	},
);
it("rejects a cross-purpose reply and never releases a success acknowledgement", async () => {
	const f = fixture("disconnect", { wrongIntent: true });
	const browserStart = vi.fn();
	await expect(
		changeCoordinatorAccount({
			intent: "disconnect",
			dbPath: "synthetic.sqlite",
			groupId: "group-a",
			coordinatorUrl: "https://coordinator.example.test",
			expectedIdentityId: "identity-a",
			fetch: f.fetch,
			onBrowserStart: browserStart,
		}),
	).rejects.toMatchObject({ code: "cancellation_unconfirmed" });
	expect(browserStart).not.toHaveBeenCalled();
	expect(mocks.close).toHaveBeenCalledExactlyOnceWith({ completed: false });
	expect(f.calls.some((r) => new URL(r.url).pathname.endsWith("/finalize"))).toBe(false);
});
