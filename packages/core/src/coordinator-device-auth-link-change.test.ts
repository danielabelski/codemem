import { Hono } from "hono";
import { afterEach, expect, it, vi } from "vitest";
import { AUTH_LINK_CHANGE_PURPOSE } from "./coordinator-auth-link-change-contract.js";
import { setupStore } from "./coordinator-auth-store-test-fixtures.js";
import type { DeviceAuthLinkDeps } from "./coordinator-device-auth-link.js";
import { registerCoordinatorDeviceAuthLinkChangeRoutes } from "./coordinator-device-auth-link-change.js";

const origin = "https://coordinator.example.test";
const config = {
	enabled: true,
	coordinatorId: "coordinator-a",
	issuer: "https://accounts.google.com",
	revision: "a".repeat(64),
	redirectUri: `${origin}/auth/callback`,
};
const create = {
	group_id: "group-a",
	identity_id: "identity-a",
	intent: "disconnect",
	attempt_id: "attempt-a",
	runtime_verifier_hash: "b".repeat(64),
	browser_start_hash: "c".repeat(64),
	loopback_redirect: "http://127.0.0.1:4567/codemem/auth/complete",
};
const cleanup: (() => void)[] = [];
afterEach(() => {
	vi.restoreAllMocks();
	for (const close of cleanup.splice(0)) close();
});
function fixture() {
	const { store, db } = setupStore("SQLite");
	cleanup.push(() => {
		if (db.open) db.close();
	});
	// These are HTTP boundary tests. Native persistence/authority and OIDC are
	// exercised separately; the production API supplies its existing authorizer.
	vi.spyOn(store, "assertAuthSchemaReady").mockResolvedValue();
	vi.spyOn(store, "close").mockResolvedValue();
	const makeStatus = (state: "pending" | "completed" | "failed") => ({
		attemptId: "attempt-a",
		intent: "disconnect" as const,
		state,
		expiresAtMs: Date.now() + 600000,
	});
	const created = vi
		.spyOn(store.accountManagement, "createAuthLinkChangeAttempt")
		.mockResolvedValue({ kind: "created", status: makeStatus("pending") });
	const finalized = vi
		.spyOn(store.accountManagement, "finalizeAuthLinkChangeAttempt")
		.mockResolvedValue({ kind: "applied", status: makeStatus("completed") });
	const authorizeRequest = vi.fn<DeviceAuthLinkDeps["authorizeRequest"]>(async () => ({
		ok: true,
		error: "",
		enrollment: {
			group_id: "group-a",
			device_id: "device-a",
			public_key: "fixture-key",
			fingerprint: "d".repeat(64),
			enabled: 1,
			identity_id: "identity-a",
			created_at: "fixture",
		},
	}));
	const deps: DeviceAuthLinkDeps = {
		config,
		storeFactory: () => store,
		authorizeRequest,
		authErrorStatus: () => 403,
		readRequestBytes: async (c, max) => {
			const bytes = new Uint8Array(await c.req.raw.arrayBuffer());
			return bytes.length <= max ? bytes : null;
		},
		parseJsonObject: (bytes) => {
			try {
				const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
				return value && typeof value === "object" && !Array.isArray(value)
					? (value as Record<string, unknown>)
					: null;
			} catch {
				return null;
			}
		},
		rateLimitedResponse: () => null,
	};
	const app = new Hono();
	registerCoordinatorDeviceAuthLinkChangeRoutes(app, deps);
	const request = (path: string, body: unknown) =>
		app.request(`${origin}${path}`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Opencode-Device": "device-a",
				"X-Opencode-Signature": "fixture-signature",
				"X-Opencode-Timestamp": "123",
				"X-Opencode-Nonce": "fixture-nonce",
			},
			body: JSON.stringify(body),
		});
	return { app, request, created, finalized, authorizeRequest };
}
it("accepts only the seven-field signed change creation body and derives signer data from authorization", async () => {
	const f = fixture();
	const response = await f.request("/v1/auth/link-changes", create);
	expect(response.status).toBe(201);
	expect(f.authorizeRequest).toHaveBeenCalledOnce();
	expect(f.created).toHaveBeenCalledExactlyOnceWith(
		{
			attemptId: "attempt-a",
			identityId: "identity-a",
			intent: "disconnect",
			runtimeVerifierHash: create.runtime_verifier_hash,
			browserStartHash: create.browser_start_hash,
			loopbackRedirect: create.loopback_redirect,
			signer: {
				groupId: "group-a",
				deviceId: "device-a",
				publicKey: "fixture-key",
				fingerprint: "d".repeat(64),
			},
		},
		config,
	);
});
it.each([
	{ target_link_id: "nominated" },
	{ generation: 2 },
	{ role: "owner" },
	{ account_subject: "private-account" },
	{ intent: "switch" },
])("rejects client-selected target or authority fields before authorization", async (extra) => {
	const f = fixture();
	expect((await f.request("/v1/auth/link-changes", { ...create, ...extra })).status).toBe(400);
	expect(f.authorizeRequest).not.toHaveBeenCalled();
	expect(f.created).not.toHaveBeenCalled();
});
it("hashes runtime and completion proofs and requires the exact signed finalization purpose", async () => {
	const f = fixture();
	const body = {
		purpose: AUTH_LINK_CHANGE_PURPOSE,
		coordinator_id: config.coordinatorId,
		attempt_id: "attempt-a",
		group_id: "group-a",
		identity_id: "identity-a",
		device_id: "device-a",
		fingerprint: "d".repeat(64),
		runtime_verifier: Buffer.alloc(32, 1).toString("base64url"),
		completion: Buffer.alloc(32, 2).toString("base64url"),
	};
	expect(
		(
			await f.request("/v1/auth/link-changes/attempt-a/finalize", {
				...body,
				purpose: "coordinator-account-link-v1",
			})
		).status,
	).toBe(400);
	expect((await f.request("/v1/auth/link-changes/another-attempt/finalize", body)).status).toBe(
		400,
	);
	expect((await f.request("/v1/auth/link-changes/attempt-a/finalize", body)).status).toBe(200);
	const input = f.finalized.mock.calls[0]?.[0];
	expect(input?.runtimeVerifierHash).toMatch(/^[0-9a-f]{64}$/);
	expect(input?.completionSecretHash).toMatch(/^[0-9a-f]{64}$/);
	expect(input).not.toHaveProperty("completion");
	expect(input).not.toHaveProperty("runtimeVerifier");
});
it("permits only the group query on a device status read", async () => {
	const f = fixture();
	expect(
		(await f.app.request(`${origin}/v1/auth/link-changes/attempt-a?group_id=group-a&role=owner`))
			.status,
	).toBe(400);
	expect(f.authorizeRequest).not.toHaveBeenCalled();
});
