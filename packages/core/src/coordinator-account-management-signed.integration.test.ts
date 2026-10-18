import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { BetterSqliteCoordinatorStore } from "./better-sqlite-coordinator-store.js";
import { createCoordinatorApp } from "./coordinator-api.js";
import { AUTH_LINK_CHANGE_PURPOSE } from "./coordinator-auth-link-change-contract.js";
import { NOW } from "./coordinator-auth-link-test-fixtures.js";
import { review } from "./coordinator-auth-store-test-fixtures.js";
import {
	captureCoordinatorBrowserAuthOptions,
	createCoordinatorBrowserAuth,
} from "./coordinator-browser-auth-app.js";
import { importBrowserCsrfKey } from "./coordinator-browser-csrf.js";
import { oidcFixture, PROVIDER } from "./coordinator-oidc-test-fixtures.js";
import { createInMemoryRequestRateLimiter } from "./request-rate-limit.js";
import { buildCanonicalRequest, SIGNATURE_VERSION, verifySignature } from "./sync-auth.js";
import { fingerprintPublicKey } from "./sync-fingerprint.js";

// Actual Coordinator API, SQLite and Ed25519 verification. The OIDC transport
// below is an in-process cryptographic fixture, NOT Google or a live provider.
const origin = new URL(PROVIDER.redirectUri).origin;
const root = "/v1/auth/link-changes";
const runtime = Buffer.alloc(32, 17).toString("base64url");
const startCode = Buffer.alloc(32, 19).toString("base64url");
const genesisCompletion = Buffer.alloc(32, 23).toString("base64url");
const hash = (raw: string) =>
	createHash("sha256").update(Buffer.from(raw, "base64url")).digest("hex");
const cleanup: (() => void)[] = [];
beforeEach(() => {
	vi.spyOn(Date, "now").mockReturnValue(NOW);
	vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Unexpected real network request"));
});
afterEach(() => {
	try {
		expect(globalThis.fetch).not.toHaveBeenCalled();
	} finally {
		vi.restoreAllMocks();
		for (const close of cleanup.splice(0)) close();
	}
});

// Same SSH wire encoding and canonical signing pattern as the existing
// coordinator-device-auth-link and coordinator-browser-auth-app tests.
function device(deviceId = "device-a") {
	const keys = generateKeyPairSync("ed25519");
	const raw = Buffer.from(keys.publicKey.export({ type: "spki", format: "der" })).subarray(-32);
	const kind = Buffer.from("ssh-ed25519");
	const wire = Buffer.alloc(8 + kind.length + raw.length);
	wire.writeUInt32BE(kind.length);
	kind.copy(wire, 4);
	wire.writeUInt32BE(raw.length, 4 + kind.length);
	raw.copy(wire, 8 + kind.length);
	const publicKey = `ssh-ed25519 ${wire.toString("base64")}`;
	return {
		deviceId,
		publicKey,
		fingerprint: fingerprintPublicKey(publicKey),
		privateKey: keys.privateKey,
	};
}
type Device = ReturnType<typeof device>;
async function setup(
	authority: "controller_attestation" | "device_claim" = "controller_attestation",
) {
	const directory = mkdtempSync(join(tmpdir(), "account-management-signed-"));
	const path = join(directory, "fixture.sqlite");
	const store = new BetterSqliteCoordinatorStore(path, { authClock: () => NOW });
	cleanup.push(() => {
		if (store.db.open) store.db.close();
		rmSync(directory, { recursive: true });
	});
	const key = device();
	await store.createGroup("group-a");
	await store.enrollDevice("group-a", { ...key, identityId: "identity-a" });
	if (authority === "controller_attestation")
		expect(await store.createAuthControllerAttestation(review(key))).toMatchObject({
			kind: "created",
		});
	const config = {
		...PROVIDER,
		// Production browser composition permits only this issuer. All discovery,
		// JWKS and token responses still come from our synthetic local transport.
		issuer: "https://accounts.google.com",
		enabled: true,
		coordinatorId: "coordinator-a",
		revision: "a".repeat(64),
	};
	const oidc = oidcFixture({ issuer: config.issuer });
	const browser = await createCoordinatorBrowserAuth(
		captureCoordinatorBrowserAuthOptions({
			config,
			csrfKey: await importBrowserCsrfKey(randomBytes(32)),
			oidcOptions: { fetch: oidc.fetch },
		}),
		store,
		createInMemoryRequestRateLimiter({ now: () => NOW }),
	);
	if (!browser.ok) throw new Error(`Synthetic provider composition failed: ${browser.error}`);
	// Each HTTP request gets a real independently closed adapter over the same DB.
	const storeFactory = () => new BetterSqliteCoordinatorStore(path, { authClock: () => NOW });
	const app = createCoordinatorApp({
		storeFactory,
		runtime: { adminSecret: () => null, now: () => new Date(NOW).toISOString() },
		requestVerifier: (input) =>
			verifySignature({ ...input, bodyBytes: Buffer.from(input.bodyBytes) }),
		browserAuth: {
			kind: "ready",
			auth: browser.auth,
			storeFactory,
			clientKey: () => "synthetic-browser",
		},
	});
	return { store, key, config, oidc, app, authority };
}
type Fixture = Awaited<ReturnType<typeof setup>>;
function createBody(overrides: Record<string, unknown> = {}) {
	return {
		group_id: "group-a",
		identity_id: "identity-a",
		intent: "refresh",
		attempt_id: "change-a",
		runtime_verifier_hash: hash(runtime),
		browser_start_hash: hash(startCode),
		loopback_redirect: "http://127.0.0.1:4567/codemem/auth/complete",
		...overrides,
	};
}
function finalBody(f: Fixture, completion: string, overrides: Record<string, unknown> = {}) {
	return {
		purpose: AUTH_LINK_CHANGE_PURPOSE,
		coordinator_id: f.config.coordinatorId,
		attempt_id: "change-a",
		group_id: "group-a",
		identity_id: "identity-a",
		device_id: f.key.deviceId,
		fingerprint: f.key.fingerprint,
		runtime_verifier: runtime,
		completion,
		...overrides,
	};
}
function signedRequest(
	f: Fixture,
	path: string,
	value: unknown = createBody(),
	options: {
		method?: string;
		signedMethod?: string;
		signedPath?: string;
		signedBody?: string;
		key?: Device;
		nonce?: string;
	} = {},
) {
	const method = options.method ?? "POST";
	const body = method === "GET" ? "" : JSON.stringify(value);
	const timestamp = String(NOW / 1000);
	const nonce = options.nonce ?? randomBytes(16).toString("hex");
	const key = options.key ?? f.key;
	const signature = sign(
		null,
		buildCanonicalRequest(
			options.signedMethod ?? method,
			options.signedPath ?? path,
			timestamp,
			nonce,
			Buffer.from(options.signedBody ?? body),
		),
		key.privateKey,
	);
	return new Request(`${origin}${path}`, {
		method,
		headers: {
			"content-type": "application/json",
			"X-Opencode-Device": key.deviceId,
			"X-Opencode-Timestamp": timestamp,
			"X-Opencode-Nonce": nonce,
			"X-Opencode-Signature": `${SIGNATURE_VERSION}:${signature.toString("base64")}`,
		},
		...(method === "GET" ? {} : { body }),
	});
}
const request = (
	f: Fixture,
	path: string,
	body?: unknown,
	options?: Parameters<typeof signedRequest>[3],
) => f.app.request(signedRequest(f, path, body, options));
function rows(f: Fixture, table: string) {
	const order = table === "coordinator_auth_device_claims" ? "claim_id" : "rowid";
	return f.store.db.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();
}
function snapshot(f: Fixture) {
	const tables = f.store.db
		.prepare(
			"SELECT name FROM sqlite_master WHERE type='table' AND name <> 'request_nonces' ORDER BY name",
		)
		.all() as { name: string }[];
	return tables.map(({ name }) => [name, rows(f, name)]);
}
function lifecycle(f: Fixture) {
	return [
		"coordinator_auth_account_links",
		"coordinator_auth_account_associations",
		"coordinator_auth_sessions",
		"coordinator_auth_link_profile_refreshes",
		"coordinator_auth_link_audit_log",
		"coordinator_identity_group_grants",
		"coordinator_device_ownership_bindings",
	].map((name) => [name, rows(f, name)]);
}
async function genesis(f: Fixture) {
	const linkRoot = "/v1/auth/link-attempts";
	const body = {
		group_id: "group-a",
		identity_id: "identity-a",
		authority: f.authority,
		attempt_id: "genesis",
		runtime_verifier_hash: hash(runtime),
		browser_start_hash: hash(startCode),
		loopback_redirect: createBody().loopback_redirect,
	};
	expect((await request(f, linkRoot, body)).status).toBe(201);
	const material = {
		purpose: "link" as const,
		attemptId: "genesis",
		browserStartHash: hash(startCode),
		stateHash: "1".repeat(64),
		binderHash: "2".repeat(64),
		nonce: "n".repeat(43),
		pkceVerifier: "p".repeat(43),
	};
	expect(await f.store.startAuthBrowserTransaction(material, f.config)).toMatchObject({
		kind: "started",
	});
	const consumed = await f.store.consumeAuthBrowserTransaction(material, f.config);
	if (consumed.kind !== "consumed") throw new Error("Genesis browser proof not consumed");
	const proof = { attemptId: "genesis", browserTransactionHash: consumed.browserTransactionHash };
	expect(
		await f.store.recordAuthLinkOidcVerified(
			{
				...proof,
				account: { issuer: f.config.issuer, subject: "fixture-subject" },
				profile: { displayName: "Original profile" },
			},
			f.config,
		),
	).toMatchObject({ kind: "applied" });
	expect(
		await f.store.confirmAuthLinkAttempt(
			{ ...proof, completionSecretHash: hash(genesisCompletion) },
			f.config,
		),
	).toMatchObject({ kind: "applied" });
	expect(
		(
			await request(
				f,
				`${linkRoot}/genesis/finalize`,
				finalBody(f, genesisCompletion, {
					purpose: "coordinator-account-link-v1",
					attempt_id: "genesis",
				}),
			)
		).status,
	).toBe(200);
}
function hidden(html: string, name: string) {
	const value = new RegExp(`name="${name}" value="([^"]+)"`).exec(html)?.[1];
	if (!value) throw new Error(`Missing browser field ${name}`);
	return value.replaceAll("&amp;", "&");
}
// HTTP-only cookie model for this fixed HTTPS host and Path=/ scope. It models
// replacement, deletion and expiry, not browser popup/COOP behavior.
function cookieExpiry(attrs: Map<string | undefined, string>) {
	if (attrs.has("max-age")) {
		const seconds = Number(attrs.get("max-age"));
		if (!Number.isFinite(seconds)) throw new Error("Invalid fixture cookie Max-Age");
		return Date.now() + seconds * 1000;
	}
	if (attrs.has("expires")) {
		const expires = Date.parse(attrs.get("expires") ?? "");
		if (!Number.isFinite(expires)) throw new Error("Invalid fixture cookie Expires");
		return expires;
	}
	return Number.POSITIVE_INFINITY;
}
function cookies(response: Response, jar: Map<string, { value: string; expires: number }>) {
	for (const header of response.headers.getSetCookie()) {
		const [pair, ...attributes] = header.split(";");
		if (!pair) throw new Error("Missing Set-Cookie name/value");
		const separator = pair.indexOf("=");
		if (separator < 1) throw new Error("Malformed fixture Set-Cookie");
		const name = pair.slice(0, separator);
		const value = pair.slice(separator + 1);
		const attrs = new Map(
			attributes.map((attribute) => {
				const [key, ...parts] = attribute.trim().split("=");
				return [key?.toLowerCase(), parts.join("=")];
			}),
		);
		// Fail on an unsupported scope rather than sending a cookie to the wrong URL.
		expect(attrs.get("path")).toBe("/");
		expect(attrs.has("domain")).toBe(false);
		const expires = cookieExpiry(attrs);
		if (expires <= Date.now()) jar.delete(name);
		else jar.set(name, { value, expires });
	}
	for (const [name, cookie] of jar) {
		if (cookie.expires <= Date.now()) jar.delete(name);
	}
	return [...jar].map(([name, cookie]) => `${name}=${cookie.value}`).join("; ");
}
function postForm(f: Fixture, path: string, cookie: string, fields: Record<string, string>) {
	return f.app.request(`${origin}${path}`, {
		method: "POST",
		headers: { origin, cookie, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(fields),
	});
}
async function providerCallback(f: Fixture) {
	const jar = new Map<string, { value: string; expires: number }>();
	const start = await f.app.request(
		`${origin}/auth/link-change/start?attempt_id=change-a&start_code=${startCode}`,
	);
	expect(start.status).toBe(200);
	const started = await postForm(f, "/auth/link-change/start", cookies(start, jar), {
		csrf: hidden(await start.text(), "csrf"),
		attempt_id: "change-a",
		start_code: startCode,
	});
	expect(started.status).toBe(200);
	const authorization = /href="([^"]+)"/.exec(await started.text())?.[1]?.replaceAll("&amp;", "&");
	if (!authorization) throw new Error("Missing synthetic-provider authorization URL");
	const cookie = cookies(started, jar);
	const response = await f.app.request(f.oidc.authorize(authorization), { headers: { cookie } });
	return { response, cookie };
}

it.each(["wrong key", "changed body", "changed path", "changed method"])(
	"rejects %s with real Ed25519 verification before management writes",
	async (attack) => {
		// Arrange: no provider or existing link is necessary for signature rejection.
		const f = await setup();
		const before = snapshot(f);
		const options: Parameters<typeof signedRequest>[3] = {};
		if (attack === "wrong key") options.key = device();
		if (attack === "changed body")
			options.signedBody = JSON.stringify(createBody({ intent: "disconnect" }));
		if (attack === "changed path") options.signedPath = `${root}/another-attempt/cancel`;
		if (attack === "changed method") options.signedMethod = "GET";
		// Act
		const response = await request(f, root, createBody(), options);
		// Assert: authentication failed, not a later lifecycle precondition.
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "auth_link_change_unavailable" });
		expect(snapshot(f)).toEqual(before);
		expect(rows(f, "request_nonces")).toEqual([]);
	},
);

it.each([
	{ target_link_id: "client-target" },
	{ generation: 9 },
	{ role: "owner" },
	{ intent: "switch" },
])("rejects signed caller-selected target or authority input %j without writes", async (extra) => {
	// Arrange
	const f = await setup();
	const before = snapshot(f);
	// Act
	const response = await request(f, root, createBody(extra));
	// Assert
	expect(response.status).toBe(400);
	expect(snapshot(f)).toEqual(before);
	expect(rows(f, "request_nonces")).toEqual([]);
});

it.each(["group", "identity"])(
	"rejects a correctly signed mismatched %s without lifecycle writes",
	async (mismatch) => {
		// Arrange: positive genesis pins the requester's actual Identity and group.
		const f = await setup();
		await genesis(f);
		const before = snapshot(f);
		// Act
		const response = await request(
			f,
			root,
			createBody(
				mismatch === "group" ? { group_id: "other-group" } : { identity_id: "other-identity" },
			),
		);
		// Assert
		expect(response.status).toBe(mismatch === "group" ? 401 : 403);
		expect(snapshot(f)).toEqual(before);
	},
);

it("accepts signed create/status/cancel and rejects replayed nonce or another device's status read", async () => {
	// Arrange
	const f = await setup();
	await genesis(f);
	const nonce = "0123456789abcdef0123456789abcdef";
	const before = lifecycle(f);
	// Act: the exact same signed request must not be admitted twice.
	const created = await request(f, root, createBody(), { nonce });
	const afterCreate = snapshot(f);
	const replay = await request(f, root, createBody(), { nonce });
	// Assert
	expect(created.status).toBe(201);
	expect(replay.status).toBe(401);
	expect(snapshot(f)).toEqual(afterCreate);
	// Arrange: a separately enrolled reader has a valid signature, not ownership.
	const reader = device("reader");
	await f.store.enrollDevice("group-a", { ...reader, identityId: "identity-a" });
	const statusPath = `${root}/change-a?group_id=group-a`;
	// Act
	const own = await request(f, statusPath, undefined, { method: "GET" });
	const other = await request(f, statusPath, undefined, { method: "GET", key: reader });
	const cancelled = await request(f, `${root}/change-a/cancel`, { group_id: "group-a" });
	const ended = await request(f, statusPath, undefined, { method: "GET" });
	// Assert
	expect(own.status).toBe(200);
	expect(await own.json()).toMatchObject({ status: { state: "pending", intent: "refresh" } });
	expect(other.status).toBe(404);
	expect(cancelled.status).toBe(200);
	expect(await ended.json()).toMatchObject({ status: { state: "failed" } });
	expect(lifecycle(f)).toEqual(before);
});

it.each(["refresh", "disconnect"] as const)(
	"runs signed %s through fresh synthetic OIDC, browser proof and signed finalization",
	async (intent) => {
		// Arrange: genuine device signatures and intact genesis; provider is synthetic.
		const f = await setup();
		await genesis(f);
		expect((await request(f, root, createBody({ intent }))).status).toBe(201);
		const before = lifecycle(f);
		// Act: state/nonce/PKCE and signed fixture ID token pass the real OIDC client.
		const callback = await providerCallback(f);
		expect(callback.response.status).toBe(200);
		let html = await callback.response.text();
		if (intent === "disconnect") {
			expect(html.match(/>Unlink Google account<\/button>/g)).toHaveLength(1);
			const confirmed = await postForm(f, "/auth/link-change/confirm", callback.cookie, {
				csrf: hidden(html, "csrf"),
				attempt_id: "change-a",
			});
			expect(confirmed.status).toBe(200);
			html = await confirmed.text();
		} else expect(html).not.toContain("Unlink Google account</button>");
		const href = /href="([^"]+)"/.exec(html)?.[1]?.replaceAll("&amp;", "&");
		if (!href) throw new Error("Missing held-loopback completion link");
		const completion = new URL(href).searchParams.get("completion");
		if (!completion) throw new Error("Missing device completion secret");
		// Assert: browser proof never publishes the lifecycle change by itself.
		expect(lifecycle(f)).toEqual(before);
		const finalizePath = `${root}/change-a/finalize`;
		// Act: purpose and runtime proofs remain separate from a valid signature.
		const wrongPurpose = await request(
			f,
			finalizePath,
			finalBody(f, completion, { purpose: "coordinator-account-link-v1" }),
		);
		const wrongRuntime = await request(
			f,
			finalizePath,
			finalBody(f, completion, { runtime_verifier: genesisCompletion }),
		);
		// Assert
		expect(wrongPurpose.status).toBe(400);
		expect(wrongRuntime.status).toBe(403);
		expect(lifecycle(f)).toEqual(before);
		// Act
		const result = await request(f, finalizePath, finalBody(f, completion));
		const committed = snapshot(f);
		const retry = await request(f, finalizePath, finalBody(f, completion));
		// Assert: both initial result and exact retry traverse real signature checks.
		expect(result.status).toBe(200);
		expect(await result.json()).toMatchObject({ status: { state: "completed", intent } });
		expect(retry.status).toBe(200);
		expect(snapshot(f)).toEqual(committed);
		const link = rows(f, "coordinator_auth_account_links")[0];
		expect(link).toMatchObject({
			ended_at_ms: intent === "disconnect" ? NOW : null,
			revoked_at_ms: null,
		});
		if (intent === "refresh")
			expect(rows(f, "coordinator_auth_link_profile_refreshes")).toEqual([
				expect.objectContaining({ display_name: "Fixture User", source_attempt_id: "change-a" }),
			]);
		else expect(rows(f, "coordinator_auth_link_profile_refreshes")).toEqual([]);
	},
);

it("rejects fresh synthetic-provider proof for another account without exposing or mutating the target", async () => {
	// Arrange
	const f = await setup();
	await genesis(f);
	expect((await request(f, root)).status).toBe(201);
	f.oidc.claims.sub = "wrong-synthetic-account";
	const before = lifecycle(f);
	// Act
	const callback = await providerCallback(f);
	const html = await callback.response.text();
	// Assert
	expect(callback.response.status).toBe(403);
	expect(html).not.toContain("fixture-subject");
	expect(html).not.toContain("wrong-synthetic-account");
	expect(lifecycle(f)).toEqual(before);
	expect(rows(f, "coordinator_auth_link_change_attempts")).toEqual([
		expect.objectContaining({ state: "browser_claimed" }),
	]);
});

it("admits the original device-claim signer but denies a same-Identity reader without minting owner or grant authority", async () => {
	// Arrange: full first-claim genesis, not a fabricated trusted context.
	const f = await setup("device_claim");
	await genesis(f);
	const reader = device("reader");
	await f.store.enrollDevice("group-a", { ...reader, identityId: "identity-a" });
	const before = lifecycle(f);
	// Act
	const denied = await request(f, root, createBody({ attempt_id: "reader-change" }), {
		key: reader,
	});
	const allowed = await request(f, root);
	// Assert: valid reader signature is insufficient for management authority.
	expect(denied.status).toBe(403);
	expect(allowed.status).toBe(201);
	expect(lifecycle(f)).toEqual(before);
	expect(rows(f, "coordinator_device_ownership_bindings")).toEqual([]);
	expect(rows(f, "coordinator_identity_group_grants")).toEqual([]);
	expect(rows(f, "coordinator_auth_link_change_attempts")).toEqual([
		expect.objectContaining({ authority_kind: "device_claim", device_id: f.key.deviceId }),
	]);
});
