import { env } from "cloudflare:workers";
import { expect, it } from "vitest";
import { D1CoordinatorStore } from "../../core/src/d1-coordinator-store.js";
import { AUTH_LIFECYCLE_CURRENT_DEFINITIONS, AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS } from "../../core/src/coordinator-auth-lifecycle-fresh-schema.js";
import type { CoordinatorAuthBrowserConfig } from "../../core/src/coordinator-auth-browser-transaction-contract.js";
import { CANONICAL_PUBLIC_KEY } from "../../core/src/coordinator-ed25519-key-id-test-fixtures.js";
import { AUTH_LIFECYCLE_CURRENT_READINESS_SQL, AUTH_LIFECYCLE_CURRENT_READY_COUNT } from "../../core/src/coordinator-auth-lifecycle-current-readiness.js";

const hash = (n: number) => n.toString(16).padStart(64, "0");

async function freshNativeAuth() {
	const db = env.COORDINATOR_DB;
	if ((await db.prepare(AUTH_LIFECYCLE_CURRENT_READINESS_SQL).first<{ ready: number }>())?.ready === AUTH_LIFECYCLE_CURRENT_READY_COUNT) return;
	// Isolated, empty test DB only. Production predecessor opening never does this.
	const names = AUTH_LIFECYCLE_CURRENT_DEFINITIONS.filter(({ type }) => type === "table").map(({ name }) => name);
	const present: string[] = [];
	for (const name of names) {
		if (!(await db.prepare("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'").bind(name).first())) continue;
		expect(await db.prepare(`SELECT count(*) AS n FROM ${name}`).first()).toEqual({ n: 0 });
		present.push(name);
	}
	await db.batch(present.map((name) => db.prepare(`DROP TABLE ${name}`)));
	await db.batch(AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS.map((sql) => db.prepare(sql)));
}

it("runs first-link, bound redemption, ordered profiles and idempotent revocation through current native D1 writers", async () => {
	await freshNativeAuth();
	const db = env.COORDINATOR_DB;
	const now = 1791028800000;
	const store = new D1CoordinatorStore(db, { authClock: () => now });
	const cfg: CoordinatorAuthBrowserConfig = { coordinatorId: "native-v3", issuer: "https://accounts.example.test", revision: hash(1), enabled: true, redirectUri: "https://coordinator.example.test/auth/callback" };
	const signer = { groupId: "native-v3-group", deviceId: "native-v3-device", publicKey: "synthetic-key", fingerprint: hash(2) };
	await store.createGroup(signer.groupId);
	await store.enrollDevice(signer.groupId, { ...signer, identityId: null });
	expect(await store.createAuthControllerAttestation({ ...signer, coordinatorId: cfg.coordinatorId, identityId: "native-v3-identity", attestationId: "native-v3-attestation", reviewReceiptId: "native-v3-review", evidenceDigest: hash(3) })).toMatchObject({ kind: "created" });
	const start = { authority: { kind: "controller_attestation" as const }, attemptId: "native-v3-attempt", signer, runtimeVerifierHash: hash(4), browserStartHash: hash(5), loopbackRedirect: "http://127.0.0.1:4567/codemem/auth/complete" };
	expect(await store.createAuthLinkAttempt(start, cfg)).toMatchObject({ kind: "created" });
	async function proof(seed: number, link?: { attemptId: string; browserStartHash: string }) {
		const materials = { stateHash: hash(seed), binderHash: hash(seed + 1), nonce: "n".repeat(43), pkceVerifier: "p".repeat(43) };
		const input = link ? { ...materials, purpose: "link" as const, ...link } : { ...materials, purpose: "signin" as const };
		expect(await store.startAuthBrowserTransaction(input, cfg)).toMatchObject({ kind: "started" });
		const consumed = await store.consumeAuthBrowserTransaction(materials, cfg);
		if (consumed.kind !== "consumed") throw new Error("Synthetic browser proof was not consumed");
		return { ...consumed, binderHash: materials.binderHash };
	}
	const browser = await proof(10, start);
	const account = { issuer: cfg.issuer, subject: "native-v3-subject" };
	const completion = { attemptId: start.attemptId, browserTransactionHash: browser.browserTransactionHash };
	expect(await store.recordAuthLinkOidcVerified({ ...completion, account, profile: { displayName: "Link profile" } }, cfg)).toMatchObject({ kind: "applied" });
	expect(await store.confirmAuthLinkAttempt({ ...completion, completionSecretHash: hash(6) }, cfg)).toMatchObject({ kind: "applied" });
	const finalize = { ...start, purpose: "coordinator-account-link-v1" as const, coordinatorId: cfg.coordinatorId, identityId: "native-v3-identity", ...signer, completionSecretHash: hash(6) };
	expect(await store.finalizeAuthLinkAttempt(finalize, cfg)).toMatchObject({ kind: "applied" });
	expect(await store.finalizeAuthLinkAttempt(finalize, cfg)).toMatchObject({ kind: "existing" });
	expect((await store.redeemAuthLinkSessionWithBrowserTransaction({ ...completion, binderHash: browser.binderHash, credentialHash: hash(30) }, cfg)).kind).toBe("issued");
	const older = await proof(40);
	const newer = await proof(50);
	for (const [browserProof, credential] of [[older, hash(60)], [newer, hash(61)]] as const) {
		expect((await store.signInWithConsumedBrowserTransaction({ account, browserTransactionHash: browserProof.browserTransactionHash, credentialHash: credential }, cfg)).kind).toBe("issued");
	}
	expect(await store.recordAuthAccountProfile({ credentialHash: hash(61), profile: {} }, cfg)).toEqual({ kind: "recorded" });
	expect(await store.recordAuthAccountProfile({ credentialHash: hash(60), profile: { displayName: "Late older" } }, cfg)).toEqual({ kind: "not_recorded" });
	expect((await store.readAuthSessionAccount(hash(30), cfg))?.profile).toEqual({});
	const row = await db.prepare("SELECT link_id FROM coordinator_auth_account_links").first<{ link_id: string }>();
	if (!row) throw new Error("Synthetic link missing");
	expect(await store.revokeAuthAccountLink({ linkId: row.link_id }, cfg)).toEqual({ kind: "revoked" });
	expect(await store.revokeAuthAccountLink({ linkId: row.link_id }, cfg)).toEqual({ kind: "revoked" });
	expect(await store.readAuthSession(hash(30), cfg)).toBeNull();
});

it("runs a device-claim first link and account reads with intact genesis proof in native D1", async () => {
	await freshNativeAuth();
	const db = env.COORDINATOR_DB;
	const now = 1791028800000;
	const store = new D1CoordinatorStore(db, { authClock: () => now });
	const cfg = { coordinatorId: "device-v3", issuer: "https://accounts.example.test", revision: hash(1), enabled: true, redirectUri: "https://coordinator.example.test/auth/callback" };
	const signer = { groupId: "device-v3-group", deviceId: "device-v3-device", publicKey: CANONICAL_PUBLIC_KEY, fingerprint: hash(102) };
	await store.createGroup(signer.groupId);
	await store.enrollDevice(signer.groupId, { ...signer, identityId: "device-v3-identity" });
	const start = { authority: { kind: "device_claim" as const, identityId: "device-v3-identity" }, expectedIdentityId: "device-v3-identity", attemptId: "device-v3-attempt", signer, runtimeVerifierHash: hash(3), browserStartHash: hash(4), loopbackRedirect: "http://127.0.0.1:4567/codemem/auth/complete" };
	expect(await store.createAuthLinkAttempt(start, cfg)).toMatchObject({ kind: "created" });
	const materials = { stateHash: hash(5), binderHash: hash(6), nonce: "n".repeat(43), pkceVerifier: "p".repeat(43) };
	expect(await store.startAuthBrowserTransaction({ ...materials, purpose: "link", attemptId: start.attemptId, browserStartHash: start.browserStartHash }, cfg)).toMatchObject({ kind: "started" });
	const consumed = await store.consumeAuthBrowserTransaction(materials, cfg);
	if (consumed.kind !== "consumed") throw new Error("Synthetic device browser proof not consumed");
	const browser = { attemptId: start.attemptId, browserTransactionHash: consumed.browserTransactionHash };
	expect(await store.recordAuthLinkOidcVerified({ ...browser, account: { issuer: cfg.issuer, subject: "device-account" }, profile: { displayName: "Device account" } }, cfg)).toMatchObject({ kind: "applied" });
	expect(await store.confirmAuthLinkAttempt({ ...browser, completionSecretHash: hash(7) }, cfg)).toMatchObject({ kind: "applied" });
	const finalize = { purpose: "coordinator-account-link-v1" as const, coordinatorId: cfg.coordinatorId, attemptId: start.attemptId, identityId: "device-v3-identity", ...signer, signer, runtimeVerifierHash: start.runtimeVerifierHash, completionSecretHash: hash(7) };
	expect(await store.finalizeAuthLinkAttempt(finalize, cfg)).toMatchObject({ kind: "applied" });
	expect(await store.finalizeAuthLinkAttempt(finalize, cfg)).toMatchObject({ kind: "existing" });
	expect((await store.redeemAuthLinkSessionWithBrowserTransaction({ ...browser, binderHash: materials.binderHash, credentialHash: hash(8) }, cfg)).kind).toBe("issued");
	expect((await store.readAuthSession(hash(8), cfg))?.identityId).toBe("device-v3-identity");
	expect((await store.readAuthSessionAccount(hash(8), cfg))?.profile).toEqual({ displayName: "Device account" });
	expect((await store.readAccountLinkStatus(signer, cfg, { identityId: "device-v3-identity" })).state).toBe("linked");
	expect((await db.prepare("SELECT count(*) AS n FROM coordinator_auth_device_claims").first())?.n).toBe(1);
});
