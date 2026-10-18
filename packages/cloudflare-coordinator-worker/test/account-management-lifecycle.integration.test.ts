import { env } from "cloudflare:workers";
import { afterEach, beforeAll, expect, it } from "vitest";
import {
	AUTH_LIFECYCLE_CURRENT_DEFINITIONS,
	AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS,
} from "../../core/src/coordinator-auth-lifecycle-fresh-schema.js";
import { AUTH_LINK_CHANGE_PURPOSE } from "../../core/src/coordinator-auth-link-change-contract.js";
import { D1CoordinatorStore, type D1PreparedStatementLike } from "../../core/src/d1-coordinator-store.js";
import { config, input, NOW, otherKey, seedAttestationSql, seedEnrollmentSql } from "./device-claim-eligibility-fixture.js";

// Native D1 persistence acceptance only: provider accounts below are synthetic
// verified metadata. These tests do NOT claim OIDC or HTTP-signature acceptance.
const cfg = { ...config, redirectUri: "https://coordinator.example.test/auth/callback" };
const db = (env as typeof env & { COORDINATOR_DB: D1Database }).COORDINATOR_DB;
const hash = (n: number) => n.toString(16).padStart(64, "0");
const account = (subject = "synthetic-account-a") => ({ issuer: cfg.issuer, subject });
const loopbackRedirect = "http://127.0.0.1:4567/codemem/auth/complete";
const rows = async (table: string) => {
	const order = table === "coordinator_auth_device_claims" ? "claim_id" : "rowid";
	return (await db.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all()).results;
};
const authTables = AUTH_LIFECYCLE_CURRENT_DEFINITIONS.filter((d) => d.type === "table").map((d) => d.name);
const fixtureTables = ["groups", "enrolled_devices", "coordinator_identity_group_grants", "coordinator_auth_controller_attestations"];
let fixtureDdl: string[] = [];
beforeAll(async () => {
	const definitions = await db.prepare("SELECT tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END").all<{ tbl_name: string; sql: string }>();
	fixtureDdl = definitions.results.filter((r) => fixtureTables.includes(r.tbl_name)).map((r) => r.sql);
});
afterEach(async () => {
	// The case is over: dispose its entire test graph, not individual immutable
	// history/proof rows. The next case starts before guards and data exist.
	await db.batch([...authTables, ...fixtureTables].map((name) => db.prepare(`DROP TABLE IF EXISTS ${name}`)));
	await db.batch(fixtureDdl.map((sql) => db.prepare(sql)));
});

async function setup(authority: "controller_attestation" | "device_claim" = "controller_attestation") {
	// The global setup supplies an empty predecessor test snapshot. Dispose only
	// that empty auth graph, before any fixture operation; never remove live guards.
	const present: string[] = [];
	for (const name of authTables) {
		if (!(await db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").bind(name).first())) continue;
		expect(await db.prepare(`SELECT count(*) AS n FROM ${name}`).first()).toEqual({ n: 0 });
		present.push(name);
	}
	if (present.length) await db.batch(present.map((name) => db.prepare(`DROP TABLE ${name}`)));
	await db.batch(AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS.map((sql) => db.prepare(sql)));
	await db.batch(seedEnrollmentSql.split(";").map((s) => s.trim()).filter(Boolean).map((sql) => db.prepare(sql)));
	await db.prepare("UPDATE enrolled_devices SET identity_id=? WHERE device_id=?").bind(input.identityId, input.signer.deviceId).run();
	if (authority === "controller_attestation") await db.prepare(seedAttestationSql).run();
	let now = NOW + 10;
	const errors: string[] = [];
	const nativeStatements = new WeakMap<D1PreparedStatementLike, D1PreparedStatement>();
	const metadata = new WeakMap<D1PreparedStatementLike, string>();
	const explain = new WeakMap<D1PreparedStatementLike, () => Promise<unknown>>();
	const report = (operation: string, sql: string, error: unknown) => {
		const message = `${operation}: ${String(error)}\nSQL: ${sql}`;
		errors.push(message);
		console.error(message);
	};
	const instrument = (native: D1PreparedStatement, sql: string, values: unknown[] = []): D1PreparedStatementLike => {
		const summary = `parameters=${(sql.match(/\?/g) ?? []).length}, bindings=${values.length}; ${sql.replace(/\s+/g, " ").slice(0, 700)}`;
		async function run<T>(operation: string, action: () => Promise<T>): Promise<T> {
			try { return await action(); }
			catch (error) { report(operation, summary, error); throw error; }
		}
		const wrapped: D1PreparedStatementLike = {
			bind: (...values) => instrument(native.bind(...values), sql, values),
			first: <T>() => run("first", () => native.first<T>()),
			run: () => run("run", () => native.run()),
			all: <T>() => run("all", () => native.all<T>()),
			raw: <T>() => run("raw", () => native.raw<T>()),
		};
		nativeStatements.set(wrapped, native);
		metadata.set(wrapped, summary);
		explain.set(wrapped, () => db.prepare(`EXPLAIN ${sql}`).bind(...values).all());
		return wrapped;
	};
	const nativeDb = { prepare: (sql: string) => instrument(db.prepare(sql), sql), batch: async (statements: D1PreparedStatementLike[]) => {
		const actual = statements.map((statement) => {
			const native = nativeStatements.get(statement);
			if (!native) throw new Error("Untracked test statement");
			return native;
		});
		try { return await db.batch(actual); }
		catch (error) {
			report("batch", statements.map((s, index) => `${index}: ${metadata.get(s)}`).join("\n"), error);
			for (const [index, statement] of statements.entries()) {
				try { await explain.get(statement)?.(); }
				catch (compileError) { report(`EXPLAIN batch[${index}]`, metadata.get(statement) ?? "", compileError); }
			}
			throw error;
		}
	} };
	const store = new D1CoordinatorStore(nativeDb, { authClock: () => now });
	await store.assertAuthSchemaReady();
	const f = { store, management: store.accountManagement, authority, errors, advance: () => { now += 600000; } };
	const first = await prepareLink(f, "genesis", 10);
	expect(await store.finalizeAuthLinkAttempt(first.finalize, cfg)).toMatchObject({ kind: "applied" });
	const link = await db.prepare("SELECT link_id FROM coordinator_auth_account_links").first<{ link_id: string }>();
	if (!link) throw new Error("Fresh genesis did not commit");
	return { ...f, linkId: link.link_id, genesis: first };
}
type Fixture = { store: D1CoordinatorStore; management: D1CoordinatorStore["accountManagement"]; authority: "controller_attestation" | "device_claim"; errors: string[] };

async function signinProof(f: Fixture, seed: number) {
	const material = { stateHash: hash(seed), binderHash: hash(seed + 1), nonce: "n".repeat(43), pkceVerifier: "p".repeat(43) };
	expect(await f.store.startAuthBrowserTransaction({ ...material, purpose: "signin" }, cfg)).toMatchObject({ kind: "started" });
	const consumed = await f.store.consumeAuthBrowserTransaction(material, cfg);
	if (consumed.kind !== "consumed") throw new Error("Fresh signin proof not consumed");
	return consumed.browserTransactionHash;
}
async function prepareLink(f: Fixture, attemptId: string, seed: number, subject = "synthetic-account-a") {
	const authority = f.authority === "device_claim" ? { kind: "device_claim" as const, identityId: input.identityId } : { kind: "controller_attestation" as const };
	const create = { ...input, expectedIdentityId: input.identityId, authority, attemptId, runtimeVerifierHash: hash(seed), browserStartHash: hash(seed + 1), loopbackRedirect };
	expect(await f.store.createAuthLinkAttempt(create, cfg)).toMatchObject({ kind: "created" });
	const material = { stateHash: hash(seed + 2), binderHash: hash(seed + 3), nonce: "n".repeat(43), pkceVerifier: "p".repeat(43) };
	expect(await f.store.startAuthBrowserTransaction({ ...material, purpose: "link", attemptId, browserStartHash: create.browserStartHash }, cfg)).toMatchObject({ kind: "started" });
	const consumed = await f.store.consumeAuthBrowserTransaction(material, cfg);
	if (consumed.kind !== "consumed") throw new Error("Fresh link proof not consumed");
	const browser = { attemptId, browserTransactionHash: consumed.browserTransactionHash, binderHash: material.binderHash };
	expect(await f.store.recordAuthLinkOidcVerified({ ...browser, account: account(subject), profile: { displayName: "Original display" } }, cfg)).toMatchObject({ kind: "applied" });
	expect(await f.store.confirmAuthLinkAttempt({ ...browser, completionSecretHash: hash(seed + 4) }, cfg)).toMatchObject({ kind: "applied" });
	return { browser, finalize: { ...input, ...input.signer, purpose: "coordinator-account-link-v1" as const, coordinatorId: cfg.coordinatorId, attemptId, runtimeVerifierHash: create.runtimeVerifierHash, completionSecretHash: hash(seed + 4) } };
}
async function prepareChange(f: Fixture, intent: "refresh" | "disconnect", attemptId = "change-a", seed = 100) {
	const create = { ...input, intent, attemptId, runtimeVerifierHash: hash(seed), browserStartHash: hash(seed + 1), loopbackRedirect };
	const result = await f.management.createAuthLinkChangeAttempt(create, cfg);
	expect(result, f.errors.join("\n")).toMatchObject({ kind: "created" });
	const material = { attemptId, browserStartHash: create.browserStartHash, stateHash: hash(seed + 2), binderHash: hash(seed + 3), nonce: "n".repeat(43), pkceVerifier: "p".repeat(43) };
	expect(await f.management.startAuthLinkChangeBrowser(material, cfg)).toBe(true);
	const browser = await f.management.consumeAuthLinkChangeBrowser(material, cfg);
	if (!browser) throw new Error("Fresh management browser proof not consumed");
	return { intent, browser, finalize: { ...input, ...input.signer, purpose: AUTH_LINK_CHANGE_PURPOSE as typeof AUTH_LINK_CHANGE_PURPOSE, coordinatorId: cfg.coordinatorId, attemptId, runtimeVerifierHash: create.runtimeVerifierHash, completionSecretHash: hash(seed + 4) } };
}
async function confirm(f: Fixture, change: Awaited<ReturnType<typeof prepareChange>>, profile: unknown = {}) {
	expect(await f.management.recordAuthLinkChangeOidcVerified({ ...change.browser, account: account(), profile }, cfg)).toMatchObject({ kind: "applied" });
	expect(await f.management.confirmAuthLinkChangeAttempt({ ...change.browser, completionSecretHash: change.finalize.completionSecretHash, confirmation: change.intent === "refresh" ? "verified_refresh" : "browser" }, cfg)).toMatchObject({ kind: "applied" });
}
async function disconnect(f: Fixture) {
	const change = await prepareChange(f, "disconnect");
	await confirm(f, change);
	expect(await f.management.finalizeAuthLinkChangeAttempt(change.finalize, cfg)).toMatchObject({ kind: "applied" });
	return change;
}
const protectedTables = ["enrolled_devices", "coordinator_auth_controller_attestations", "coordinator_identity_group_grants", "coordinator_auth_device_claims", "coordinator_auth_link_audit_log", "coordinator_auth_account_associations"];
const preserved = () => Promise.all(protectedTables.map(rows));
const status = (f: Fixture) => f.management.readAccountManagementStatus(input.signer, cfg, { identityId: input.identityId });

it("publishes refresh only at device finalization, clears old fields with an empty snapshot, and retains exact retries", async () => {
	// Arrange: intact genesis and private, confirmed empty provider snapshot.
	const f = await setup();
	const change = await prepareChange(f, "refresh");
	await confirm(f, change);
	expect((await status(f)).profile).toMatchObject({ displayName: "Original display" });
	expect(await rows("coordinator_auth_link_profile_refreshes")).toEqual([]);
	const before = await preserved();
	// Act: invalid runtime proof cannot publish; exact original proof can.
	const bad = await f.management.finalizeAuthLinkChangeAttempt({ ...change.finalize, runtimeVerifierHash: hash(999) }, cfg);
	expect(await rows("coordinator_auth_link_profile_refreshes")).toEqual([]);
	const applied = await f.management.finalizeAuthLinkChangeAttempt(change.finalize, cfg);
	const snapshot = await rows("coordinator_auth_link_profile_refreshes");
	const retry = await f.management.finalizeAuthLinkChangeAttempt(change.finalize, cfg);
	// Assert: no data authority changes or retry reinsertions.
	expect(bad.kind).toBe("rejected");
	expect(applied).toMatchObject({ kind: "applied", status: { state: "completed", intent: "refresh" } });
	expect(retry).toEqual({ ...applied, kind: "existing" });
	expect(await rows("coordinator_auth_link_profile_refreshes")).toEqual(snapshot);
	expect(snapshot).toEqual([expect.objectContaining({ display_name: null, email: null, picture_url: null, source_attempt_id: "change-a", source_order: 3 })]);
	expect((await status(f)).profile).toEqual({ state: "verified", verifiedAtMs: NOW + 10 });
	expect(await preserved()).toEqual(before);
});

it.each(["account", "binder"])("rejects wrong %s proof without publishing private claims or ending a link", async (mismatch) => {
	// Arrange
	const f = await setup();
	const change = await prepareChange(f, "refresh");
	const before = await rows("coordinator_auth_account_links");
	// Act
	const result = await f.management.recordAuthLinkChangeOidcVerified({ ...change.browser, binderHash: mismatch === "binder" ? hash(999) : change.browser.binderHash, account: account(mismatch === "account" ? "wrong-account" : undefined), profile: { displayName: "Must stay private" } }, cfg);
	// Assert
	expect(result).toEqual({ kind: "rejected", error: "attempt_unavailable" });
	expect(await rows("coordinator_auth_account_links")).toEqual(before);
	expect(await rows("coordinator_auth_link_profile_refreshes")).toEqual([]);
	expect((await rows("coordinator_auth_link_profiles")).every((r) => r.source_purpose !== "link_change")).toBe(true);
	expect(await f.management.finalizeAuthLinkChangeAttempt(change.finalize, cfg)).toMatchObject({ kind: "rejected" });
});

it("disconnect has one winning receipt, revokes target sessions and purges display while preserving historical authority", async () => {
	// Arrange: real session from the exact committed genesis, not fabricated rows.
	const f = await setup();
	expect(await f.store.redeemAuthLinkSessionWithBrowserTransaction({ ...f.genesis.browser, credentialHash: hash(500) }, cfg)).toMatchObject({ kind: "issued" });
	const signin = await signinProof(f, 600);
	expect(await f.store.signInWithConsumedBrowserTransaction({ browserTransactionHash: signin, credentialHash: hash(501), account: account() }, cfg)).toMatchObject({ kind: "issued" });
	expect(await f.store.recordAuthAccountProfile({ credentialHash: hash(501), profile: { displayName: "Session display" } }, cfg)).toMatchObject({ kind: "recorded" });
	const first = await prepareChange(f, "disconnect");
	await confirm(f, first);
	const before = await preserved();
	// Only one live change attempt per Identity is allowed. Concurrent deliveries
	// of its valid proof must still write one immutable completion receipt.
	const outcomes = await Promise.all([first, first].map((c) => f.management.finalizeAuthLinkChangeAttempt(c.finalize, cfg)));
	const winner = outcomes.findIndex((r) => r.kind === "applied");
	const chosen = [first, first][winner];
	if (!chosen) throw new Error("No disconnect CAS winner");
	const completed = await rows("coordinator_auth_link_change_attempts");
	const retry = await f.management.finalizeAuthLinkChangeAttempt(chosen.finalize, cfg);
	// Assert
	expect(outcomes.filter((r) => r.kind === "applied")).toHaveLength(1);
	expect(outcomes.every((r) => ["applied", "existing", "rejected"].includes(r.kind))).toBe(true);
	expect(completed).toEqual([expect.objectContaining({ state: "completed", attempt_id: first.finalize.attemptId })]);
	expect(retry.kind).toBe("existing");
	expect(await rows("coordinator_auth_link_change_attempts")).toEqual(completed);
	expect(await preserved()).toEqual(before);
	expect(await rows("coordinator_auth_account_links")).toEqual([expect.objectContaining({ ended_at_ms: NOW + 10, end_reason: "user_disconnected", end_attempt_id: chosen.finalize.attemptId, revoked_at_ms: null })]);
	expect(await f.store.readAuthSession(hash(500), cfg)).toBeNull();
	expect(await f.store.readAuthSession(hash(501), cfg)).toBeNull();
	expect(await rows("coordinator_auth_sessions")).toEqual([expect.objectContaining({ revoked_at_ms: NOW + 10 }), expect.objectContaining({ revoked_at_ms: NOW + 10 })]);
	for (const table of ["coordinator_auth_account_profiles", "coordinator_auth_link_profile_refreshes"]) expect(await rows(table)).toEqual([]);
	expect((await rows("coordinator_auth_link_profiles")).filter((r) => r.link_id === f.linkId)).toEqual([]);
	expect(await status(f)).toMatchObject({ state: "disconnected", profile: { state: "unavailable" } });
});

it.each(["cancelled", "expired", "provider_failure"])("%s proof leaves the generation and published profile untouched", async (reason) => {
	// Arrange
	const f = await setup();
	const change = await prepareChange(f, "disconnect");
	await confirm(f, change);
	const links = await rows("coordinator_auth_account_links");
	const profile = (await status(f)).profile;
	// Act
	if (reason === "expired") f.advance();
	else expect(await f.management.failAuthLinkChangeAttempt({ attemptId: change.finalize.attemptId, requester: reason === "cancelled" ? { kind: "device", signer: input.signer } : { kind: "browser", browserTransactionHash: change.browser.browserTransactionHash }, reason: reason === "cancelled" ? "cancelled" : "provider_failure" }, cfg)).toMatchObject({ kind: "applied" });
	const result = await f.management.finalizeAuthLinkChangeAttempt(change.finalize, cfg);
	// Assert
	expect(result.kind).toBe("rejected");
	expect(await rows("coordinator_auth_account_links")).toEqual(links);
	expect((await status(f)).profile).toEqual(profile);
	expect(await rows("coordinator_auth_link_profile_refreshes")).toEqual([]);
});

it.each(["controller_attestation", "device_claim"] as const)("%s reconnect has one CAS winner, immutable A reservation, and an Identity-wide historical revocation barrier", async (authority) => {
	// Arrange: old session and pre-reconnect signin share the same clock timestamp.
	const f = await setup(authority);
	expect(await f.store.redeemAuthLinkSessionWithBrowserTransaction({ ...f.genesis.browser, credentialHash: hash(500) }, cfg)).toMatchObject({ kind: "issued" });
	const oldSignin = await signinProof(f, 600);
	const originalClaims = await rows("coordinator_auth_device_claims");
	await disconnect(f);
	const one = await prepareLink(f, "reconnect-one", 200, "synthetic-account-b");
	const two = await prepareLink(f, "reconnect-two", 300, "synthetic-account-c");
	// Act
	const results = await Promise.all([one, two].map((r) => f.store.finalizeAuthLinkAttempt(r.finalize, cfg)));
	// Assert: the loser leaves no generation or account reservation.
	expect(results.map((r) => r.kind).sort()).toEqual(["applied", "rejected"]);
	expect(await rows("coordinator_auth_account_links")).toEqual([expect.objectContaining({ generation: 1, link_id: f.linkId, ended_at_ms: NOW + 10 }), expect.objectContaining({ generation: 2, ended_at_ms: null })]);
	expect(await rows("coordinator_auth_account_associations")).toHaveLength(2);
	expect(await rows("coordinator_auth_device_claims")).toEqual(originalClaims);
	expect(await f.store.readAuthSession(hash(500), cfg)).toBeNull();
	expect(await f.store.redeemAuthLinkSessionWithBrowserTransaction({ ...f.genesis.browser, credentialHash: hash(501) }, cfg)).toMatchObject({ kind: "rejected" });
	expect(await f.store.signInWithConsumedBrowserTransaction({ browserTransactionHash: oldSignin, credentialHash: hash(502), account: account() }, cfg)).toMatchObject({ kind: "rejected" });
	// Act: a permanent reservation cannot be reassigned, even after ending A.
	const reassignment = db.prepare("INSERT INTO coordinator_auth_account_associations (coordinator_id,issuer,subject,identity_id,first_link_id,created_at_ms) VALUES (?,?,?,?,?,?)").bind(cfg.coordinatorId, cfg.issuer, account().subject, "another-identity", "another-link", NOW + 10).run();
	// Assert
	await expect(reassignment).rejects.toThrow();
	expect((await rows("coordinator_auth_account_associations")).find((r) => r.subject === account().subject)?.identity_id).toBe(input.identityId);
	expect(await status(f)).toMatchObject({ state: "linked" });
	// Act: admin revocation of historical A must immediately block current B/C.
	expect(await f.store.revokeAuthAccountLink({ linkId: f.linkId }, cfg)).toEqual({ kind: "revoked" });
	// Assert
	expect(await status(f)).toMatchObject({ state: "revoked", profile: { state: "unavailable" }, actions: { connect: false, disconnect: false, refresh: false } });
	expect(await f.management.createAuthLinkChangeAttempt({ ...input, attemptId: "blocked-refresh", intent: "refresh", runtimeVerifierHash: hash(800), browserStartHash: hash(801), loopbackRedirect }, cfg)).toMatchObject({ kind: "rejected" });
});

it("same-account reconnect fences old signin sequences while a fresh signin still works", async () => {
	// Arrange
	const f = await setup();
	const oldSignin = await signinProof(f, 600);
	await disconnect(f);
	const reconnect = await prepareLink(f, "reconnect-same", 200);
	expect(await f.store.finalizeAuthLinkAttempt(reconnect.finalize, cfg)).toMatchObject({ kind: "applied" });
	const freshSignin = await signinProof(f, 700);
	// Act
	const stale = await f.store.signInWithConsumedBrowserTransaction({ browserTransactionHash: oldSignin, credentialHash: hash(800), account: account() }, cfg);
	const fresh = await f.store.signInWithConsumedBrowserTransaction({ browserTransactionHash: freshSignin, credentialHash: hash(801), account: account() }, cfg);
	// Assert: timestamps tie; sequence, not wall clock, distinguishes these proofs.
	expect(stale.kind).toBe("rejected");
	expect(fresh.kind).toBe("issued");
	expect(await rows("coordinator_auth_sessions")).toHaveLength(1);
});

it("device-claim management admits only the genesis device, not another enrolled same-Identity reader", async () => {
	// Arrange: enrollment and shared Identity alone are not owner/management proof.
	const f = await setup("device_claim");
	const reader = { ...input.signer, deviceId: "reader", publicKey: otherKey, fingerprint: hash(900) };
	await f.store.enrollDevice(reader.groupId, { ...reader, identityId: input.identityId });
	const before = await preserved();
	const create = { ...input, intent: "refresh" as const, runtimeVerifierHash: hash(901), browserStartHash: hash(902), loopbackRedirect };
	// Act
	const denied = await f.management.createAuthLinkChangeAttempt({ ...create, signer: reader, attemptId: "reader-change" }, cfg);
	const allowed = await f.management.createAuthLinkChangeAttempt({ ...create, attemptId: "genesis-device-change" }, cfg);
	// Assert: no attestation, grant or ownership authority was minted by management.
	expect(denied.kind).toBe("rejected");
	expect(allowed.kind).toBe("created");
	expect(await preserved()).toEqual(before);
	expect(await rows("coordinator_auth_link_change_attempts")).toEqual([expect.objectContaining({ device_id: input.signer.deviceId, authority_kind: "device_claim" })]);
});
