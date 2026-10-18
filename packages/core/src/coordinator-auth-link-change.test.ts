import { createHash, randomBytes } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import {
	config,
	input,
	NOW,
	seedAttestationSql,
	seedEnrollmentSql,
	seedKeyRevocationSql,
	seedLinkSql,
} from "../../cloudflare-coordinator-worker/test/device-claim-eligibility-fixture.js";
import { AccountManagementStatusOperations } from "./coordinator-account-management-status.js";
import { CoordinatorAuthBrowserTransactions } from "./coordinator-auth-browser-transaction.js";
import { upgradeAuthLifecycleSchema } from "./coordinator-auth-lifecycle-upgrade-sqlite.js";
import { insert } from "./coordinator-auth-lifecycle-upgrade-test-fixture.js";
import type { AuthLinkBackend, AuthLinkStatement } from "./coordinator-auth-link.js";
import { AuthLinkOperations } from "./coordinator-auth-link.js";
import { AuthLinkChangeOperations } from "./coordinator-auth-link-change.js";
import { AuthLinkChangeBrowserOperations } from "./coordinator-auth-link-change-browser.js";
import {
	AUTH_LINK_CHANGE_PURPOSE,
	type CoordinatorAuthLinkChangeIntent,
} from "./coordinator-auth-link-change-contract.js";
import { createCoordinatorAccountManagementStore } from "./coordinator-auth-link-change-store.js";
import { cleanAuthLinkProfiles } from "./coordinator-auth-link-profile.js";
import {
	encodeCoordinatorAuthProof32,
	hashCoordinatorAuthProofBytes32,
} from "./coordinator-auth-proof.js";
import { AuthSessionOperations } from "./coordinator-auth-session.js";
import { setupStore } from "./coordinator-auth-store-test-fixtures.js";
import { createCoordinatorBrowserAuthCallback } from "./coordinator-browser-auth-callback.js";
import { BROWSER_COOKIE_NAMES } from "./coordinator-browser-credential.js";
import { importBrowserCsrfKey } from "./coordinator-browser-csrf.js";
import { createCoordinatorBrowserLinkChange } from "./coordinator-browser-link-change.js";
import { EXPECTED_KEY_ID } from "./coordinator-ed25519-key-id-test-fixtures.js";
import { oidcFixture, PROVIDER } from "./coordinator-oidc-test-fixtures.js";
import { createInMemoryRequestRateLimiter } from "./request-rate-limit.js";

const cfg = { ...config, issuer: "https://accounts.google.com", redirectUri: PROVIDER.redirectUri };
const cleanup: (() => void)[] = [];
afterEach(() => {
	vi.restoreAllMocks();
	for (const close of cleanup.splice(0)) close();
});
function setup(options: { authority?: "controller_attestation" | "device_claim" } = {}) {
	const f = setupStore("SQLite");
	cleanup.push(() => {
		if (f.db.open) f.db.close();
	});
	f.db.exec(seedEnrollmentSql);
	if (options.authority === "device_claim") seedGenesis(f.db);
	else f.db.exec(seedAttestationSql + seedLinkSql.replaceAll(config.issuer, cfg.issuer));
	f.db
		.prepare("UPDATE enrolled_devices SET identity_id = ? WHERE device_id = ?")
		.run(input.identityId, input.signer.deviceId);
	upgradeAuthLifecycleSchema(f.db);
	let now = NOW + 10;
	let beforeBatch: (() => void) | null = null;
	const errors: unknown[] = [];
	const run = (s: AuthLinkStatement) => f.db.prepare(s.sql).run(...s.values).changes;
	const backend: AuthLinkBackend = {
		async first<T>(s: AuthLinkStatement) {
			return (f.db.prepare(s.sql).get(...s.values) as T | undefined) ?? null;
		},
		async run(s) {
			return run(s);
		},
		async batch(statements) {
			beforeBatch?.();
			try {
				return f.db.transaction(() => statements.map(run))();
			} catch (error) {
				errors.push(error);
				throw error;
			}
		},
	};
	const changes = new AuthLinkChangeOperations(backend, () => now);
	const browser = new AuthLinkChangeBrowserOperations(backend, () => now);
	const links = new AuthLinkOperations(backend, () => now);
	const transactions = new CoordinatorAuthBrowserTransactions(backend, () => now);
	const status = new AccountManagementStatusOperations(backend, () => now);
	const management = createCoordinatorAccountManagementStore(backend, () => now);
	const sessions = new AuthSessionOperations(backend, () => now);
	return {
		...f,
		changes,
		browser,
		links,
		transactions,
		status,
		management,
		sessions,
		errors,
		advance: (ms: number) => {
			now += ms;
		},
		beforeBatch: (fn: () => void) => {
			beforeBatch = fn;
		},
	};
}

function seedGenesis(db: ReturnType<typeof setupStore>["db"]) {
	const common = {
		coordinator_id: cfg.coordinatorId,
		identity_id: input.identityId,
		group_id: input.signer.groupId,
		device_id: input.signer.deviceId,
		public_key: input.signer.publicKey,
		fingerprint: input.signer.fingerprint,
		issuer: cfg.issuer,
		auth_config_revision: cfg.revision,
		attempt_id: "genesis-a",
	};
	insert(db, "coordinator_auth_link_attempts", {
		...common,
		controller_attestation_id: null,
		controller_review_receipt_id: null,
		controller_revision: null,
		authority_kind: "device_claim",
		runtime_verifier_hash: "6".repeat(64),
		browser_start_hash: "7".repeat(64),
		browser_transaction_hash: "8".repeat(64),
		completion_secret_hash: "9".repeat(64),
		loopback_redirect: create().loopbackRedirect,
		state: "finalized",
		account_subject: "private-subject",
		link_id: "link-a",
		created_at_ms: NOW - 100,
		claimed_at_ms: NOW - 90,
		oidc_verified_at_ms: NOW - 80,
		confirmed_at_ms: NOW - 70,
		finalized_at_ms: NOW - 60,
		expires_at_ms: NOW + 599900,
	});
	insert(db, "coordinator_auth_device_claims", {
		...common,
		claim_id: "link-a",
		key_id: EXPECTED_KEY_ID,
		created_at_ms: NOW - 60,
	});
	insert(db, "coordinator_auth_account_links", {
		coordinator_id: cfg.coordinatorId,
		link_id: "link-a",
		issuer: cfg.issuer,
		subject: "private-subject",
		identity_id: input.identityId,
		attempt_id: "genesis-a",
		controller_attestation_id: null,
		device_claim_id: "link-a",
		authority_kind: "device_claim",
		auth_config_revision: cfg.revision,
		created_at_ms: NOW - 60,
	});
	insert(db, "coordinator_auth_link_audit_log", {
		coordinator_id: cfg.coordinatorId,
		link_id: "link-a",
		action: "link_created",
		attempt_id: "genesis-a",
		identity_id: input.identityId,
		group_id: input.signer.groupId,
		device_id: input.signer.deviceId,
		fingerprint: input.signer.fingerprint,
		controller_attestation_id: null,
		device_claim_id: "link-a",
		authority_kind: "device_claim",
		auth_config_revision: cfg.revision,
		created_at_ms: NOW - 60,
	});
}
const create = (intent: CoordinatorAuthLinkChangeIntent = "refresh") => ({
	...input,
	attemptId: "change-a",
	intent,
	runtimeVerifierHash: "b".repeat(64),
	browserStartHash: "c".repeat(64),
	loopbackRedirect: "http://127.0.0.1:4567/codemem/auth/complete",
});
const final = {
	...input,
	purpose: AUTH_LINK_CHANGE_PURPOSE,
	coordinatorId: cfg.coordinatorId,
	attemptId: "change-a",
	groupId: input.signer.groupId,
	deviceId: input.signer.deviceId,
	fingerprint: input.signer.fingerprint,
	runtimeVerifierHash: "b".repeat(64),
	completionSecretHash: "d".repeat(64),
};
async function verify(
	f: ReturnType<typeof setup>,
	intent: CoordinatorAuthLinkChangeIntent = "refresh",
	profile: unknown = {},
) {
	const created = await f.changes.createAuthLinkChangeAttempt(create(intent), cfg);
	expect(f.errors).toEqual([]);
	expect(created).toMatchObject({
		kind: "created",
		status: { state: "pending", intent },
	});
	expect(
		await f.browser.startAuthLinkChangeBrowser(
			{
				attemptId: "change-a",
				browserStartHash: "c".repeat(64),
				stateHash: "e".repeat(64),
				binderHash: "f".repeat(64),
				nonce: "n".repeat(43),
				pkceVerifier: "p".repeat(43),
			},
			cfg,
		),
	).toBe(true);
	const consumed = await f.browser.consumeAuthLinkChangeBrowser(
		{ stateHash: "e".repeat(64), binderHash: "f".repeat(64) },
		cfg,
	);
	expect(consumed).not.toBeNull();
	if (!consumed) throw new Error("missing proof");
	expect(
		await f.changes.recordAuthLinkChangeOidcVerified(
			{ ...consumed, account: { issuer: cfg.issuer, subject: "private-subject" }, profile },
			cfg,
		),
	).toMatchObject({ kind: "applied", status: { state: "oidc_verified" } });
	return consumed;
}
async function confirm(
	f: ReturnType<typeof setup>,
	intent: CoordinatorAuthLinkChangeIntent = "refresh",
	profile: unknown = {},
) {
	const consumed = await verify(f, intent, profile);
	expect(
		await f.changes.confirmAuthLinkChangeAttempt(
			{
				...consumed,
				completionSecretHash: final.completionSecretHash,
				confirmation: intent === "disconnect" ? "browser" : "verified_refresh",
			},
			cfg,
		),
	).toMatchObject({ kind: "applied", status: { state: "confirmed" } });
	return consumed;
}
it("keeps verified claims private until signed refresh and accepts an empty snapshot", async () => {
	const f = setup();
	await confirm(f);
	expect(f.db.prepare("SELECT * FROM coordinator_auth_link_profile_refreshes").all()).toEqual([]);
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "applied",
		status: { state: "completed", intent: "refresh" },
	});
	expect(f.db.prepare("SELECT * FROM coordinator_auth_link_profile_refreshes").get()).toMatchObject(
		{
			link_id: "link-a",
			display_name: null,
			email: null,
			picture_url: null,
			source_order: 2,
			source_attempt_id: "change-a",
		},
	);
	expect(f.db.prepare("SELECT * FROM coordinator_auth_link_profiles").all()).toEqual([]);
	expect(
		f.db.prepare("SELECT ended_at_ms,revoked_at_ms FROM coordinator_auth_account_links").get(),
	).toEqual({ ended_at_ms: null, revoked_at_ms: null });
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "existing",
	});
});
it("disconnect requires its hosted proof fence then ends one generation without deleting its association", async () => {
	const f = setup();
	const consumed = await verify(f, "disconnect", { displayName: "Fresh name" });
	expect(
		await f.changes.confirmAuthLinkChangeAttempt(
			{
				...consumed,
				completionSecretHash: final.completionSecretHash,
				confirmation: "verified_refresh",
			},
			cfg,
		),
	).toMatchObject({ kind: "rejected" });
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "rejected",
	});
	await f.changes.confirmAuthLinkChangeAttempt(
		{ ...consumed, completionSecretHash: final.completionSecretHash, confirmation: "browser" },
		cfg,
	);
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "applied",
	});
	expect(
		f.db
			.prepare(
				"SELECT ended_at_ms,end_reason,end_attempt_id,revoked_at_ms FROM coordinator_auth_account_links",
			)
			.get(),
	).toEqual({
		ended_at_ms: NOW + 10,
		end_reason: "user_disconnected",
		end_attempt_id: "change-a",
		revoked_at_ms: null,
	});
	expect(
		f.db.prepare("SELECT count(*) AS n FROM coordinator_auth_account_associations").get(),
	).toEqual({ n: 1 });
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "existing",
	});
});
it.each([
	"disabled",
	"assignment",
	"key_revocation",
	"attestation",
	"security_revocation",
	"expiry",
])("rechecks %s at the winning finalization", async (change) => {
	const f = setup();
	await confirm(f, "disconnect");
	if (change === "expiry") f.advance(600000);
	else {
		const mutations: Record<string, string> = {
			disabled: "UPDATE enrolled_devices SET enabled = 0 WHERE device_id = 'device-a'",
			assignment: "UPDATE enrolled_devices SET identity_id = 'other' WHERE device_id = 'device-a'",
			key_revocation: seedKeyRevocationSql,
			attestation:
				"UPDATE coordinator_auth_controller_attestations SET revoked_at = 'revoked' WHERE attestation_id = 'attestation-a'",
			security_revocation: `UPDATE coordinator_auth_account_links SET revoked_at_ms = ${NOW + 1}`,
		};
		f.beforeBatch(() => f.db.exec(mutations[change] ?? ""));
	}
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "rejected",
	});
	expect(f.db.prepare("SELECT ended_at_ms FROM coordinator_auth_account_links").get()).toEqual({
		ended_at_ms: null,
	});
	expect(f.db.prepare("SELECT state FROM coordinator_auth_link_change_attempts").get()).toEqual({
		state: "confirmed",
	});
});
it("rolls back receipt completion when the end write unexpectedly matches zero", async () => {
	const f = setup();
	await confirm(f, "disconnect");
	f.db.exec(
		"CREATE TRIGGER ignore_end BEFORE UPDATE ON coordinator_auth_account_links WHEN NEW.ended_at_ms IS NOT NULL BEGIN SELECT RAISE(IGNORE); END",
	);
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "rejected",
	});
	expect(f.db.prepare("SELECT state FROM coordinator_auth_link_change_attempts").get()).toEqual({
		state: "confirmed",
	});
});

it("rolls back a completed refresh receipt when snapshot publication is ignored", async () => {
	const f = setup();
	await confirm(f, "refresh", {});
	f.db.exec(
		"CREATE TRIGGER ignore_refresh BEFORE INSERT ON coordinator_auth_link_profile_refreshes BEGIN SELECT RAISE(IGNORE); END",
	);
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "rejected",
	});
	expect(f.db.prepare("SELECT state FROM coordinator_auth_link_change_attempts").get()).toEqual({
		state: "confirmed",
	});
	expect(
		f.db
			.prepare(
				"SELECT count(*) AS n FROM coordinator_auth_link_profiles WHERE source_purpose = 'link_change'",
			)
			.get(),
	).toEqual({ n: 1 });
});
it("cancellation discards staging without lifecycle mutation", async () => {
	const f = setup();
	await confirm(f, "disconnect");
	expect(
		await f.changes.failAuthLinkChangeAttempt(
			{
				attemptId: "change-a",
				requester: { kind: "device", signer: input.signer },
				reason: "cancelled",
			},
			cfg,
		),
	).toMatchObject({ kind: "applied", status: { state: "failed" } });
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "rejected",
	});
	expect(f.db.prepare("SELECT * FROM coordinator_auth_link_profiles").all()).toEqual([]);
	expect(f.db.prepare("SELECT ended_at_ms FROM coordinator_auth_account_links").get()).toEqual({
		ended_at_ms: null,
	});
});

it("projects server-derived V3 management capabilities and a verified empty profile", async () => {
	const f = setup();
	expect(
		await f.status.readAccountManagementStatus(input.signer, cfg, { identityId: input.identityId }),
	).toMatchObject({
		version: 3,
		state: "linked",
		profile: { state: "unavailable" },
		actions: { connect: false, disconnect: true, refresh: true },
	});
	await confirm(f);
	await f.changes.finalizeAuthLinkChangeAttempt(final, cfg);
	expect(
		await f.status.readAccountManagementStatus(input.signer, cfg, { identityId: input.identityId }),
	).toMatchObject({ state: "linked", profile: { state: "verified", verifiedAtMs: NOW + 10 } });
});

async function reconnect(
	f: ReturnType<typeof setup>,
	attemptId = "reconnect-a",
	subject = "account-b",
) {
	const hash = (purpose: string) =>
		createHash("sha256").update(`${attemptId}:${purpose}`).digest("hex");
	const prior = f.db
		.prepare(
			"SELECT authority_kind FROM coordinator_auth_account_links ORDER BY generation DESC LIMIT 1",
		)
		.get() as { authority_kind: "device_claim" | "controller_attestation" };
	const authority =
		prior.authority_kind === "device_claim"
			? { kind: "device_claim" as const, identityId: input.identityId }
			: { kind: "controller_attestation" as const };
	expect(
		await f.links.createAuthLinkAttempt(
			{
				authority,
				expectedIdentityId: input.identityId,
				attemptId,
				signer: input.signer,
				runtimeVerifierHash: hash("runtime"),
				browserStartHash: hash("start"),
				loopbackRedirect: create().loopbackRedirect,
			},
			cfg,
		),
	).toMatchObject({ kind: "created" });
	expect(
		await f.transactions.startAuthBrowserTransaction(
			{
				purpose: "link",
				attemptId,
				browserStartHash: hash("start"),
				stateHash: hash("state"),
				binderHash: hash("binder"),
				nonce: "n".repeat(43),
				pkceVerifier: "p".repeat(43),
			},
			cfg,
		),
	).toMatchObject({ kind: "started" });
	const consumed = await f.transactions.consumeAuthBrowserTransaction(
		{ stateHash: hash("state"), binderHash: hash("binder") },
		cfg,
	);
	if (consumed.kind !== "consumed") throw new Error("missing reconnect proof");
	expect(
		await f.links.recordAuthLinkOidcVerified(
			{
				attemptId,
				browserTransactionHash: consumed.browserTransactionHash,
				account: { issuer: cfg.issuer, subject },
				profile: { displayName: "Account B" },
			},
			cfg,
		),
	).toMatchObject({ kind: "applied" });
	expect(
		await f.links.confirmAuthLinkAttempt(
			{
				attemptId,
				browserTransactionHash: consumed.browserTransactionHash,
				completionSecretHash: hash("completion"),
			},
			cfg,
		),
	).toMatchObject({ kind: "applied" });
	return {
		...final,
		purpose: "coordinator-account-link-v1" as const,
		attemptId,
		runtimeVerifierHash: hash("runtime"),
		completionSecretHash: hash("completion"),
	};
}
it("disconnects A then commits a separate fresh B generation and retains A's association", async () => {
	const f = setup();
	await confirm(f, "disconnect");
	await f.changes.finalizeAuthLinkChangeAttempt(final, cfg);
	expect(
		await f.status.readAccountManagementStatus(input.signer, cfg, { identityId: input.identityId }),
	).toMatchObject({
		state: "disconnected",
		actions: { connect: true, disconnect: false, refresh: false },
	});
	const next = await reconnect(f);
	expect(await f.links.finalizeAuthLinkAttempt(next, cfg)).toMatchObject({ kind: "applied" });
	expect(
		f.db
			.prepare(
				"SELECT subject,generation,ended_at_ms FROM coordinator_auth_account_links ORDER BY generation",
			)
			.all(),
	).toEqual([
		{ subject: "private-subject", generation: 1, ended_at_ms: NOW + 10 },
		{ subject: "account-b", generation: 2, ended_at_ms: null },
	]);
	expect(
		f.db
			.prepare(
				"SELECT subject,identity_id FROM coordinator_auth_account_associations ORDER BY subject",
			)
			.all(),
	).toEqual([
		{ subject: "account-b", identity_id: input.identityId },
		{ subject: "private-subject", identity_id: input.identityId },
	]);
	expect(await f.links.finalizeAuthLinkAttempt(next, cfg)).toMatchObject({ kind: "existing" });
});

it("requires the exact original device claim and reuses its genesis through A-to-B reconnect", async () => {
	const f = setup({ authority: "device_claim" });
	await confirm(f, "disconnect");
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "applied",
	});
	const next = await reconnect(f);
	expect(await f.links.finalizeAuthLinkAttempt(next, cfg)).toMatchObject({ kind: "applied" });
	expect(f.db.prepare("SELECT count(*) AS n FROM coordinator_auth_device_claims").get()).toEqual({
		n: 1,
	});
	expect(
		f.db
			.prepare(
				"SELECT device_claim_id,generation FROM coordinator_auth_account_links ORDER BY generation",
			)
			.all(),
	).toEqual([
		{ device_claim_id: "link-a", generation: 1 },
		{ device_claim_id: "link-a", generation: 2 },
	]);
	expect(
		await f.status.readAccountManagementStatus(input.signer, cfg, { identityId: input.identityId }),
	).toMatchObject({
		state: "linked",
		authority: "device_claim",
		actions: { connect: false, disconnect: true, refresh: true },
	});
	expect(
		await f.changes.createAuthLinkChangeAttempt(
			{
				...create(),
				attemptId: "second-refresh",
				runtimeVerifierHash: "e".repeat(64),
				browserStartHash: "f".repeat(64),
			},
			cfg,
		),
	).toMatchObject({ kind: "created" });
});

it("allows only one of two reconnect finalizations to win the latest-ended generation CAS", async () => {
	const f = setup();
	await confirm(f, "disconnect");
	await f.changes.finalizeAuthLinkChangeAttempt(final, cfg);
	const first = await reconnect(f, "reconnect-one", "account-b");
	const second = await reconnect(f, "reconnect-two", "account-c");
	const results = await Promise.all([
		f.links.finalizeAuthLinkAttempt(first, cfg),
		f.links.finalizeAuthLinkAttempt(second, cfg),
	]);
	expect(results.filter((result) => result.kind === "applied")).toHaveLength(1);
	expect(results.filter((result) => result.kind === "rejected")).toHaveLength(1);
	expect(f.db.prepare("SELECT count(*) AS n FROM coordinator_auth_account_links").get()).toEqual({
		n: 2,
	});
	expect(
		f.db.prepare("SELECT count(*) AS n FROM coordinator_auth_account_associations").get(),
	).toEqual({ n: 2 });
});
it("a security revocation on ended A blocks active B and new management without exposing profile", async () => {
	const f = setup({ authority: "device_claim" });
	await confirm(f, "disconnect");
	await f.changes.finalizeAuthLinkChangeAttempt(final, cfg);
	const next = await reconnect(f);
	await f.links.finalizeAuthLinkAttempt(next, cfg);
	f.db
		.prepare("UPDATE coordinator_auth_account_links SET revoked_at_ms = ? WHERE generation = 1")
		.run(NOW + 10);
	expect(
		await f.status.readAccountManagementStatus(input.signer, cfg, { identityId: input.identityId }),
	).toMatchObject({
		state: "revoked",
		profile: { state: "unavailable" },
		actions: { connect: false, disconnect: false, refresh: false },
	});
	expect(
		await f.changes.createAuthLinkChangeAttempt(
			{
				...create(),
				attemptId: "refresh-blocked",
				runtimeVerifierHash: "e".repeat(64),
				browserStartHash: "f".repeat(64),
			},
			cfg,
		),
	).toMatchObject({ kind: "rejected" });
	expect(
		f.db
			.prepare("SELECT ended_at_ms FROM coordinator_auth_account_links WHERE generation = 2")
			.get(),
	).toEqual({ ended_at_ms: null });
});
it("permits fresh same-issuer revision rotation without rewriting a genesis claim", async () => {
	const f = setup({ authority: "device_claim" });
	const rotated = { ...cfg, revision: "9".repeat(64) };
	const claims = f.db.prepare("SELECT * FROM coordinator_auth_device_claims").all();
	expect(await f.changes.createAuthLinkChangeAttempt(create(), rotated)).toMatchObject({
		kind: "created",
	});
	expect(
		await f.changes.createAuthLinkChangeAttempt(
			{
				...create(),
				attemptId: "wrong-issuer",
				browserStartHash: "e".repeat(64),
				runtimeVerifierHash: "f".repeat(64),
			},
			{ ...rotated, issuer: "https://other.example.test" },
		),
	).toMatchObject({ kind: "rejected" });
	expect(f.db.prepare("SELECT * FROM coordinator_auth_device_claims").all()).toEqual(claims);
});

async function signIn(f: ReturnType<typeof setup>, label: string) {
	const hash = (purpose: string) =>
		createHash("sha256").update(`${label}:${purpose}`).digest("hex");
	const materials = {
		purpose: "signin" as const,
		stateHash: hash("state"),
		binderHash: hash("binder"),
		nonce: "n".repeat(43),
		pkceVerifier: "p".repeat(43),
	};
	expect(await f.transactions.startAuthBrowserTransaction(materials, cfg)).toMatchObject({
		kind: "started",
	});
	const consumed = await f.transactions.consumeAuthBrowserTransaction(materials, cfg);
	if (consumed.kind !== "consumed") throw new Error("missing sign-in proof");
	const result = await f.sessions.signInWithConsumedBrowserTransaction(
		{
			browserTransactionHash: consumed.browserTransactionHash,
			account: { issuer: cfg.issuer, subject: "private-subject" },
			credentialHash: hash("credential"),
		},
		cfg,
	);
	if (result.kind !== "issued") throw new Error(`sign-in seed rejected: ${result.error}`);
	return {
		...result.session,
		credentialHash: hash("credential"),
		transactionHash: consumed.browserTransactionHash,
	};
}
it("disconnect revokes every target session and removes all three display sources atomically", async () => {
	const f = setup();
	const first = await signIn(f, "first");
	await signIn(f, "second");
	insert(f.db, "coordinator_auth_account_profiles", {
		coordinator_id: cfg.coordinatorId,
		link_id: "link-a",
		display_name: "Sign-in profile",
		source_session_id: first.sessionId,
		source_signed_in_at_ms: NOW + 10,
		source_order: 2,
	});
	insert(f.db, "coordinator_auth_link_profiles", {
		coordinator_id: cfg.coordinatorId,
		attempt_id: "historical-attempt",
		issuer: cfg.issuer,
		subject: "private-subject",
		auth_config_revision: cfg.revision,
		browser_transaction_hash: "a".repeat(64),
		link_id: "link-a",
		display_name: "Link-time profile",
		verified_at_ms: NOW - 10,
	});
	insert(f.db, "coordinator_auth_link_profile_refreshes", {
		coordinator_id: cfg.coordinatorId,
		link_id: "link-a",
		display_name: "Older refresh display",
		source_attempt_id: "older-display-source",
		verified_at_ms: NOW - 10,
		source_order: 2,
	});
	await confirm(f, "disconnect");
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "applied",
	});
	expect(f.db.prepare("SELECT revoked_at_ms FROM coordinator_auth_sessions").all()).toEqual([
		{ revoked_at_ms: NOW + 10 },
		{ revoked_at_ms: NOW + 10 },
	]);
	for (const table of [
		"coordinator_auth_account_profiles",
		"coordinator_auth_link_profiles",
		"coordinator_auth_link_profile_refreshes",
	])
		expect(f.db.prepare(`SELECT * FROM ${table}`).all()).toEqual([]);
	expect(f.db.prepare("SELECT count(*) AS n FROM coordinator_auth_session_receipts").get()).toEqual(
		{ n: 2 },
	);
});
it("refresh preserves sessions, follows source order instead of timestamps, and retains staging across cleanup", async () => {
	const f = setup();
	await confirm(f, "refresh", { displayName: "Earlier intent" });
	const session = await signIn(f, "later-intent");
	const before = f.db.prepare("SELECT * FROM coordinator_auth_sessions").all();
	insert(f.db, "coordinator_auth_account_profiles", {
		coordinator_id: cfg.coordinatorId,
		link_id: "link-a",
		display_name: "Later intent",
		source_session_id: session.sessionId,
		source_signed_in_at_ms: NOW + 10,
		source_order: 3,
	});
	const cleanup = cleanAuthLinkProfiles(cfg, NOW + 10, 32);
	f.db.prepare(cleanup.sql).run(...cleanup.values);
	expect(
		f.db
			.prepare(
				"SELECT count(*) AS n FROM coordinator_auth_link_profiles WHERE source_purpose = 'link_change'",
			)
			.get(),
	).toEqual({ n: 1 });
	expect(await f.changes.finalizeAuthLinkChangeAttempt(final, cfg)).toMatchObject({
		kind: "applied",
	});
	expect(f.db.prepare("SELECT * FROM coordinator_auth_sessions").all()).toEqual(before);
	expect(
		await f.status.readAccountManagementStatus(input.signer, cfg, { identityId: input.identityId }),
	).toMatchObject({ profile: { state: "verified", displayName: "Later intent" }, state: "linked" });
});

function hidden(html: string, name: string): string {
	const value = new RegExp(`name="${name}" value="([^"]+)"`).exec(html)?.[1];
	if (!value) throw new Error(`Missing fixture field ${name}`);
	return value.replaceAll("&amp;", "&");
}
function browserPost(path: string, cookie: string, body: Record<string, string>) {
	return new Request(new URL(path, cfg.redirectUri), {
		method: "POST",
		headers: {
			Origin: new URL(cfg.redirectUri).origin,
			Cookie: cookie,
			"Content-Type": "application/x-www-form-urlencoded",
		},
		body: new URLSearchParams(body),
	});
}
async function browserSetup(intent: CoordinatorAuthLinkChangeIntent) {
	vi.spyOn(Date, "now").mockReturnValue(NOW + 10);
	const f = setup();
	const oidc = oidcFixture({ issuer: cfg.issuer });
	oidc.claims.sub = "private-subject";
	const browserConfig = {
		...cfg,
		clientId: PROVIDER.clientId,
		clientSecret: PROVIDER.clientSecret,
	};
	const handlers = await createCoordinatorBrowserLinkChange({
		config: browserConfig,
		csrfKey: await importBrowserCsrfKey(randomBytes(32)),
		limiter: createInMemoryRequestRateLimiter({ now: () => NOW + 10 }),
		oidcOptions: { fetch: oidc.fetch },
		store: {
			...f.management,
			readAuthBrowserTransactionActivity: f.transactions.readAuthBrowserTransactionActivity.bind(
				f.transactions,
			),
		},
	});
	const startCode = randomBytes(32);
	await f.changes.createAuthLinkChangeAttempt(
		{ ...create(intent), browserStartHash: await hashCoordinatorAuthProofBytes32(startCode) },
		cfg,
	);
	const url = new URL("/auth/link-change/start", cfg.redirectUri);
	url.searchParams.set("attempt_id", "change-a");
	url.searchParams.set("start_code", encodeCoordinatorAuthProof32(startCode));
	const page = (await handlers.startPage(new Request(url))).response;
	expect(page.status).toBe(200);
	const html = await page.text();
	const startCookie = page.headers
		.getSetCookie()
		.map((c) => c.split(";")[0])
		.join("; ");
	const started = (
		await handlers.start(
			browserPost("/auth/link-change/start", startCookie, {
				csrf: hidden(html, "csrf"),
				attempt_id: "change-a",
				start_code: encodeCoordinatorAuthProof32(startCode),
			}),
			"fixture-browser",
		)
	).response;
	expect(started.status).toBe(200);
	const authorization = /href="([^"]+)"/.exec(await started.text())?.[1]?.replaceAll("&amp;", "&");
	if (!authorization) throw new Error("missing provider URL");
	const transactionCookie = started.headers
		.getSetCookie()
		.find((c) => c.startsWith(`${BROWSER_COOKIE_NAMES.transaction}=`))
		?.split(";")[0];
	if (!transactionCookie) throw new Error("missing transaction cookie");
	const callback = await createCoordinatorBrowserAuthCallback({
		config: browserConfig,
		store: f.store,
		completeLink: async () => {
			throw new Error("wrong purpose");
		},
		changeCallback: handlers.callback,
		purposeStore: f.transactions,
		oidcOptions: { fetch: oidc.fetch },
	});
	if (!callback.ok) throw new Error("callback setup failed");
	return {
		...f,
		handlers,
		oidc,
		callback,
		transactionCookie,
		providerCallback: oidc.authorize(authorization),
	};
}
it.each(["disconnect", "refresh"] as const)(
	"runs the real %s browser ceremony through fresh OIDC and shared-purpose callback dispatch",
	async (intent) => {
		const f = await browserSetup(intent);
		const callback = await f.callback.handlers.callback(
			new Request(f.providerCallback, { headers: { Cookie: f.transactionCookie } }),
		);
		expect(callback.response.status).toBe(200);
		let html = await callback.response.text();
		expect(callback.response.headers.getSetCookie()).toEqual([]);
		if (intent === "disconnect") {
			expect(html.match(/>Unlink Google account<\/button>/g)).toHaveLength(1);
			expect(f.db.prepare("SELECT state FROM coordinator_auth_link_change_attempts").get()).toEqual(
				{ state: "oidc_verified" },
			);
			const confirmed = (
				await f.handlers.confirm(
					browserPost("/auth/link-change/confirm", f.transactionCookie, {
						csrf: hidden(html, "csrf"),
						attempt_id: "change-a",
					}),
					"fixture-browser",
				)
			).response;
			expect(confirmed.status).toBe(200);
			html = await confirmed.text();
		} else expect(html).not.toContain("Unlink Google account</button>");
		expect(f.db.prepare("SELECT state FROM coordinator_auth_link_change_attempts").get()).toEqual({
			state: "confirmed",
		});
		expect(f.db.prepare("SELECT ended_at_ms FROM coordinator_auth_account_links").get()).toEqual({
			ended_at_ms: null,
		});
		expect(f.db.prepare("SELECT * FROM coordinator_auth_link_profile_refreshes").all()).toEqual([]);
		const completion = new URL(
			/href="([^"]+)"/.exec(html)?.[1]?.replaceAll("&amp;", "&") ?? "https://invalid.test",
		).searchParams.get("completion");
		if (!completion) throw new Error("missing loopback completion");
		const completed = await f.changes.finalizeAuthLinkChangeAttempt(
			{
				...final,
				completionSecretHash: await hashCoordinatorAuthProofBytes32(
					Buffer.from(completion, "base64url"),
				),
			},
			cfg,
		);
		expect(completed).toMatchObject({ kind: "applied", status: { state: "completed", intent } });
		expect(
			f.db.prepare("SELECT nonce,pkce_verifier FROM coordinator_auth_browser_transactions").get(),
		).toEqual({ nonce: null, pkce_verifier: null });
	},
);

it("does not disclose the target or publish profile data when fresh proof is for another account", async () => {
	const f = await browserSetup("refresh");
	f.oidc.claims.sub = "wrong-account";
	const callback = await f.callback.handlers.callback(
		new Request(f.providerCallback, { headers: { Cookie: f.transactionCookie } }),
	);
	expect(callback.response.status).toBe(403);
	const html = await callback.response.text();
	expect(html).not.toContain("private-subject");
	expect(html).not.toContain("wrong-account");
	expect(f.db.prepare("SELECT state FROM coordinator_auth_link_change_attempts").get()).toEqual({
		state: "browser_claimed",
	});
	expect(f.db.prepare("SELECT * FROM coordinator_auth_link_profiles").all()).toEqual([]);
	expect(f.db.prepare("SELECT ended_at_ms FROM coordinator_auth_account_links").get()).toEqual({
		ended_at_ms: null,
	});
});
