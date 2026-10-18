import { env } from "cloudflare:workers";
import { expect, it } from "vitest";
import { restoreFrozenAuthPredecessor } from "./frozen-auth-predecessor-fixture.js";
import { disposeNativeAuthFixture } from "./owner-ceremony-test-fixtures.js";
import { AUTH_LIFECYCLE_CURRENT_DEFINITIONS, AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS } from "../../core/src/coordinator-auth-lifecycle-fresh-schema.js";
import { browserConfig, materials } from "../../core/src/coordinator-auth-browser-transaction-test-fixtures.js";
import { attempt } from "../../core/src/coordinator-auth-link-test-fixtures.js";
import { enroll, review } from "../../core/src/coordinator-auth-store-test-fixtures.js";
import {
	assertBrowserUniqueness,
	browserDefinitions,
	browserSnapshot,
	normalizeDefinitions,
	seedOldBrowserRows,
	type SchemaFixture,
} from "../../core/src/coordinator-auth-browser-migration-test-harness.js";
import { NOW } from "../../core/src/coordinator-auth-link-test-fixtures.js";
import { D1CoordinatorStore } from "../../core/src/d1-coordinator-store.js";

const fixture: SchemaFixture = {
	exec: async (sql, ...values) => {
		await env.COORDINATOR_DB.prepare(sql).bind(...values).run();
	},
	query: async (sql) => (await env.COORDINATOR_DB.prepare(sql).all<Record<string, unknown>>()).results,
};
const migration = env.TEST_MIGRATIONS.find((m) => m.name === "0029_add_owner_enrollment_attempts.sql");
if (!migration) throw new Error("Missing browser-purpose migration fixture");

it("native official migration preserves all six old signin/link rows and purge counters and rolls back SQL failure", async () => {
	await restoreFrozenAuthPredecessor();
	const expectedBrowser = normalizeDefinitions(await fixture.query(browserDefinitions));
	await env.COORDINATOR_DB.batch([
		env.COORDINATOR_DB.prepare("DROP TABLE coordinator_auth_browser_transactions"),
		env.COORDINATOR_DB.prepare("DROP TABLE coordinator_auth_signin_purge_floors"),
	]);
	for (const name of ["0020_add_auth_browser_transactions.sql", "0023_add_auth_signin_purge_floors.sql"]) {
		const old = env.TEST_MIGRATIONS.find((m) => m.name === name);
		if (!old) throw new Error(`Missing old migration ${name}`);
		await env.COORDINATOR_DB.batch(old.queries.map((sql) => env.COORDINATOR_DB.prepare(sql)));
	}
	try {
		await seedOldBrowserRows(fixture);
		const before = await browserSnapshot(fixture);
		const oldDefinition = await fixture.query(browserDefinitions);
		const failed = [...migration.queries];
		failed.splice(failed.findIndex((sql) => sql.includes("INSERT INTO coordinator_auth_browser_transactions_owner_upgrade")) + 1, 0, "SELECT absent_fixture_column FROM coordinator_auth_browser_transactions_owner_upgrade");
		await expect(env.COORDINATOR_DB.batch(failed.map((sql) => env.COORDINATOR_DB.prepare(sql)))).rejects.toThrow(/absent_fixture_column/);
		expect(await browserSnapshot(fixture)).toEqual(before);
		expect(await fixture.query(browserDefinitions)).toEqual(oldDefinition);
		await env.COORDINATOR_DB.batch(migration.queries.map((sql) => env.COORDINATOR_DB.prepare(sql)));
		expect(await browserSnapshot(fixture)).toEqual(before);
		expect(normalizeDefinitions(await fixture.query(browserDefinitions))).toEqual(expectedBrowser);
		await assertBrowserUniqueness(fixture);
	} finally {
		// Restore the browser schema even if rollback assertions fail.
		const tables = await fixture.query("SELECT sql FROM sqlite_master WHERE name = 'coordinator_auth_browser_transactions'");
		if (!String(tables[0]?.sql).includes("'owner_enroll'")) {
			await env.COORDINATOR_DB.batch(migration.queries.map((sql) => env.COORDINATOR_DB.prepare(sql)));
		}
	}
});

it("native legacy handlers reject reserved owner rows without burning browser material", async () => {
	// Arrange: explicitly dispose the populated historical test, then install a fresh current root.
	await disposeNativeAuthFixture();
	for (const { name } of AUTH_LIFECYCLE_CURRENT_DEFINITIONS.filter(({ type }) => type === "table")) await fixture.exec(`DROP TABLE IF EXISTS ${name}`);
	await env.COORDINATOR_DB.batch(AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS.map((sql) => env.COORDINATOR_DB.prepare(sql)));
	const store = new D1CoordinatorStore(env.COORDINATOR_DB, { authClock: () => NOW });
	await enroll(store);
	expect(await store.createAuthControllerAttestation(review())).toMatchObject({ kind: "created" });
	const start = attempt({ attemptId: "owner-attempt-a" });
	expect(await store.createAuthLinkAttempt(start, browserConfig)).toMatchObject({ kind: "created" });
	const input = materials();
	// Synthetic same-attempt/hash owner evidence tests purpose isolation, not provider verification.
	await fixture.exec(`UPDATE coordinator_auth_link_attempts SET state='browser_claimed', browser_transaction_hash=?, claimed_at_ms=? WHERE attempt_id=?`, "9".repeat(64), NOW, start.attemptId);
	await fixture.exec(`INSERT INTO coordinator_auth_browser_transactions
 (coordinator_id,browser_transaction_hash,purpose,attempt_id,state_hash,binder_hash,issuer,auth_config_revision,redirect_uri,state,nonce,pkce_verifier,created_at_ms,expires_at_ms)
 VALUES (?,?,'owner_enroll',?,?,?,?,?,?,'pending',?,?,?,?)`, browserConfig.coordinatorId, "9".repeat(64), start.attemptId, input.stateHash, input.binderHash, browserConfig.issuer, browserConfig.revision, browserConfig.redirectUri, input.nonce, input.pkceVerifier, NOW, NOW + 600000);
	const before = await fixture.query("SELECT * FROM coordinator_auth_browser_transactions");
	const linkBefore = await fixture.query("SELECT * FROM coordinator_auth_link_attempts");
	// Act: neither a matching attempt nor matching hash changes the reserved purpose.
	const denied = await store.consumeAuthBrowserTransaction(input, browserConfig);
	const resolved = await store.resolveAuthLinkBrowserTransaction({ attemptId: start.attemptId, binderHash: input.binderHash }, browserConfig);
	const reservedStart = await store.startAuthBrowserTransaction({ ...input, purpose: "owner_enroll" } as unknown as Parameters<typeof store.startAuthBrowserTransaction>[0], browserConfig);
	// Assert
	expect(denied).toEqual({ kind: "rejected", error: "transaction_unavailable" });
	expect(resolved).toBeNull();
	expect(reservedStart).toEqual({ kind: "rejected", error: "invalid_input" });
	expect(await fixture.query("SELECT * FROM coordinator_auth_browser_transactions")).toEqual(before);
	expect(await fixture.query("SELECT * FROM coordinator_auth_link_attempts")).toEqual(linkBefore);
	// Positive control: ordinary sign-in can still start, consume and retire independently.
	const signin = materials(2);
	expect(await store.startAuthBrowserTransaction(signin, browserConfig)).toMatchObject({ kind: "started" });
	expect(await store.consumeAuthBrowserTransaction(signin, browserConfig)).toMatchObject({ kind: "consumed", purpose: "signin" });
	expect(await store.startAuthBrowserTransaction(materials(3), browserConfig)).toMatchObject({ kind: "started" });
	expect(await store.retireAuthBrowserTransactions({ ...browserConfig, enabled: false }, { attemptId: start.attemptId })).toMatchObject({ kind: "retired", processedCount: 0 });
	expect(await store.retireAuthBrowserTransactions({ ...browserConfig, enabled: false })).toMatchObject({ kind: "retired", processedCount: 1 });
	expect(await fixture.query("SELECT * FROM coordinator_auth_browser_transactions WHERE purpose='owner_enroll'")).toEqual(before);
	// Positive expiry control: only expired owner secrets are scrubbed; the live owner survives.
	await fixture.exec(`INSERT INTO coordinator_auth_browser_transactions
 (coordinator_id,browser_transaction_hash,purpose,attempt_id,state_hash,binder_hash,issuer,auth_config_revision,redirect_uri,state,nonce,pkce_verifier,created_at_ms,expires_at_ms)
 SELECT coordinator_id,?,'owner_enroll','expired-owner-attempt',?,?,issuer,auth_config_revision,redirect_uri,'pending',nonce,pkce_verifier,?,?
 FROM coordinator_auth_browser_transactions WHERE purpose='owner_enroll' AND attempt_id=?`, "a".repeat(64), "b".repeat(64), "c".repeat(64), NOW - 600000, NOW, start.attemptId);
	const expired = await fixture.query("SELECT * FROM coordinator_auth_browser_transactions WHERE attempt_id='expired-owner-attempt'");
	expect(await store.maintainAuthBrowserTransactions({ coordinatorId: browserConfig.coordinatorId }, { limit: 1 })).toEqual({ kind: "maintained", processedCount: 1, more: true });
	expect(await fixture.query("SELECT * FROM coordinator_auth_browser_transactions WHERE attempt_id='expired-owner-attempt'")).toEqual(expired.map(row => ({ ...row, state: "expired", nonce: null, pkce_verifier: null })));
	expect(await fixture.query("SELECT * FROM coordinator_auth_browser_transactions WHERE attempt_id='owner-attempt-a'")).toEqual(before);
	for (const table of ["coordinator_auth_sessions", "coordinator_auth_account_links", "coordinator_device_ownership_bindings"]) expect(await fixture.query(`SELECT * FROM ${table}`)).toEqual([]);
});
