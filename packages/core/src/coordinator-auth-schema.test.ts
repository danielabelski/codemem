import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import {
	legacyLinkAuthorityRowsSql,
	linkAuthorityTables,
	withoutNewAuthorityColumns,
} from "../../cloudflare-coordinator-worker/test/link-authority-upgrade-fixture.js";
import { BetterSqliteCoordinatorStore } from "./better-sqlite-coordinator-store.js";
import { COORDINATOR_AUTH_DEVICE_CLAIM_SCHEMA_STATEMENTS as proof } from "./coordinator-auth-device-claim-schema.js";
import { AUTH_SCHEMA_V2_READINESS_SQL } from "./coordinator-auth-lifecycle-predecessor.js";
import { upgradeAuthLifecycleSchema } from "./coordinator-auth-lifecycle-upgrade-sqlite.js";
import { frozenV2Database } from "./coordinator-auth-lifecycle-upgrade-test-fixture.js";
import { AUTH_LINK_SCHEMA_SQL } from "./coordinator-auth-link-contract.js";
import { LEGACY_INLINE_AUTH_LINK_SCHEMA_SQL } from "./coordinator-auth-link-legacy-inline-test-fixture.js";
import { attempt, cfg } from "./coordinator-auth-link-test-fixtures.js";
import { CoordinatorAuthSchemaUpgradeRequiredError } from "./coordinator-auth-schema.js";
import { upgradeCoordinatorAuthSchemaFile } from "./coordinator-auth-schema-operator.js";

const directory = mkdtempSync(join(tmpdir(), "auth-cutover-"));
afterEach(() => {
	vi.restoreAllMocks();
});
// Each fixture file is disposable; no default profile or coordinator path is opened.
it("refuses old optional auth before a new-column query, keeps ordinary operations usable, and explicitly upgrades all rows", async () => {
	const path = join(directory, "legacy.sqlite");
	const legacy = frozenV2Database();
	legacy.exec(linkAuthorityTables.map((table) => `DROP TABLE ${table};`).join("\n"));
	legacy.exec("DROP TABLE coordinator_auth_device_claims");
	legacy.exec(LEGACY_INLINE_AUTH_LINK_SCHEMA_SQL);
	legacy.exec(legacyLinkAuthorityRowsSql);
	const before = linkAuthorityTables.map((table) =>
		legacy.prepare(`SELECT rowid,* FROM ${table} ORDER BY rowid`).all(),
	);
	writeFileSync(path, legacy.serialize());
	legacy.close();
	const store = new BetterSqliteCoordinatorStore(path);
	try {
		const queries: string[] = [];
		const prepare = store.db.prepare.bind(store.db);
		const trace = vi.spyOn(store.db, "prepare").mockImplementation((sql) => {
			queries.push(sql);
			return prepare(sql);
		});
		await expect(store.createAuthLinkAttempt(attempt(), cfg)).rejects.toBeInstanceOf(
			CoordinatorAuthSchemaUpgradeRequiredError,
		);
		expect(queries.every((sql) => sql.includes("sqlite_master"))).toBe(true);
		trace.mockRestore();
		await store.createGroup("signed-sync-group");
		expect(await store.listGroups()).toHaveLength(1);
		expect(
			store.db
				.prepare(
					"SELECT 1 FROM pragma_table_info('coordinator_auth_link_attempts') WHERE name='authority_kind'",
				)
				.get(),
		).toBeUndefined();
		upgradeCoordinatorAuthSchemaFile(path);
		expect(store.db.prepare(AUTH_SCHEMA_V2_READINESS_SQL).get()).toEqual({ ready: 10 });
		await expect(store.assertAuthSchemaReady()).rejects.toBeInstanceOf(
			CoordinatorAuthSchemaUpgradeRequiredError,
		);
		expect(
			linkAuthorityTables.map((table) =>
				withoutNewAuthorityColumns(
					store.db.prepare(`SELECT rowid,* FROM ${table} ORDER BY rowid`).all() as Record<
						string,
						unknown
					>[],
				),
			),
		).toEqual(before);
		upgradeAuthLifecycleSchema(store.db);
		await expect(store.assertAuthSchemaReady()).resolves.toBeUndefined();
		expect(await store.maintainAuthLinkAttempts(cfg)).toMatchObject({ kind: "maintained" });
		expect(
			store.db
				.prepare("SELECT sql FROM sqlite_master WHERE name='coordinator_auth_device_claims'")
				.get(),
		).toMatchObject({ sql: expect.stringContaining("WITHOUT ROWID") });
	} finally {
		await store.close();
	}
});

it("rolls back fresh link DDL together with a failed proof install, then retries", async () => {
	const path = join(directory, "fresh.sqlite");
	const exec = Database.prototype.exec;
	let failed: Database.Database | undefined;
	const fault = vi.spyOn(Database.prototype, "exec").mockImplementation(function (
		this: Database.Database,
		sql,
	) {
		if (sql.includes("CREATE TABLE IF NOT EXISTS coordinator_auth_device_claims")) {
			failed = this;
			throw new Error("fixture proof failure");
		}
		return exec.call(this, sql);
	});
	expect(() => new BetterSqliteCoordinatorStore(path)).toThrow("fixture proof failure");
	fault.mockRestore();
	failed?.close();
	const db = new Database(path);
	expect(
		db
			.prepare(
				"SELECT name FROM sqlite_master WHERE name IN ('coordinator_auth_link_attempts','coordinator_auth_account_links','coordinator_auth_link_audit_log','coordinator_auth_device_claims')",
			)
			.all(),
	).toEqual([]);
	db.close();
	const store = new BetterSqliteCoordinatorStore(path);
	try {
		await expect(store.assertAuthSchemaReady()).resolves.toBeUndefined();
	} finally {
		await store.close();
	}
});

it("does not repair partial auth on open and keeps ordinary group operations available", async () => {
	const path = join(directory, "partial.sqlite");
	const db = new Database(path);
	db.exec(AUTH_LINK_SCHEMA_SQL);
	const before = db
		.prepare(
			"SELECT name,sql FROM sqlite_master WHERE name LIKE 'coordinator_auth_%' ORDER BY name",
		)
		.all();
	db.close();
	const store = new BetterSqliteCoordinatorStore(path);
	try {
		await expect(store.assertAuthSchemaReady()).rejects.toBeInstanceOf(
			CoordinatorAuthSchemaUpgradeRequiredError,
		);
		for (const table of before)
			expect(
				store.db
					.prepare("SELECT name,sql FROM sqlite_master WHERE name = ?")
					.get((table as { name: string }).name),
			).toEqual(table);
		expect(
			store.db
				.prepare(
					"SELECT name,sql FROM sqlite_master WHERE name LIKE 'coordinator_auth_%' ORDER BY name",
				)
				.all(),
		).toEqual(before);
		await store.createGroup("partial-auth-device-sync");
		expect((await store.listGroups()).map(({ group_id }) => group_id)).toEqual([
			"partial-auth-device-sync",
		]);
	} finally {
		await store.close();
	}
});

it("does not create a database when an operator selects a missing file", () => {
	expect(() => upgradeCoordinatorAuthSchemaFile(join(directory, "missing.sqlite"))).toThrow(
		/does not exist|unable to open/i,
	);
});

afterAll(() => rmSync(directory, { recursive: true, force: true }));

it.each([
	"CREATE UNIQUE INDEX custom_claim_group ON coordinator_auth_device_claims(group_id)",
	"CREATE TRIGGER custom_claim_insert BEFORE INSERT ON coordinator_auth_device_claims BEGIN SELECT RAISE(IGNORE); END;",
])("rejects extra proof objects without repairing them: %s", async (damage) => {
	// Arrange: the complete reviewed proof schema passes before adding a custom object.
	const store = new BetterSqliteCoordinatorStore(":memory:");
	try {
		await expect(store.assertAuthSchemaReady()).resolves.toBeUndefined();
		store.db.exec(damage);
		const schema = store.db.prepare("SELECT * FROM sqlite_master ORDER BY name").all();
		// Act / Assert: the extra object invalidates readiness and remains untouched.
		await expect(store.assertAuthSchemaReady()).rejects.toBeInstanceOf(
			CoordinatorAuthSchemaUpgradeRequiredError,
		);
		expect(store.db.prepare("SELECT * FROM sqlite_master ORDER BY name").all()).toEqual(schema);
	} finally {
		await store.close();
	}
});

it.each([
	"CREATE TABLE coordinator_auth_device_claims (claim_id TEXT)",
	proof[0].replace("UNIQUE (coordinator_id, identity_id),", ""),
	proof[0].replace("'text'", "'te xt'"),
	...proof.slice(1).map((sql) => sql.replace(/SELECT RAISE\([^;]+;/u, "SELECT 1;")),
])("rejects incomplete proof definitions after reopening (case %#)", async (damage) => {
	const path = join(mkdtempSync(join(directory, "damaged-")), "coordinator.sqlite");
	const isTable = damage.trimStart().startsWith("CREATE TABLE");
	const original = new BetterSqliteCoordinatorStore(path);
	original.db.exec("DROP TABLE coordinator_auth_device_claims");
	if (isTable) original.db.exec(damage);
	else original.db.exec(proof[0]);
	for (const sql of proof.slice(1)) original.db.exec(sql);
	if (!isTable) {
		const name = /CREATE TRIGGER IF NOT EXISTS (\w+)/u.exec(damage)?.[1];
		original.db.exec(`DROP TRIGGER ${name}`);
		original.db.exec(damage);
	}
	const before = original.db.prepare("SELECT * FROM sqlite_master ORDER BY name").all();
	await original.close();
	const reopened = new BetterSqliteCoordinatorStore(path);
	try {
		await expect(reopened.assertAuthSchemaReady()).rejects.toBeInstanceOf(
			CoordinatorAuthSchemaUpgradeRequiredError,
		);
		expect(reopened.db.prepare("SELECT * FROM sqlite_master ORDER BY name").all()).toEqual(before);
	} finally {
		await reopened.close();
	}
});
