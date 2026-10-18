import { env } from "cloudflare:workers";
import { AUTH_ONLY_PREDECESSOR_MIGRATION_NAMES } from "../../core/src/coordinator-auth-historical-migration-test-fixture.js";
import { AUTH_LINK_AUTHORITY_CUTOVER_STATEMENTS } from "../../core/src/coordinator-auth-link-authority-upgrade.js";

/** Explicit disposal/rebuild between isolated historical tests, not a runtime upgrade. */
export async function restoreFrozenAuthPredecessor() {
	const db = env.COORDINATOR_DB;
	const migrations = AUTH_ONLY_PREDECESSOR_MIGRATION_NAMES.map((name) => {
		const matches = env.TEST_MIGRATIONS.filter((migration) => migration.name === name);
		if (matches.length !== 1) throw new Error(`Expected exactly one historical fixture migration: ${name}`);
		return matches[0];
	});
	const definitions = (await db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL").all<{type: string; name: string; tbl_name: string; sql: string}>()).results;
	const order: Record<string, number> = { trigger: 0, view: 1, index: 2, table: 3 };
	const reset = definitions.filter(({ name, tbl_name, sql }) => tbl_name.startsWith("coordinator_auth_") || /coordinator_auth_/iu.test(sql) || name.startsWith("coordinator_lifecycle_") || name.startsWith("lifecycle_test_"));
	reset.sort((a, b) => (order[a.type] ?? 4) - (order[b.type] ?? 4) || Number(a.tbl_name.startsWith("coordinator_auth_")) - Number(b.tbl_name.startsWith("coordinator_auth_")));
	for (const { type, name } of reset) await db.prepare(`DROP ${type.toUpperCase()} IF EXISTS "${name.replaceAll('"', '""')}"`).run();
	for (const migration of migrations) await db.batch(migration.queries.map((sql) => db.prepare(sql)));
	await db.batch(AUTH_LINK_AUTHORITY_CUTOVER_STATEMENTS.map((sql) => db.prepare(sql)));
}
