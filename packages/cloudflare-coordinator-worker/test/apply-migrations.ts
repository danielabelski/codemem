import { env } from "cloudflare:workers";
import { applyD1Migrations } from "cloudflare:test";
import { AUTH_LINK_AUTHORITY_UPGRADE_SQL } from "../../core/src/coordinator-auth-link-authority-upgrade.js";
import { AUTH_LIFECYCLE_CURRENT_DEFINITIONS, AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS } from "../../core/src/coordinator-auth-lifecycle-fresh-schema.js";

await applyD1Migrations(env.COORDINATOR_DB, env.TEST_MIGRATIONS);
// Isolated test DB only: exercise the planned cutover without publishing an
// auto-discovered migration that would be incompatible with deployed writers.
await env.COORDINATOR_DB.batch(
	AUTH_LINK_AUTHORITY_UPGRADE_SQL.split(";").map((sql) => sql.trim()).filter(Boolean).map((sql) => env.COORDINATOR_DB.prepare(sql)),
);

// Explicit fresh-only native fixture construction; never reinterpret populated history.
const authTables = AUTH_LIFECYCLE_CURRENT_DEFINITIONS.filter(({ type }) => type === "table");
const present: string[] = [];
for (const { name } of authTables) {
	if (!(await env.COORDINATOR_DB.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").bind(name).first())) continue;
	if ((await env.COORDINATOR_DB.prepare(`SELECT count(*) AS n FROM ${name}`).first<{ n: number }>())?.n !== 0)
		throw new Error("Populated native auth fixture requires an explicit historical upgrade");
	present.push(name);
}
await env.COORDINATOR_DB.batch([
	...present.map((name) => env.COORDINATOR_DB.prepare(`DROP TABLE ${name}`)),
	...AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS.map((sql) => env.COORDINATOR_DB.prepare(sql)),
]);
