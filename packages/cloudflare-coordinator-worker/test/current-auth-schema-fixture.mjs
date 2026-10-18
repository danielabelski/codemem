import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

// Match the native HTTP fixtures' existing esbuild source-loading boundary.
const require = createRequire(new URL("../package.json", import.meta.url));
const runtimeRequire = createRequire(require.resolve("wrangler/package.json"));
const { build } = runtimeRequire("esbuild");
const bundle = await build({
	stdin: {
		contents: `export { AUTH_LIFECYCLE_CURRENT_DEFINITIONS, AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS } from './coordinator-auth-lifecycle-fresh-schema.ts';
export { AUTH_LIFECYCLE_UPGRADE_STATEMENTS } from './coordinator-auth-lifecycle-upgrade.ts';
export { AUTH_LIFECYCLE_CURRENT_READINESS_SQL, AUTH_LIFECYCLE_CURRENT_READY_COUNT } from './coordinator-auth-lifecycle-current-readiness.ts';
export { AUTH_SCHEMA_V2_READINESS_SQL } from './coordinator-auth-lifecycle-predecessor.ts';`,
		resolveDir: fileURLToPath(new URL("../../core/src", import.meta.url)),
		sourcefile: "native-current-auth-schema.ts",
	},
	bundle: true, write: false, format: "esm", platform: "node", target: "node24",
});
export const { AUTH_LIFECYCLE_CURRENT_DEFINITIONS, AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS, AUTH_LIFECYCLE_UPGRADE_STATEMENTS, AUTH_LIFECYCLE_CURRENT_READINESS_SQL, AUTH_LIFECYCLE_CURRENT_READY_COUNT, AUTH_SCHEMA_V2_READINESS_SQL } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`);

/** Fresh-only local test binding; reject populated history before changing DDL. */
export async function installEmptyNativeCurrentAuth(db) {
	const tables = [];
	for (const { name } of AUTH_LIFECYCLE_CURRENT_DEFINITIONS.filter(({ type }) => type === "table")) {
		if (!(await db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").bind(name).first())) continue;
		assert.deepEqual(await db.prepare(`SELECT count(*) AS n FROM ${name}`).first(), { n: 0 });
		tables.push(name);
	}
	await db.batch([
		...tables.map(name => db.prepare(`DROP TABLE ${name}`)),
		...AUTH_LIFECYCLE_FRESH_SCHEMA_STATEMENTS.map(sql => db.prepare(sql)),
	]);
}

/** Explicit preserving operation used only by the historical HTTP fence test. */
export async function upgradeNativeCurrentAuth(db) {
	assert.equal(AUTH_LIFECYCLE_UPGRADE_STATEMENTS.length, 191);
	assert.deepEqual(await db.prepare(AUTH_SCHEMA_V2_READINESS_SQL).first(), { ready: 10 });
	await db.batch(AUTH_LIFECYCLE_UPGRADE_STATEMENTS.map(sql => db.prepare(sql)));
	assert.deepEqual(await db.prepare(AUTH_LIFECYCLE_CURRENT_READINESS_SQL).first(), { ready: AUTH_LIFECYCLE_CURRENT_READY_COUNT });
	assert.deepEqual(await db.prepare(AUTH_SCHEMA_V2_READINESS_SQL).first(), { ready: 9 });
}
