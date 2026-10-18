import type { Database } from "better-sqlite3";
import {
	AUTH_LIFECYCLE_CURRENT_READINESS_SQL,
	AUTH_LIFECYCLE_CURRENT_READY_COUNT,
} from "./coordinator-auth-lifecycle-current-readiness.js";
import {
	AUTH_LIFECYCLE_CURRENT_DEFINITIONS,
	AUTH_LIFECYCLE_FRESH_SCHEMA_SQL,
} from "./coordinator-auth-lifecycle-fresh-schema.js";

/** Test-only bridge until the root Worker snapshot moves to current auth DDL.
 * Never upgrades populated history or changes production store-open behavior.
 */
export function installEmptyCurrentAuthFixture(db: Database): void {
	if (
		(db.prepare(AUTH_LIFECYCLE_CURRENT_READINESS_SQL).get() as { ready: number }).ready ===
		AUTH_LIFECYCLE_CURRENT_READY_COUNT
	)
		return;
	const names = AUTH_LIFECYCLE_CURRENT_DEFINITIONS.filter(({ type }) => type === "table").map(
		({ name }) => name,
	);
	const present = names.filter((name) =>
		db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name),
	);
	for (const name of present) {
		if ((db.prepare(`SELECT count(*) AS n FROM ${name}`).get() as { n: number }).n !== 0)
			throw new Error("Populated auth fixture requires an explicit historical upgrade");
	}
	db.transaction(() => {
		for (const name of present) db.exec(`DROP TABLE ${name}`);
		db.exec(AUTH_LIFECYCLE_FRESH_SCHEMA_SQL);
	}).immediate();
}
