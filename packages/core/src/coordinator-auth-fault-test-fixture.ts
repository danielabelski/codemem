import type { Database } from "better-sqlite3";
import { vi } from "vitest";

/** Fail execution, not schema validation: current readiness must keep rejecting
 * extra triggers. Both SQLite and its D1 adapter execute run() inside the batch.
 */
export function failAuthStatementRun(db: Database, prefix: string): () => void {
	const prepare = db.prepare.bind(db);
	const spy = vi.spyOn(db, "prepare").mockImplementation((sql: string) => {
		const statement = prepare(sql);
		if (sql.startsWith(prefix)) {
			vi.spyOn(statement, "run").mockImplementation(() => {
				throw new Error("Synthetic auth statement failure");
			});
		}
		return statement;
	});
	return () => spy.mockRestore();
}

/** Model an ignored backend statement inside the batch without adding a trigger. */
export function skipAuthStatementRun(db: Database, prefix: string): () => void {
	const prepare = db.prepare.bind(db);
	const spy = vi.spyOn(db, "prepare").mockImplementation((sql: string) => {
		const statement = prepare(sql);
		if (sql.startsWith(prefix)) {
			vi.spyOn(statement, "run").mockReturnValue({ changes: 0, lastInsertRowid: 0 });
		}
		return statement;
	});
	return () => spy.mockRestore();
}
