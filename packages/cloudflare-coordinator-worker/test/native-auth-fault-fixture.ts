import { env } from "cloudflare:workers";
import { vi } from "vitest";

/** Inject an execution failure after the selected native batch statement.
 * Leave the schema inventory intact so readiness still runs normally.
 */
export function failNativeAuthBatch(prefix: string) {
	const db = env.COORDINATOR_DB;
	const prepare = db.prepare.bind(db);
	const batch = db.batch.bind(db);
	const statements = new WeakMap<object, string>();
	const prepareSpy = vi.spyOn(db, "prepare").mockImplementation((sql) => {
		const statement = prepare(sql);
		const bind = statement.bind.bind(statement);
		statements.set(statement, sql);
		vi.spyOn(statement, "bind").mockImplementation((...values) => {
			const bound = bind(...values);
			statements.set(bound, sql);
			return bound;
		});
		return statement;
	});
	const batchSpy = vi.spyOn(db, "batch").mockImplementation((input) => {
		const index = input.findIndex((statement) => statements.get(statement)?.startsWith(prefix));
		if (index < 0) return batch(input);
		return batch([...input.slice(0, index + 1), prepare("SELECT json('synthetic execution failure')"), ...input.slice(index + 1)]);
	});
	return () => { batchSpy.mockRestore(); prepareSpy.mockRestore(); };
}
