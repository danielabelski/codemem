import type { Database } from "../db.js";
import { type FixtureVector, vectorBytes } from "./semantic-ranking.js";
import {
	changeCounts,
	finishMutation,
	type IndexedRow,
	readState,
	requireGenerationModel,
	requireWriter,
	type VectorCatalog,
} from "./validated-vector-index-state.js";

export interface ValidatedBatch {
	writerVersion: 1;
	expectedModel: string;
	model: string;
	expectedCount: number;
	mode: "append" | "replace-memory-model";
	rows: readonly FixtureVector[];
}

export function requireModel(model: string): void {
	if (typeof model !== "string" || !model.trim()) throw new TypeError("vector_model_required");
}

export function requireVectorMetadata(row: Omit<FixtureVector, "vector">): void {
	if (
		!Number.isSafeInteger(row.memoryId) ||
		row.memoryId <= 0 ||
		!Number.isSafeInteger(row.chunkIndex) ||
		row.chunkIndex < 0 ||
		typeof row.contentHash !== "string" ||
		!row.contentHash.trim()
	) {
		throw new TypeError("invalid_vector_metadata");
	}
}

export function removeRow(db: Database, row: IndexedRow): void {
	db.prepare("DELETE FROM memory_vectors WHERE rowid=?").run(BigInt(row.rowid));
	db.prepare("DELETE FROM validated_vector_rows WHERE rowid=?").run(row.rowid);
	changeCounts(db, row.memory_id, row.model, -1);
	db.prepare(`UPDATE validated_vector_state SET pending_count=pending_count-?,
		invalid_count=invalid_count-? WHERE id=1`).run(
		Number(row.audit_state === "pending"),
		Number(row.audit_state === "invalid"),
	);
}

export function insertRow(
	db: Database,
	row: Omit<FixtureVector, "vector">,
	model: string,
	bytes: Buffer,
): void {
	const result = db
		.prepare(`INSERT INTO memory_vectors
		(embedding,memory_id,chunk_index,content_hash,model) VALUES(?,?,?,?,?)`)
		.run(bytes, BigInt(row.memoryId), BigInt(row.chunkIndex), row.contentHash, model);
	const rowid = Number(result.lastInsertRowid);
	if (!Number.isSafeInteger(rowid)) throw new RangeError("unsafe_vector_rowid");
	db.prepare(`INSERT INTO validated_vector_rows
		(rowid,memory_id,model,chunk_index,content_hash,audit_state) VALUES(?,?,?,?,?,'valid')`).run(
		rowid,
		row.memoryId,
		model,
		row.chunkIndex,
		row.contentHash,
	);
	changeCounts(db, row.memoryId, model, 1);
}

function removeMemoryModel(db: Database, memoryId: number, model: string | null): void {
	const rows = db
		.prepare("SELECT * FROM validated_vector_rows WHERE model IS ? AND memory_id=?")
		.all(model, memoryId) as IndexedRow[];
	for (const row of rows) removeRow(db, row);
}

export function writeValidatedBatch(db: Database, batch: ValidatedBatch): VectorCatalog {
	requireWriter(batch.writerVersion);
	requireModel(batch.model);
	if (batch.expectedModel !== batch.model) throw new TypeError("vector_model_mismatch");
	if (!Number.isSafeInteger(batch.expectedCount) || batch.expectedCount !== batch.rows.length) {
		throw new TypeError("vector_count_mismatch");
	}
	if (batch.mode !== "append" && batch.mode !== "replace-memory-model") {
		throw new TypeError("invalid_vector_write_mode");
	}
	const prepared = batch.rows.map((row) => {
		requireVectorMetadata(row);
		return { ...row, bytes: vectorBytes(row.vector) };
	});
	return db.transaction(() => {
		const state = readState(db);
		requireGenerationModel(state, batch.model);
		if (batch.mode === "replace-memory-model" && !state.audit_started) {
			throw new Error("start_audit_census_required");
		}
		const ids = new Set(prepared.map((row) => row.memoryId));
		for (const id of ids) {
			if (!db.prepare("SELECT 1 FROM memory_items WHERE id=?").get(id)) {
				throw new Error("vector_source_memory_missing");
			}
			if (batch.mode === "replace-memory-model") removeMemoryModel(db, id, batch.model);
		}
		for (const row of prepared) insertRow(db, row, batch.model, row.bytes);
		return finishMutation(db);
	})();
}

export function deleteValidatedVectors(
	db: Database,
	options: { writerVersion: 1; memoryId: number; model: string | null },
): VectorCatalog {
	requireWriter(options.writerVersion);
	if (!Number.isSafeInteger(options.memoryId) || options.memoryId < 1)
		throw new TypeError("invalid_memory_id");
	if (options.model !== null) requireModel(options.model);
	return db.transaction(() => {
		if (!readState(db).audit_started) throw new Error("start_audit_census_required");
		removeMemoryModel(db, options.memoryId, options.model);
		return finishMutation(db);
	})();
}
