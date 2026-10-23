import type { Database } from "../db.js";
import { vectorBytes } from "./semantic-ranking.js";
import {
	insertRow,
	removeRow,
	requireModel,
	requireVectorMetadata,
} from "./validated-vector-index-mutations.js";
import {
	type AuditProgress,
	finishMutation,
	type IndexedRow,
	progress,
	type RepairInput,
	readState,
	requireGenerationModel,
	requireLimit,
	snapshot,
	updateAuditState,
} from "./validated-vector-index-state.js";

interface MemoryText {
	title: string | null;
	body_text: string | null;
	rev: number;
}
type PruneReason = "source_missing" | "metadata_unusable" | "target_chunk_exists";
interface PrunePlan {
	kind: "prune";
	row: IndexedRow;
	reason: PruneReason;
}
interface RepairPlan {
	kind: "repair";
	row: IndexedRow;
	memory: MemoryText;
	version: number;
	targetVersion: number;
	input: RepairInput;
	outputIndex: number;
}
type WorkPlan = PrunePlan | RepairPlan;
interface CapturedWork {
	generationId: string;
	plans: WorkPlan[];
	inputs: RepairInput[];
}

function memoryText(db: Database, memoryId: number): MemoryText | undefined {
	return db.prepare("SELECT title,body_text,rev FROM memory_items WHERE id=?").get(memoryId) as
		| MemoryText
		| undefined;
}

function memoryVersion(db: Database, memoryId: number, model: string | null): number {
	const value = db
		.prepare(`SELECT version FROM validated_vector_versions
		WHERE memory_id=? AND model_null=? AND model_key=?`)
		.get(memoryId, Number(model === null), model ?? "") as { version: number } | undefined;
	return value?.version ?? 0;
}

function usableMetadata(row: IndexedRow): boolean {
	try {
		requireVectorMetadata({
			memoryId: row.memory_id,
			chunkIndex: row.chunk_index,
			contentHash: row.content_hash,
		});
		return true;
	} catch {
		return false;
	}
}

function hasTargetChunk(db: Database, row: IndexedRow, model: string): boolean {
	// Prefer a validated target, otherwise keep one deterministic incumbent.
	// The incumbent may repair itself; competing invalid rows cannot prune each other away.
	const target = db
		.prepare(`SELECT rowid FROM validated_vector_rows
		WHERE model=? AND memory_id=? AND chunk_index=?
		AND chunk_index>=0 AND trim(content_hash)<>''
		ORDER BY CASE WHEN audit_state='valid' THEN 0 ELSE 1 END,rowid LIMIT 1`)
		.get(model, row.memory_id, row.chunk_index) as { rowid: number } | undefined;
	return target !== undefined && target.rowid !== row.rowid;
}

function pruneReason(db: Database, row: IndexedRow, targetModel: string): PruneReason | null {
	if (!usableMetadata(row)) return "metadata_unusable";
	if (!memoryText(db, row.memory_id)) return "source_missing";
	if (hasTargetChunk(db, row, targetModel)) return "target_chunk_exists";
	return null;
}

function captureRepair(
	db: Database,
	row: IndexedRow,
	targetModel: string,
	outputIndex: number,
): RepairPlan {
	const memory = memoryText(db, row.memory_id);
	if (!memory) throw new Error("repair_source_missing");
	return {
		kind: "repair",
		row,
		memory,
		outputIndex,
		version: memoryVersion(db, row.memory_id, row.model),
		targetVersion: memoryVersion(db, row.memory_id, targetModel),
		input: {
			rowid: row.rowid,
			memoryId: row.memory_id,
			chunkIndex: row.chunk_index,
			previousModel: row.model,
			contentHash: row.content_hash,
			title: memory.title ?? "",
			bodyText: memory.body_text ?? "",
		},
	};
}

function captureRepairs(db: Database, limit: number, targetModel: string): CapturedWork {
	return snapshot(db, () => {
		const state = readState(db);
		if (!state.audit_started) throw new Error("start_audit_required");
		requireGenerationModel(state, targetModel);
		const rows = db
			.prepare(`SELECT * FROM validated_vector_rows
			WHERE audit_state='invalid' ORDER BY rowid LIMIT ?`)
			.all(limit) as IndexedRow[];
		const plans: WorkPlan[] = [];
		const inputs: RepairInput[] = [];
		for (const row of rows) {
			const reason = pruneReason(db, row, targetModel);
			if (reason) {
				plans.push({ kind: "prune", row, reason });
				continue;
			}
			const plan = captureRepair(db, row, targetModel, inputs.length);
			inputs.push(plan.input);
			plans.push(plan);
		}
		return { generationId: state.generation_id, plans, inputs };
	});
}

function sameRow(current: IndexedRow | undefined, saved: IndexedRow): boolean {
	return (
		current !== undefined &&
		current.rowid === saved.rowid &&
		current.memory_id === saved.memory_id &&
		current.model === saved.model &&
		current.chunk_index === saved.chunk_index &&
		current.content_hash === saved.content_hash
	);
}

function currentInvalidRow(db: Database, saved: IndexedRow): IndexedRow | undefined {
	const current = db
		.prepare("SELECT * FROM validated_vector_rows WHERE rowid=?")
		.get(saved.rowid) as IndexedRow | undefined;
	if (
		!sameRow(current, saved) ||
		current?.audit_state !== "invalid" ||
		current.reason !== saved.reason
	)
		return;
	const physical = db
		.prepare(`SELECT rowid,memory_id,model,chunk_index,content_hash
		FROM memory_vectors WHERE rowid=?`)
		.get(BigInt(saved.rowid)) as IndexedRow | undefined;
	if (sameRow(physical, saved)) return current;
}

function canRepair(db: Database, saved: RepairPlan, targetModel: string): boolean {
	const memory = memoryText(db, saved.row.memory_id);
	if (
		!memory ||
		memory.title !== saved.memory.title ||
		memory.body_text !== saved.memory.body_text ||
		memory.rev !== saved.memory.rev
	)
		return false;
	return (
		memoryVersion(db, saved.row.memory_id, saved.row.model) === saved.version &&
		memoryVersion(db, saved.row.memory_id, targetModel) === saved.targetVersion
	);
}

function pruneRow(
	db: Database,
	row: IndexedRow,
	reason: PruneReason,
): AuditProgress["diagnostics"][number] {
	removeRow(db, row);
	return { rowid: row.rowid, memoryId: row.memory_id, model: row.model, reason, action: "pruned" };
}

function applyPlan(
	db: Database,
	options: {
		plan: WorkPlan;
		model: string;
		vectors: Buffer[];
		eligible: boolean;
		diagnostics: AuditProgress["diagnostics"];
	},
): { checked: number; changed: boolean } {
	const { plan } = options;
	const current = currentInvalidRow(db, plan.row);
	if (!current) return { checked: 0, changed: false };
	if (plan.kind === "prune") {
		if (pruneReason(db, current, options.model) === plan.reason) {
			options.diagnostics.push(pruneRow(db, current, plan.reason));
			return { checked: 1, changed: true };
		}
		updateAuditState(db, current, "pending");
		return { checked: 0, changed: true };
	}
	// Recheck after earlier insertions in this same batch, not just at capture time.
	if (hasTargetChunk(db, current, options.model)) {
		options.diagnostics.push(pruneRow(db, current, "target_chunk_exists"));
		return { checked: 1, changed: true };
	}
	if (!options.eligible) {
		updateAuditState(db, current, "pending");
		return { checked: 0, changed: true };
	}
	removeRow(db, current);
	insertRow(
		db,
		{
			memoryId: current.memory_id,
			chunkIndex: current.chunk_index,
			contentHash: current.content_hash,
		},
		options.model,
		options.vectors[plan.outputIndex] as Buffer,
	);
	return { checked: 1, changed: true };
}

function applyRepairs(
	db: Database,
	work: CapturedWork,
	model: string,
	vectors: Buffer[],
): AuditProgress {
	return db.transaction(() => {
		if (readState(db).generation_id !== work.generationId) return progress(db);
		// Compare versions before our own writes; unrelated memories do not invalidate this work.
		const eligible = work.plans.map((plan) => plan.kind === "repair" && canRepair(db, plan, model));
		const diagnostics: AuditProgress["diagnostics"] = [];
		let checked = 0;
		let changed = false;
		for (const [index, plan] of work.plans.entries()) {
			const result = applyPlan(db, {
				plan,
				model,
				vectors,
				eligible: eligible[index] ?? false,
				diagnostics,
			});
			checked += result.checked;
			changed ||= result.changed;
		}
		if (changed) finishMutation(db);
		return progress(db, checked, diagnostics);
	})();
}

/** Capture is read-only. Validate the whole callback reply before committing any prune or repair. */
export async function repairBatch(
	db: Database,
	options: {
		limit: number;
		targetModel: string;
		repair: (
			rows: readonly RepairInput[],
		) => Promise<{ model: string; vectors: readonly Float32Array[] }>;
	},
): Promise<AuditProgress> {
	if (db.inTransaction) throw new Error("repair_requires_own_transactions");
	requireLimit(options.limit);
	requireModel(options.targetModel);
	const work = captureRepairs(db, options.limit, options.targetModel);
	if (!work.plans.length) return snapshot(db, () => progress(db));
	let vectors: Buffer[] = [];
	if (work.inputs.length) {
		const result = await options.repair(work.inputs);
		if (result.model !== options.targetModel) throw new TypeError("vector_model_mismatch");
		if (result.vectors.length !== work.inputs.length) throw new TypeError("vector_count_mismatch");
		vectors = result.vectors.map((vector) => vectorBytes(vector));
	}
	return applyRepairs(db, work, options.targetModel, vectors);
}
