import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { FixtureVector } from "./semantic-ranking.js";
import { MODEL, type RankingFixture, vector } from "./semantic-ranking.test-helper.js";
import {
	auditBatch,
	deleteValidatedVectors,
	initializeValidatedIndex,
	rankValidatedIndex,
	readCandidateVersions,
	readCatalog,
	repairBatch,
	startAudit,
	writeValidatedBatch,
} from "./validated-vector-index.js";
import {
	createDisposableIndexFixture,
	request,
	row,
} from "./validated-vector-index.test-helper.js";

let owned: ReturnType<typeof createDisposableIndexFixture>;
let fixture: RankingFixture;
const writer = { writerVersion: 1 as const };
beforeEach(() => {
	owned = createDisposableIndexFixture();
	fixture = owned.fixture;
});
afterEach(() => owned.dispose());
function initialize() {
	return initializeValidatedIndex(fixture.db, { ...writer, allWritersUpgraded: true });
}
function write(rows: FixtureVector[], mode: "append" | "replace-memory-model" = "append") {
	return writeValidatedBatch(fixture.db, {
		...writer,
		expectedModel: MODEL,
		model: MODEL,
		expectedCount: rows.length,
		mode,
		rows,
	});
}
function audit() {
	startAudit(fixture.db, { knownModels: [MODEL] });
	return auditBatch(fixture.db, { limit: 100 });
}
function versions(memoryId: number) {
	return readCandidateVersions(fixture.db, { memoryIds: [memoryId], models: [MODEL] });
}
async function finishRepair(targetModel = MODEL) {
	let catalog = readCatalog(fixture.db);
	for (let attempt = 0; attempt < 4 && catalog?.status !== "ready"; attempt++) {
		auditBatch(fixture.db, { limit: 100 });
		catalog = (
			await repairBatch(fixture.db, {
				limit: 1,
				targetModel,
				repair: async (rows) => ({
					model: targetModel,
					vectors: rows.map(() => vector(1)),
				}),
			})
		).catalog;
	}
	return catalog;
}
it("repairs only derived vectors using retained text outside a transaction", async () => {
	// Arrange
	const id = fixture.memory();
	fixture.rawVector(id, vector(3));
	initialize();
	audit();
	const memories = fixture.snapshot().memories;
	let callbackRan = false;
	// Act
	const progress = await repairBatch(fixture.db, {
		limit: 1,
		targetModel: MODEL,
		repair: async (rows) => {
			callbackRan = true;
			expect(fixture.db.inTransaction).toBe(false);
			expect(rows).toMatchObject([
				{ memoryId: id, title: "Fixture", bodyText: "Body", previousModel: MODEL },
			]);
			await Promise.resolve();
			return { model: MODEL, vectors: rows.map(() => vector(1)) };
		},
	});
	// Assert
	expect(callbackRan).toBe(true);
	expect(progress).toMatchObject({ invalid: 0, remaining: 0 });
	expect(fixture.snapshot().memories).toEqual(memories);
	expect(audit().catalog.status).toBe("ready");
});
it.each(["content", "version"] as const)(
	"does not overwrite concurrent %s changes during repair",
	async (change) => {
		// Arrange
		const id = fixture.memory();
		fixture.rawVector(id, vector(3));
		initialize();
		audit();
		let concurrent: ReturnType<RankingFixture["snapshot"]> | undefined;
		// Act
		await repairBatch(fixture.db, {
			limit: 1,
			targetModel: MODEL,
			repair: async () => {
				if (change === "content")
					fixture.db
						.prepare("UPDATE memory_items SET body_text = ?, rev = rev + 1 WHERE id = ?")
						.run("Changed", id);
				else write([row(id, 2)], "replace-memory-model");
				concurrent = fixture.snapshot();
				return { model: MODEL, vectors: [vector(-1)] };
			},
		}).catch(() => undefined);
		// Assert: either an explicit conflict or a skipped repair is acceptable, never stale overwrite.
		expect(concurrent).toBeDefined();
		expect(fixture.snapshot()).toEqual(concurrent);
	},
);
it.each(["count", "model", "shape", "norm"] as const)(
	"rejects corrupt repair output atomically: %s",
	async (invalid) => {
		// Arrange
		fixture.rawVector(fixture.memory(), vector(3));
		fixture.rawVector(fixture.memory(), vector(3));
		initialize();
		audit();
		const before = fixture.snapshot();
		const catalog = readCatalog(fixture.db);
		const corruptVectors: Record<typeof invalid, Float32Array[]> = {
			count: [vector(1)],
			model: [vector(1), vector(3)],
			shape: [vector(1), new Float32Array(383)],
			norm: [vector(1), vector(3)],
		};
		// Act
		const repair = repairBatch(fixture.db, {
			limit: 2,
			targetModel: MODEL,
			repair: async () => ({
				model: invalid === "model" ? "wrong-model" : MODEL,
				vectors: corruptVectors[invalid],
			}),
		});
		// Assert
		await expect(repair).rejects.toThrow();
		expect(fixture.snapshot()).toEqual(before);
		expect(readCatalog(fixture.db)).toEqual(catalog);
		expect(fixture.db.inTransaction).toBe(false);
	},
);

it("keeps a concurrent supported model transition instead of applying stale repair output", async () => {
	// Arrange
	const id = fixture.memory();
	const nextModel = "next-fixture-model";
	fixture.rawVector(id, vector(3));
	initialize();
	startAudit(fixture.db, { knownModels: [MODEL, nextModel] });
	auditBatch(fixture.db, { limit: 100 });
	let afterTransition: ReturnType<RankingFixture["snapshot"]> | undefined;
	// Act
	await repairBatch(fixture.db, {
		limit: 1,
		targetModel: MODEL,
		repair: async () => {
			expect(fixture.db.inTransaction).toBe(false);
			deleteValidatedVectors(fixture.db, { ...writer, memoryId: id, model: MODEL });
			writeValidatedBatch(fixture.db, {
				...writer,
				expectedModel: nextModel,
				model: nextModel,
				expectedCount: 1,
				mode: "append",
				rows: [row(id, 2)],
			});
			afterTransition = fixture.snapshot();
			await Promise.resolve();
			return { model: MODEL, vectors: [vector(-1)] };
		},
	});
	// Assert: delete/reinsert may reuse rowid, but cannot reuse the old model version.
	expect(afterTransition).toBeDefined();
	expect(fixture.snapshot()).toEqual(afterTransition);
	expect(versions(id)[0]).toMatchObject({ memoryId: id, model: MODEL, count: 0 });
	expect(readCatalog(fixture.db)?.models).toEqual([{ model: nextModel, count: 1 }]);
	expect(rankValidatedIndex(fixture.db, request(fixture))).toBeNull();
});

it("review-orphan: a limit-one repair reaches later rows instead of stalling on an orphan", async () => {
	// Arrange: both invalid rows precede the initial census; no live/raw ready-index writes.
	const id = fixture.memory();
	fixture.rawVector(9999, vector(1));
	fixture.rawVector(id, vector(3));
	initialize();
	audit();
	const memories = fixture.snapshot().memories;
	const repaired: number[] = [];
	let catalog = readCatalog(fixture.db);
	// Act: four calls is sufficient for two invalid rows, without an unbounded retry loop.
	for (let attempt = 0; attempt < 4 && catalog?.status !== "ready"; attempt++) {
		catalog = (
			await repairBatch(fixture.db, {
				limit: 1,
				targetModel: MODEL,
				repair: async (rows) => {
					expect(rows.map((input) => input.memoryId)).toEqual([id]);
					repaired.push(...rows.map((input) => input.memoryId));
					return { model: MODEL, vectors: rows.map(() => vector(1)) };
				},
			})
		).catalog;
	}
	// Assert: only orphaned derived data may disappear; retained text must survive.
	expect(catalog?.status).toBe("ready");
	expect(repaired).toEqual([id]);
	expect(fixture.db.prepare("SELECT memory_id FROM memory_vectors").all()).toEqual([
		{ memory_id: id },
	]);
	expect(fixture.snapshot().memories).toEqual(memories);
});

it("generation-model: rejects an undeclared repair target before callback or pruning", async () => {
	// Arrange: this batch contains both an orphan prune and an inference candidate.
	const id = fixture.memory();
	fixture.rawVector(9999, vector(1));
	fixture.rawVector(id, vector(3));
	initialize();
	audit();
	const targetModel = "undeclared-fixture-model";
	const before = fixture.snapshot();
	const catalog = readCatalog(fixture.db);
	const options = { memoryIds: [9999, id], models: [MODEL, targetModel] };
	const candidates = readCandidateVersions(fixture.db, options);
	const repair = vi.fn(async (rows: readonly { memoryId: number }[]) => ({
		model: targetModel,
		vectors: rows.map(() => vector(1)),
	}));
	// Act
	const rejected = repairBatch(fixture.db, { limit: 2, targetModel, repair });
	// Assert: matching callback/model labels cannot add a model to the generation manifest.
	await expect(rejected).rejects.toThrow(/model/i);
	expect(repair).not.toHaveBeenCalled();
	expect(fixture.snapshot()).toEqual(before);
	expect(readCatalog(fixture.db)).toEqual(catalog);
	expect(readCandidateVersions(fixture.db, options)).toEqual(candidates);
	expect(fixture.db.inTransaction).toBe(false);
});

it.each(["empty hash", "negative chunk"] as const)(
	"review-unusable-metadata: finishes repair without inference for %s",
	async (invalid) => {
		// Arrange: valid source memory, unusable derived metadata from a legacy writer.
		const id = fixture.memory();
		const rowid = fixture.rawVector(id, vector(1), invalid === "negative chunk" ? -1 : 0);
		if (invalid === "empty hash")
			fixture.db.prepare("UPDATE memory_vectors SET content_hash='' WHERE rowid=?").run(rowid);
		initialize();
		audit();
		const memories = fixture.snapshot().memories;
		const repair = vi.fn(async (rows: readonly { memoryId: number }[]) => ({
			model: MODEL,
			vectors: rows.map(() => vector(1)),
		}));
		let catalog = readCatalog(fixture.db);
		// Act
		for (let attempt = 0; attempt < 4 && catalog?.status !== "ready"; attempt++) {
			catalog = (await repairBatch(fixture.db, { limit: 1, targetModel: MODEL, repair })).catalog;
		}
		// Assert: invalid metadata cannot be used to regenerate a meaningful chunk.
		expect(repair).not.toHaveBeenCalled();
		expect(catalog?.status).toBe("ready");
		expect(fixture.db.prepare("SELECT rowid FROM memory_vectors").all()).toEqual([]);
		expect(fixture.snapshot().memories).toEqual(memories);
	},
);

it.each(["count", "nonfinite", "model"] as const)(
	"review-prune-atomicity: corrupt %s output cannot commit an orphan prune",
	async (invalid) => {
		// Arrange: the prune candidate sorts before a normally repairable chunk.
		const id = fixture.memory();
		fixture.rawVector(9999, vector(1));
		fixture.rawVector(id, vector(3));
		initialize();
		audit();
		const before = fixture.snapshot();
		const catalog = readCatalog(fixture.db);
		const candidates = readCandidateVersions(fixture.db, {
			memoryIds: [9999, id],
			models: [MODEL],
		});
		// Act
		const failed = repairBatch(fixture.db, {
			limit: 2,
			targetModel: MODEL,
			repair: async (rows) => {
				expect(rows.map((input) => input.memoryId)).toEqual([id]);
				const corruptVectors: Record<typeof invalid, Float32Array[]> = {
					count: [],
					nonfinite: rows.map(() => vector(Number.NaN)),
					model: rows.map(() => vector(1)),
				};
				return {
					model: invalid === "model" ? "wrong-model" : MODEL,
					vectors: corruptVectors[invalid],
				};
			},
		});
		// Assert: no prune, repair, version bump, or revision is allowed on a failed reply.
		await expect(failed).rejects.toThrow();
		expect(fixture.snapshot()).toEqual(before);
		expect(readCatalog(fixture.db)).toEqual(catalog);
		expect(readCandidateVersions(fixture.db, { memoryIds: [9999, id], models: [MODEL] })).toEqual(
			candidates,
		);
		expect((await finishRepair())?.status).toBe("ready");
		expect(fixture.snapshot().memories).toEqual(before.memories);
	},
);

it("review-target-existing: preserves an already valid target chunk without redundant inference", async () => {
	// Arrange: two legacy model labels share one logical chunk, but only the old vector is invalid.
	const id = fixture.memory();
	const oldModel = "old-fixture-model";
	fixture.rawVector(id, vector(3), 0, oldModel);
	const targetRowid = fixture.rawVector(id, vector(2));
	initialize();
	startAudit(fixture.db, { knownModels: [MODEL, oldModel] });
	auditBatch(fixture.db, { limit: 100 });
	const memories = fixture.snapshot().memories;
	const target = fixture.db
		.prepare("SELECT rowid, * FROM memory_vectors WHERE rowid=?")
		.get(targetRowid);
	const candidates = versions(id);
	const repair = vi.fn(async (rows: readonly { memoryId: number }[]) => ({
		model: MODEL,
		vectors: rows.map(() => vector(-1)),
	}));
	// Act
	const progress = await repairBatch(fixture.db, { limit: 1, targetModel: MODEL, repair });
	// Assert: the valid target is the sole target-model chunk and retains its version.
	expect(repair).not.toHaveBeenCalled();
	expect(progress.catalog.status).toBe("ready");
	expect(
		fixture.db.prepare("SELECT rowid, * FROM memory_vectors WHERE model=?").all(MODEL),
	).toEqual([target]);
	expect(versions(id)).toEqual(candidates);
	expect(fixture.snapshot().memories).toEqual(memories);
});

it("review-unusable-incumbent: preserves a repairable old chunk when the target metadata is unusable", async () => {
	// Arrange: both legacy rows precede the census and refer to one retained source chunk.
	const id = fixture.memory();
	const oldModel = "old-fixture-model";
	fixture.rawVector(id, vector(3), 0, oldModel);
	const badTarget = fixture.rawVector(id, vector(1));
	fixture.db.prepare("UPDATE memory_vectors SET content_hash='' WHERE rowid=?").run(badTarget);
	initialize();
	startAudit(fixture.db, { knownModels: [oldModel, MODEL] });
	auditBatch(fixture.db, { limit: 100 });
	const memories = fixture.snapshot().memories;
	let inferenceCalls = 0;
	let catalog = readCatalog(fixture.db);
	// Act: an unusable incumbent must not suppress inference for the repairable old row.
	for (let attempt = 0; attempt < 4 && catalog?.status !== "ready"; attempt++) {
		auditBatch(fixture.db, { limit: 100 });
		catalog = (
			await repairBatch(fixture.db, {
				limit: 2,
				targetModel: MODEL,
				repair: async (rows) => {
					inferenceCalls++;
					expect(rows).toMatchObject([
						{ memoryId: id, chunkIndex: 0, previousModel: oldModel, contentHash: `hash-${id}-0` },
					]);
					return { model: MODEL, vectors: rows.map(() => vector(1)) };
				},
			})
		).catalog;
	}
	// Assert: pruning derived metadata cannot discard the only regenerable chunk.
	expect(inferenceCalls).toBeGreaterThanOrEqual(1);
	expect(catalog?.status).toBe("ready");
	expect(
		fixture.db
			.prepare(
				"SELECT memory_id, chunk_index, content_hash, model, vec_distance_l2(embedding, ?) AS distance FROM memory_vectors",
			)
			.all(Buffer.from(vector(1).buffer)),
	).toEqual([
		{ memory_id: id, chunk_index: 0, content_hash: `hash-${id}-0`, model: MODEL, distance: 0 },
	]);
	expect(fixture.snapshot().memories).toEqual(memories);
});

it.each(["append", "replace-memory-model"] as const)(
	"review-target-concurrent: preserves a newer target-model %s while repair awaits",
	async (mode) => {
		// Arrange: the captured invalid row belongs to the old model only.
		const id = fixture.memory();
		const targetModel = "next-fixture-model";
		fixture.rawVector(id, vector(3));
		initialize();
		startAudit(fixture.db, { knownModels: [MODEL, targetModel] });
		auditBatch(fixture.db, { limit: 100 });
		const memories = fixture.snapshot().memories;
		const oldVersions = versions(id);
		let targetRows: unknown[] | undefined;
		let targetVersions: ReturnType<typeof readCandidateVersions> | undefined;
		// Act: a supported target writer commits after capture, without touching the old version.
		await repairBatch(fixture.db, {
			limit: 1,
			targetModel,
			repair: async (rows) => {
				await Promise.resolve();
				writeValidatedBatch(fixture.db, {
					...writer,
					expectedModel: targetModel,
					model: targetModel,
					expectedCount: 1,
					mode,
					rows: [row(id, 2)],
				});
				expect(versions(id)).toEqual(oldVersions);
				targetRows = fixture.db
					.prepare("SELECT rowid, * FROM memory_vectors WHERE model=?")
					.all(targetModel);
				targetVersions = readCandidateVersions(fixture.db, {
					memoryIds: [id],
					models: [targetModel],
				});
				return { model: targetModel, vectors: rows.map(() => vector(-1)) };
			},
		});
		// Assert: no duplicate target chunk, stale overwrite, or target-version bump.
		expect(targetRows).toHaveLength(1);
		expect(
			fixture.db.prepare("SELECT rowid, * FROM memory_vectors WHERE model=?").all(targetModel),
		).toEqual(targetRows);
		expect(readCandidateVersions(fixture.db, { memoryIds: [id], models: [targetModel] })).toEqual(
			targetVersions,
		);
		expect((await finishRepair(targetModel))?.status).toBe("ready");
		expect(fixture.snapshot().memories).toEqual(memories);
	},
);
