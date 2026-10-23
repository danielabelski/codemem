import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";
import type { FixtureVector, RankingRequest } from "./semantic-ranking.js";
import {
	createFixture,
	MODEL,
	type RankingFixture,
	vector,
} from "./semantic-ranking.test-helper.js";

export function createDisposableIndexFixture(): { fixture: RankingFixture; dispose(): void } {
	const directory = mkdtempSync(join(tmpdir(), "validated-vector-index-"));
	vi.stubEnv("HOME", directory);
	const fixture = createFixture(directory);
	return {
		fixture,
		dispose() {
			vi.restoreAllMocks();
			fixture.db.close();
			vi.unstubAllEnvs();
			rmSync(directory, { recursive: true, force: true });
		},
	};
}

export function row(memoryId: number, value = 1, chunkIndex = 0): FixtureVector {
	return {
		memoryId,
		chunkIndex,
		contentHash: `hash-${memoryId}-${chunkIndex}`,
		vector: vector(value),
	};
}

export function request(fixture: RankingFixture): Omit<RankingRequest, "token"> {
	return {
		query: { model: MODEL, vectors: [vector()] },
		limit: 2,
		filters: null,
		context: fixture.context,
	};
}
