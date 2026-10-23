import type { AutomaticContext, MemoryFilters } from "../types.js";
import type { SemanticSearchResult } from "../vectors.js";

export interface PackSemanticExecutor {
	search(input: {
		query: string;
		limit: number;
		filters: MemoryFilters | null;
		automaticContext: AutomaticContext | null | undefined;
	}): Promise<SemanticSearchResult[]>;
	close(): Promise<void>;
}

const identityErrorBrand = Symbol.for("codemem.experimental.semantic-identity-changed");

export class SemanticIdentityChangedError extends Error {
	readonly [identityErrorBrand] = true;

	constructor() {
		super("semantic_worker_identity_changed");
	}
}

/** The isolated experiment build and source pack can load separate copies of this class. */
export function isSemanticIdentityChangedError(error: unknown): boolean {
	return typeof error === "object" && error !== null && identityErrorBrand in error;
}

const executors = new WeakMap<object, PackSemanticExecutor>();

/** Explicit fixture/experiment injection only: no runtime flag or package export. */
export function attachExperimentalSemanticExecutor(
	store: object,
	executor: PackSemanticExecutor,
): void {
	if (executors.has(store)) throw new Error("semantic_executor_already_attached");
	executors.set(store, executor);
}

export function getExperimentalSemanticExecutor(store: object): PackSemanticExecutor | undefined {
	return executors.get(store);
}
