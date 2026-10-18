import { expect } from "vitest";
import { startBrowserProof } from "../../core/src/coordinator-auth-browser-proof-test-fixtures.js";
import type { CoordinatorAuthBrowserConfig } from "../../core/src/coordinator-auth-browser-transaction-contract.js";
import type { D1CoordinatorStore } from "../../core/src/d1-coordinator-store.js";

/** Consumed synthetic browser proof; never calls an identity provider. */
export async function consumeNativeLinkProof(f: {
	store: D1CoordinatorStore;
	cfg: CoordinatorAuthBrowserConfig;
}, start: { attemptId: string; browserStartHash: string }, browser: {
	attemptId: string; browserTransactionHash: string; binderHash: string;
}) {
	const materials = await startBrowserProof(f, { ...browser, browserStartHash: start.browserStartHash });
	expect(await f.store.consumeAuthBrowserTransaction(materials, f.cfg)).toMatchObject({ kind: "consumed", purpose: "link", browserTransactionHash: browser.browserTransactionHash });
	browser.binderHash = materials.binderHash;
	return materials;
}
