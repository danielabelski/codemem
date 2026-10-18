import { expect, vi } from "vitest";
import type { CoordinatorAuthBrowserTransactionStartInput } from "./coordinator-auth-browser-transaction-contract.js";
import {
	materials,
	transactionRows,
} from "./coordinator-auth-browser-transaction-test-fixtures.js";
import {
	attempt,
	authorize,
	backendTest,
	type LinkFixture,
	NOW,
	startBrowserProof,
} from "./coordinator-auth-link-test-fixtures.js";

async function assertPurposeIsolation(f: LinkFixture) {
	// Arrange: a real committed link claim is not permission to use owner material.
	await authorize(f);
	const creation = attempt({ attemptId: "owner-attempt-a" });
	expect((await f.store.createAuthLinkAttempt(creation, f.cfg)).kind).toBe("created");
	const material = await startBrowserProof(f, {
		attemptId: creation.attemptId,
		browserTransactionHash: "9".repeat(64),
		browserStartHash: creation.browserStartHash,
	});
	f.db.prepare("UPDATE coordinator_auth_browser_transactions SET purpose='owner_enroll'").run();
	const before = transactionRows(f);
	const links = f.db.prepare("SELECT * FROM coordinator_auth_link_attempts").all();
	// Act
	const start = await f.store.startAuthBrowserTransaction(
		{
			...material,
			purpose: "owner_enroll",
		} as unknown as CoordinatorAuthBrowserTransactionStartInput,
		f.cfg,
	);
	const consume = await f.store.consumeAuthBrowserTransaction(material, f.cfg);
	const resolve = await f.store.resolveAuthLinkBrowserTransaction(
		{ attemptId: creation.attemptId, binderHash: material.binderHash },
		f.cfg,
	);
	// Assert: neither a matching link nor a valid binder changes the reserved purpose.
	expect(start).toEqual({ kind: "rejected", error: "invalid_input" });
	expect(consume).toEqual({ kind: "rejected", error: "transaction_unavailable" });
	expect(resolve).toBeNull();
	expect(transactionRows(f)).toEqual(before);
	expect(f.db.prepare("SELECT * FROM coordinator_auth_link_attempts").all()).toEqual(links);
}

async function assertRetirementControls(f: LinkFixture) {
	// Arrange: ordinary signin is a positive control beside reserved owner material.
	const before = transactionRows(f);
	expect((await f.store.startAuthBrowserTransaction(materials(2), f.cfg)).kind).toBe("started");
	// Act
	const targeted = await f.store.retireAuthBrowserTransactions(
		{ ...f.cfg, enabled: false },
		{ attemptId: "owner-attempt-a" },
	);
	const global = await f.store.retireAuthBrowserTransactions({ ...f.cfg, enabled: false });
	// Assert
	expect(targeted).toMatchObject({ kind: "retired", processedCount: 0 });
	expect(global).toMatchObject({ kind: "retired", processedCount: 1 });
	expect(transactionRows(f).filter((row) => row.purpose === "owner_enroll")).toEqual(before);
	expect(transactionRows(f).filter((row) => row.purpose === "signin")).toEqual([
		expect.objectContaining({ state: "expired", nonce: null, pkce_verifier: null }),
	]);
}

async function assertGlobalExpiry(f: LinkFixture) {
	// Arrange: one expired owner row beside the unchanged live owner control.
	const live = transactionRows(f).filter((row) => row.purpose === "owner_enroll");
	f.db
		.prepare(`INSERT INTO coordinator_auth_browser_transactions
	 (coordinator_id,browser_transaction_hash,purpose,attempt_id,state_hash,binder_hash,issuer,auth_config_revision,redirect_uri,state,nonce,pkce_verifier,created_at_ms,expires_at_ms)
	 SELECT coordinator_id,?,'owner_enroll','expired-owner-attempt',?,?,issuer,auth_config_revision,redirect_uri,'pending',nonce,pkce_verifier,?,?
	 FROM coordinator_auth_browser_transactions WHERE attempt_id='owner-attempt-a'`)
		.run("a".repeat(64), "b".repeat(64), "c".repeat(64), NOW - 600000, NOW);
	const expired = transactionRows(f).filter((row) => row.attempt_id === "expired-owner-attempt");
	// Act
	const result = await f.store.maintainAuthBrowserTransactions(f.cfg, { limit: 1 });
	// Assert
	expect(result).toEqual({ kind: "maintained", processedCount: 1, more: true });
	expect(transactionRows(f).filter((row) => row.attempt_id === "expired-owner-attempt")).toEqual(
		expired.map((row) => ({ ...row, state: "expired", nonce: null, pkce_verifier: null })),
	);
	expect(transactionRows(f).filter((row) => row.attempt_id === "owner-attempt-a")).toEqual(live);
	for (const table of [
		"coordinator_auth_sessions",
		"coordinator_auth_account_links",
		"coordinator_device_ownership_bindings",
	])
		expect(f.db.prepare(`SELECT * FROM ${table}`).all()).toEqual([]);
}

for (const backend of ["SQLite", "D1"] as const) {
	const test = backendTest(backend);
	test(`${backend} legacy browser handlers reject reserved owner rows without burning material`, async ({
		fixture: f,
	}) => {
		const fetch = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network forbidden"));
		try {
			await assertPurposeIsolation(f);
			await assertRetirementControls(f);
			await assertGlobalExpiry(f);
			expect(fetch).not.toHaveBeenCalled();
		} finally {
			fetch.mockRestore();
		}
	});
}
