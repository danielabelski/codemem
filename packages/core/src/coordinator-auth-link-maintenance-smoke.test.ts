import { describe, expect } from "vitest";
import {
	startBrowserProof,
	withBrowserHash,
} from "./coordinator-auth-browser-proof-test-fixtures.js";
import { materials } from "./coordinator-auth-browser-transaction-test-fixtures.js";
import { AUTH_LINK_MAX_ACTIVE_PER_DEVICE } from "./coordinator-auth-link-contract.js";
import {
	advance,
	attempt,
	authorize,
	backendTest,
	browserProofConfig,
	expectRejected,
	finalize,
	rows,
	TABLES,
	TTL,
} from "./coordinator-auth-link-test-fixtures.js";
import {
	freshBrowserHash,
	linked,
	sessionRows,
	signInInput,
} from "./coordinator-auth-session-test-fixtures.js";

// Trusted persistence metadata only; D1 parity uses the SQLite-backed fixture.
for (const backend of ["SQLite", "D1"] as const) {
	const test = backendTest(backend);
	describe(`${backend} auth-link maintenance smoke`, () => {
		test("parallel admission caps new attempts and preserves the winner's TTL on retry", async ({
			fixture: f,
		}) => {
			// Arrange: distinct commitments from the same attested device.
			await authorize(f);
			const inputs = Array.from({ length: AUTH_LINK_MAX_ACTIVE_PER_DEVICE + 1 }, (_, n) =>
				attempt({ attemptId: `smoke-${n}`, runtimeVerifierHash: String(n + 1).repeat(64) }),
			);
			// Act: choose an admitted result rather than depending on execution order.
			const results = await Promise.all(
				inputs.map((input) => f.store.createAuthLinkAttempt(input, f.cfg)),
			);
			const index = results.findIndex((result) => result.kind === "created");
			const winner = results[index];
			const input = inputs[index];
			if (!winner || !input) throw new Error("expected an admitted attempt");
			const before = rows(f, TABLES[0]);
			f.now++;
			const retry = await f.store.createAuthLinkAttempt(input, f.cfg);
			// Assert: rejection and retry neither add rows nor extend the expiry.
			expect(results.filter((result) => result.kind === "created")).toHaveLength(
				AUTH_LINK_MAX_ACTIVE_PER_DEVICE,
			);
			expect(results.filter((result) => result.kind === "rejected")).toEqual([
				{ kind: "rejected", error: "attempt_limited" },
			]);
			expect(retry).toEqual({ ...winner, kind: "existing" });
			expect(before).toHaveLength(AUTH_LINK_MAX_ACTIVE_PER_DEVICE);
			expect(rows(f, TABLES[0])).toEqual(before);
		});

		test("expiry scrubs an unlinked subject but retains commitments and denies completion", async ({
			fixture: f,
		}) => {
			// Arrange: verified metadata has not created a link or session.
			await authorize(f);
			await advance(f, "oidc_verified");
			const before = rows(f, TABLES[0])[0];
			expect(before).toMatchObject({ state: "oidc_verified", account_subject: "opaque-subject-a" });
			f.now += TTL;
			// Act
			const maintained = await f.store.maintainAuthLinkAttempts(f.cfg);
			const claim = await f.store.startAuthBrowserTransaction(
				{
					...materials(800),
					purpose: "link",
					attemptId: attempt().attemptId,
					browserStartHash: attempt().browserStartHash,
				},
				f.cfg,
			);
			const completion = await f.store.finalizeAuthLinkAttempt(finalize(), f.cfg);
			// Assert: the whole retained row changes only state and private subject.
			expect(maintained).toEqual({ kind: "maintained", processedCount: 1, more: false });
			expect(rows(f, TABLES[0])).toEqual([{ ...before, state: "expired", account_subject: null }]);
			expectRejected(claim, "attempt_expired");
			expectRejected(completion, "attempt_unavailable");
			expect(rows(f, TABLES[1])).toEqual([]);
			expect(rows(f, TABLES[2])).toEqual([]);
			expect(sessionRows(f)).toEqual([[], []]);
		});

		test("normal sign-in burns its browser proof without blocking a fresh link claim", async ({
			fixture: f,
		}) => {
			// Arrange: seed the link through the existing reviewed-device flow.
			await linked(f);
			const signedIn = await f.store.signInWithConsumedBrowserTransaction(
				signInInput(f),
				browserProofConfig(f),
			);
			const input = attempt({ attemptId: "smoke-new", runtimeVerifierHash: "1".repeat(64) });
			const created = await f.store.createAuthLinkAttempt(input, f.cfg);
			const before = rows(f, TABLES[0]);
			const sessions = sessionRows(f);
			const links = rows(f, TABLES[1]);
			// Act
			const replay = await withBrowserHash(freshBrowserHash, () =>
				f.store.startAuthBrowserTransaction(
					{
						...materials(801),
						purpose: "link",
						attemptId: input.attemptId,
						browserStartHash: input.browserStartHash,
					},
					f.cfg,
				),
			);
			const afterReplay = rows(f, TABLES[0]);
			const material = await startBrowserProof(f, {
				attemptId: input.attemptId,
				browserTransactionHash: "2".repeat(64),
				browserStartHash: input.browserStartHash,
			});
			const fresh = await f.store.consumeAuthBrowserTransaction(material, f.cfg);
			// Assert: replay consumes nothing, while an unused commitment succeeds.
			expect(signedIn.kind).toBe("issued");
			expect(created.kind).toBe("created");
			expectRejected(replay, "transaction_conflict");
			expect(afterReplay).toEqual(before);
			expect(fresh).toMatchObject({
				kind: "consumed",
				purpose: "link",
				attemptId: input.attemptId,
				browserTransactionHash: "2".repeat(64),
			});
			expect(sessionRows(f)).toEqual(sessions);
			expect(rows(f, TABLES[1])).toEqual(links);
		});
	});
}
