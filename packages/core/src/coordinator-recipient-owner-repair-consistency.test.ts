import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { type Fixture, setupStore, sqliteD1 } from "./coordinator-auth-store-test-fixtures.js";
import { revocationInput } from "./coordinator-device-revocation-test-harness.js";
import {
	producerSnapshot,
	retainProducerOwner,
} from "./coordinator-producer-negative-owner-test-fixtures.js";
import { recipientInvite } from "./coordinator-recipient-revocation-test-harness.js";
import type { CoordinatorConsumeRecipientInviteInput } from "./coordinator-store-contract.js";
import { D1CoordinatorStore } from "./d1-coordinator-store.js";

beforeEach(() => {
	vi.useFakeTimers();
	vi.setSystemTime(new Date("2026-10-06T00:00:00.000Z"));
	vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network forbidden"));
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});

function conflictingController(f: Fixture, input: CoordinatorConsumeRecipientInviteInput) {
	f.db
		.prepare(`INSERT INTO coordinator_auth_controller_attestations
		(attestation_id,coordinator_id,identity_id,group_id,device_id,public_key,fingerprint,
		review_receipt_id,evidence_digest,enrollment_identity_id,revision,created_at,revoked_at)
		VALUES (?,?,?,'repair-race-group',?,?,?,'repair-race-review',?,NULL,1,?,NULL)`)
		.run(
			"repair-race-controller-B",
			input.coordinatorId,
			"owner-B",
			input.deviceId,
			input.publicKey,
			input.fingerprint,
			"b".repeat(64),
			"2026-10-01T00:00:00.000Z",
		);
}

for (const backend of ["SQLite", "D1"] as const) {
	type RepairFixture = Fixture & {
		hooks: { beforeRepair?: () => void };
		winningBatches(): number;
	};
	const test = it.extend<{ f: RepairFixture }>({
		f: async ({ task: _task }, use) => {
			const base = setupStore(backend);
			const hooks: RepairFixture["hooks"] = {};
			let winners = 0;
			const store =
				backend === "D1"
					? new D1CoordinatorStore(
							sqliteD1(base.db, {
								beforeBatch(statements) {
									if (
										statements.some(({ query }) =>
											/UPDATE coordinator_invites SET token\s*=/.test(query),
										)
									)
										winners++;
									if (
										statements.some(({ query }) =>
											/UPDATE enrolled_devices SET identity_id\s*=/.test(query),
										)
									)
										hooks.beforeRepair?.();
								},
							}),
						)
					: base.store;
			const f: RepairFixture = { db: base.db, store, hooks, winningBatches: () => winners };
			try {
				await use(f);
			} finally {
				await store.close();
				if (base.db.open) base.db.close();
			}
		},
	});
	async function prepared(f: RepairFixture, kind: "team_member" | "add_device") {
		const harness = {
			store: f.store,
			input: revocationInput("repair-consistency"),
			exec: async (sql: string, ...values: unknown[]) => {
				f.db.prepare(sql).run(...values);
			},
			rows: async (table: string) => f.db.prepare(`SELECT * FROM ${table}`).all(),
		};
		const invitation = await recipientInvite(harness, kind);
		const input = { ...invitation.input, coordinatorId: "coordinator-a" };
		await retainProducerOwner(f.db, { ...input, ownerIdentityId: input.identityId });
		return input;
	}
	function clearIdentity(f: RepairFixture, input: CoordinatorConsumeRecipientInviteInput) {
		f.db
			.prepare("UPDATE enrolled_devices SET identity_id=NULL WHERE device_id=?")
			.run(input.deviceId);
	}
	for (const kind of ["team_member", "add_device"] as const) {
		test(`${backend} ${kind} fresh consumption permits its own changes after the full initial pin`, async ({
			f,
		}) => {
			// Arrange: original retained A and its unrevoked source precede the producer.
			const input = await prepared(f, kind);
			// Act
			const result = await f.store.consumeRecipientInvite(input);
			// Assert: applying the pre-write snapshot after own output would reject this control.
			expect(result.status).toBe("accepted");
			expect(await f.store.getEnrollment("repair-consistency-group", input.deviceId)).toMatchObject(
				{ identity_id: input.identityId, enabled: 1 },
			);
			expect(f.db.prepare("SELECT * FROM coordinator_bootstrap_grants").all()).toHaveLength(
				kind === "add_device" ? 1 : 0,
			);
		});
		test(`${backend} ${kind} consumed invite repairs a null identity without racing evidence`, async ({
			f,
		}) => {
			// Arrange: the real initial acceptance remains the exact expected post-repair state.
			const input = await prepared(f, kind);
			expect((await f.store.consumeRecipientInvite(input)).status).toBe("accepted");
			const repaired = producerSnapshot(f.db);
			clearIdentity(f, input);
			const winningBatches = f.winningBatches();
			// Act
			const result = await f.store.consumeRecipientInvite(input);
			// Assert: repair changes only the missing identity, not grants, token, or sibling rows.
			expect(result.status).toBe("existing");
			expect(producerSnapshot(f.db)).toEqual(repaired);
			expect(f.winningBatches()).toBe(winningBatches);
		});
		if (backend === "D1") {
			test(`D1 ${kind} repair is its invocation's first write and must pin initial current evidence`, async ({
				f,
			}) => {
				// Arrange: the previous invocation consumed the token; this invocation only repairs.
				const input = await prepared(f, kind);
				expect((await f.store.consumeRecipientInvite(input)).status).toBe("accepted");
				clearIdentity(f, input);
				const winningBatches = f.winningBatches();
				let injected = false;
				let externalChange: ReturnType<typeof producerSnapshot> | undefined;
				f.hooks.beforeRepair = () => {
					delete f.hooks.beforeRepair;
					injected = true;
					// The D1 shim invokes this before opening the repair batch transaction.
					conflictingController(f, input);
					externalChange = producerSnapshot(f.db);
				};
				// Act: full evidence was captured before the new current controller B appears.
				const outcome = await f.store.consumeRecipientInvite(input).then(
					(result) => ({ kind: "accepted", status: result.status }),
					(error: unknown) => ({ kind: "denied", error }),
				);
				// Assert: preserve external B but do not repair A or write any sibling rows.
				expect(injected).toBe(true);
				expect(f.winningBatches()).toBe(winningBatches);
				expect.soft(outcome).toMatchObject({ kind: "denied" });
				expect.soft(producerSnapshot(f.db)).toEqual(externalChange);
				expect
					.soft(
						f.db
							.prepare("SELECT identity_id FROM enrolled_devices WHERE device_id=?")
							.get(input.deviceId),
					)
					.toEqual({ identity_id: null });
			});
		} else {
			test(`SQLite ${kind} consumed repair rejects conflicting current evidence before its immediate transaction`, async ({
				f,
			}) => {
				// Arrange: SQLite's synchronous transaction has no external interleaving at its repair UPDATE.
				const input = await prepared(f, kind);
				expect((await f.store.consumeRecipientInvite(input)).status).toBe("accepted");
				clearIdentity(f, input);
				conflictingController(f, input);
				const before = producerSnapshot(f.db);
				// Act
				const acceptance = f.store.consumeRecipientInvite(input);
				// Assert: characterize its existing full evidence check without inventing an in-transaction race.
				await expect(acceptance).rejects.toThrow();
				expect(producerSnapshot(f.db)).toEqual(before);
			});
		}
	}
}
