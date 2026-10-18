import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { BetterSqliteCoordinatorStore } from "./better-sqlite-coordinator-store.js";
import { prepareHistoricalAccountDatabase } from "./coordinator-auth-historical-test-fixture.js";
import { browserProofConfig, consumeSigninProof } from "./coordinator-auth-link-test-fixtures.js";
import {
	backendTest,
	credentialHash,
	freshBrowserHash,
	linked,
	linkId,
	signInInput,
} from "./coordinator-auth-session-test-fixtures.js";

for (const backend of ["SQLite", "D1"] as const) {
	const test = backendTest(backend);
	describe(`${backend} current V3 runtime`, () => {
		test("first link creates its immutable reservation and browser-sequence floor", async ({
			fixture: f,
		}) => {
			await linked(f);
			const row = f.db.prepare("SELECT * FROM coordinator_auth_account_links").get() as Record<
				string,
				unknown
			>;
			const browser = f.db
				.prepare(
					"SELECT browser_sequence FROM coordinator_auth_browser_transactions WHERE purpose='link'",
				)
				.get() as { browser_sequence: number };
			expect(row.generation).toBe(1);
			expect(row.signin_sequence_floor).toBe(browser.browser_sequence);
			expect(
				f.db
					.prepare("SELECT identity_id,first_link_id FROM coordinator_auth_account_associations")
					.get(),
			).toEqual({ identity_id: "identity-a", first_link_id: row.link_id });
		});
		test("same-clock intent order wins and a fresh empty snapshot clears earlier fields", async ({
			fixture: f,
		}) => {
			await linked(f);
			const cfg = browserProofConfig(f);
			const older = signInInput(f);
			expect((await f.store.signInWithConsumedBrowserTransaction(older, cfg)).kind).toBe("issued");
			const newerHash = "8".repeat(64);
			const newerCredential = "1".repeat(64);
			await consumeSigninProof(f, newerHash);
			expect(
				(
					await f.store.signInWithConsumedBrowserTransaction(
						{ ...older, browserTransactionHash: newerHash, credentialHash: newerCredential },
						cfg,
					)
				).kind,
			).toBe("issued");
			expect(
				await f.store.recordAuthAccountProfile(
					{ credentialHash: newerCredential, profile: { displayName: "Newer" } },
					cfg,
				),
			).toEqual({ kind: "recorded" });
			expect(
				await f.store.recordAuthAccountProfile(
					{ credentialHash, profile: { displayName: "Late older callback" } },
					cfg,
				),
			).toEqual({ kind: "not_recorded" });
			expect((await f.store.readAuthSessionAccount(credentialHash, cfg))?.profile).toEqual({
				displayName: "Newer",
			});
			const emptyHash = "9".repeat(64);
			const emptyCredential = "2".repeat(64);
			await consumeSigninProof(f, emptyHash);
			await f.store.signInWithConsumedBrowserTransaction(
				{ ...older, browserTransactionHash: emptyHash, credentialHash: emptyCredential },
				cfg,
			);
			await f.store.recordAuthAccountProfile({ credentialHash: emptyCredential, profile: {} }, cfg);
			expect((await f.store.readAuthSessionAccount(credentialHash, cfg))?.profile).toEqual({});
			expect(
				f.db.prepare("SELECT source_order FROM coordinator_auth_account_profiles").get(),
			).toEqual({ source_order: 5 });
		});
		test("revocation targets an ended generation, blocks the Identity and retries without audit reinsertion", async ({
			fixture: f,
		}) => {
			await linked(f);
			const cfg = browserProofConfig(f);
			await f.store.signInWithConsumedBrowserTransaction(signInInput(f), cfg);
			const currentLinkId = linkId(f);
			// A second ended record exercises the Identity-wide barrier independently
			// of which generation's own cookie is being authenticated.
			f.db
				.prepare("INSERT INTO coordinator_auth_account_associations VALUES (?,?,?,?,?,?)")
				.run(f.cfg.coordinatorId, f.cfg.issuer, "ended-account", "identity-a", "ended-link", f.now);
			f.db
				.prepare(`INSERT INTO coordinator_auth_account_links
 (coordinator_id,link_id,issuer,subject,identity_id,attempt_id,controller_attestation_id,auth_config_revision,created_at_ms,authority_kind,generation,signin_sequence_floor,ended_at_ms,end_reason,end_attempt_id)
 SELECT coordinator_id,'ended-link',issuer,'ended-account',identity_id,'ended-attempt',controller_attestation_id,auth_config_revision,created_at_ms,authority_kind,2,0,created_at_ms,'user_disconnected','ended-receipt'
 FROM coordinator_auth_account_links WHERE link_id=?`)
				.run(currentLinkId);
			f.db
				.prepare(`INSERT INTO coordinator_auth_link_audit_log
 SELECT coordinator_id,'ended-link',action,'ended-attempt',identity_id,group_id,device_id,fingerprint,controller_attestation_id,auth_config_revision,created_at_ms,authority_kind,device_claim_id
 FROM coordinator_auth_link_audit_log WHERE link_id=? AND action='link_created'`)
				.run(currentLinkId);
			expect(await f.store.revokeAuthAccountLink({ linkId: "ended-link" }, cfg)).toEqual({
				kind: "revoked",
			});
			const before = f.db.prepare("SELECT * FROM coordinator_auth_link_audit_log").all();
			expect(await f.store.revokeAuthAccountLink({ linkId: "ended-link" }, cfg)).toEqual({
				kind: "revoked",
			});
			expect(f.db.prepare("SELECT * FROM coordinator_auth_link_audit_log").all()).toEqual(before);
			expect(await f.store.readAuthSession(credentialHash, cfg)).toBeNull();
			expect(await f.store.readAuthSessionAccount(credentialHash, cfg)).toBeNull();
		});
	});
}

it("opening a predecessor preserves auth DDL/data while sync remains available", async () => {
	const directory = mkdtempSync(join(tmpdir(), "auth-v3-open-"));
	const path = join(directory, "coordinator.sqlite");
	const legacy = new Database(path);
	const history = prepareHistoricalAccountDatabase(legacy, { authority: "controller_attestation" });
	const definitions = () =>
		legacy
			.prepare(
				"SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'coordinator_auth_*' ORDER BY type,name",
			)
			.all();
	const before = definitions();
	const links = legacy.prepare("SELECT * FROM coordinator_auth_account_links").all();
	legacy.close();
	const store = new BetterSqliteCoordinatorStore(path);
	try {
		expect(
			store.db
				.prepare(
					"SELECT type,name,sql FROM sqlite_master WHERE name GLOB 'coordinator_auth_*' ORDER BY type,name",
				)
				.all(),
		).toEqual(before);
		expect(store.db.prepare("SELECT * FROM coordinator_auth_account_links").all()).toEqual(links);
		await expect(store.readAuthSession(freshBrowserHash, history.config)).rejects.toMatchObject({
			name: "coordinator_auth_schema_upgrade_required",
		});
		await store.createGroup("sync-with-predecessor-auth");
		expect(
			store.db
				.prepare("SELECT group_id FROM groups WHERE group_id=?")
				.get("sync-with-predecessor-auth"),
		).toEqual({ group_id: "sync-with-predecessor-auth" });
	} finally {
		store.db.close();
		rmSync(directory, { recursive: true });
	}
});
