import { captureAuthAccountProfile } from "./coordinator-auth-account-profile.js";
import { captureAuthBrowserConfig } from "./coordinator-auth-browser-transaction.js";
import type { CoordinatorAuthBrowserConfig } from "./coordinator-auth-browser-transaction-contract.js";
import { isAuthControllerId } from "./coordinator-auth-controller.js";
import {
	type AuthLinkBackend,
	type AuthLinkStatement,
	authLinkNow,
} from "./coordinator-auth-link.js";
import { captureAuthLinkChangeAuthority } from "./coordinator-auth-link-change-authority.js";
import {
	AUTH_LINK_CHANGE_PURPOSE,
	type CoordinatorAuthLinkChangeBrowserInput,
	type CoordinatorAuthLinkChangeCreateInput,
	type CoordinatorAuthLinkChangeFinalizeInput,
	type CoordinatorAuthLinkChangeResult,
	type CoordinatorAuthLinkChangeStatus,
	type CoordinatorAuthLinkChangeStore,
} from "./coordinator-auth-link-change-contract.js";
import {
	assertAuthLinkChangeWrite,
	authLinkChangeEffects,
	AUTH_LINK_CHANGE_TABLE as TABLE,
} from "./coordinator-auth-link-change-effects.js";
import type {
	CoordinatorAuthLinkConfig,
	CoordinatorAuthLinkRequester,
} from "./coordinator-auth-link-contract.js";
import {
	AUTH_LINK_CREATE_WINDOW_MS,
	AUTH_LINK_MAX_ACTIVE_PER_DEVICE,
	AUTH_LINK_MAX_CREATES_PER_DEVICE_RETENTION,
	AUTH_LINK_MAX_CREATES_PER_DEVICE_WINDOW,
	AUTH_LINK_MAX_UNFINISHED_PER_COORDINATOR,
	AUTH_LINK_RETENTION_WINDOW_MS,
} from "./coordinator-auth-link-contract.js";
import {
	capture,
	captureAuthLinkConfig,
	captureAuthLinkSigner,
	isHash,
} from "./coordinator-auth-link-input.js";
import { parseCoordinatorAuthLoopback } from "./coordinator-auth-loopback.js";

const LIVE = "('pending','browser_claimed','oidc_verified','confirmed')";
const CONFIG = "coordinator_id = ? AND issuer = ? AND auth_config_revision = ?";
interface ChangeRow {
	attempt_id: string;
	identity_id: string;
	intent: CoordinatorAuthLinkChangeStatus["intent"];
	state: CoordinatorAuthLinkChangeStatus["state"];
	expires_at_ms: number;
	group_id: string;
	device_id: string;
	public_key: string;
	fingerprint: string;
	runtime_verifier_hash: string;
	browser_start_hash: string;
	loopback_redirect: string;
	browser_transaction_hash: string | null;
	browser_binder_hash: string | null;
	completion_secret_hash: string | null;
	target_link_id: string;
	target_generation: number;
	completed_at_ms: number | null;
}
const unavailable = (): CoordinatorAuthLinkChangeResult => ({
	kind: "rejected",
	error: "attempt_unavailable",
});
const invalid = (): CoordinatorAuthLinkChangeResult => ({
	kind: "rejected",
	error: "invalid_input",
});
const configValues = (c: CoordinatorAuthLinkConfig) => [c.coordinatorId, c.issuer, c.revision];
function project(row: ChangeRow, now: number): CoordinatorAuthLinkChangeStatus {
	let state = row.state;
	if (
		["pending", "browser_claimed", "oidc_verified", "confirmed"].includes(state) &&
		row.expires_at_ms <= now
	)
		state = "expired";
	return { attemptId: row.attempt_id, intent: row.intent, state, expiresAtMs: row.expires_at_ms };
}
function creationMatches(row: ChangeRow, i: CoordinatorAuthLinkChangeCreateInput): boolean {
	return (
		row.identity_id === i.identityId &&
		row.intent === i.intent &&
		row.group_id === i.signer.groupId &&
		row.device_id === i.signer.deviceId &&
		row.public_key === i.signer.publicKey &&
		row.fingerprint === i.signer.fingerprint &&
		row.runtime_verifier_hash === i.runtimeVerifierHash &&
		row.browser_start_hash === i.browserStartHash &&
		row.loopback_redirect === i.loopbackRedirect
	);
}
function requesterProof(value: unknown): AuthLinkStatement | null {
	const r = capture(value, ["kind"]);
	if (r?.kind === "browser") {
		const b = capture(value, ["browserTransactionHash"]);
		return isHash(b?.browserTransactionHash)
			? { sql: "browser_transaction_hash = ?", values: [b.browserTransactionHash] }
			: null;
	}
	if (r?.kind !== "device") return null;
	const d = capture(value, ["signer"]);
	const s = captureAuthLinkSigner(d?.signer);
	return s
		? {
				sql: "group_id = ? AND device_id = ? AND public_key = ? AND fingerprint = ?",
				values: [s.groupId, s.deviceId, s.publicKey, s.fingerprint],
			}
		: null;
}
function browserProof(input: unknown): CoordinatorAuthLinkChangeBrowserInput | null {
	const i = capture(input, ["attemptId", "browserTransactionHash", "binderHash"]);
	if (
		!i ||
		!isAuthControllerId(i.attemptId) ||
		!isHash(i.browserTransactionHash) ||
		!isHash(i.binderHash)
	)
		return null;
	return {
		attemptId: i.attemptId,
		browserTransactionHash: i.browserTransactionHash,
		binderHash: i.binderHash,
	};
}

function captureCreate(input: unknown): CoordinatorAuthLinkChangeCreateInput | null {
	const i = capture(input, [
		"attemptId",
		"identityId",
		"intent",
		"signer",
		"runtimeVerifierHash",
		"browserStartHash",
		"loopbackRedirect",
	]);
	const signer = captureAuthLinkSigner(i?.signer);
	if (
		!i ||
		!signer ||
		!isAuthControllerId(i.attemptId) ||
		!isAuthControllerId(i.identityId) ||
		(i.intent !== "disconnect" && i.intent !== "refresh") ||
		!isHash(i.runtimeVerifierHash) ||
		!isHash(i.browserStartHash) ||
		typeof i.loopbackRedirect !== "string" ||
		!parseCoordinatorAuthLoopback(i.loopbackRedirect).ok
	)
		return null;
	return {
		attemptId: i.attemptId,
		identityId: i.identityId,
		intent: i.intent,
		signer,
		runtimeVerifierHash: i.runtimeVerifierHash,
		browserStartHash: i.browserStartHash,
		loopbackRedirect: i.loopbackRedirect,
	};
}

function captureFinalize(
	input: unknown,
	c: CoordinatorAuthLinkConfig,
): CoordinatorAuthLinkChangeFinalizeInput | null {
	const i = capture(input, [
		"purpose",
		"coordinatorId",
		"attemptId",
		"groupId",
		"identityId",
		"deviceId",
		"fingerprint",
		"signer",
		"runtimeVerifierHash",
		"completionSecretHash",
	]);
	const signer = captureAuthLinkSigner(i?.signer);
	if (
		!i ||
		!signer ||
		i.purpose !== AUTH_LINK_CHANGE_PURPOSE ||
		i.coordinatorId !== c.coordinatorId ||
		!isAuthControllerId(i.attemptId) ||
		!isAuthControllerId(i.identityId) ||
		i.groupId !== signer.groupId ||
		i.deviceId !== signer.deviceId ||
		i.fingerprint !== signer.fingerprint ||
		!isHash(i.runtimeVerifierHash) ||
		!isHash(i.completionSecretHash)
	)
		return null;
	return {
		purpose: AUTH_LINK_CHANGE_PURPOSE,
		coordinatorId: c.coordinatorId,
		attemptId: i.attemptId,
		identityId: i.identityId,
		groupId: signer.groupId,
		deviceId: signer.deviceId,
		fingerprint: signer.fingerprint,
		signer,
		runtimeVerifierHash: i.runtimeVerifierHash,
		completionSecretHash: i.completionSecretHash,
	};
}

/** No initialization/migration or session mint. The native batch owns atomicity. */
export class AuthLinkChangeOperations implements CoordinatorAuthLinkChangeStore {
	constructor(
		private readonly backend: AuthLinkBackend,
		private readonly clock: () => number = Date.now,
	) {}
	private read(
		attemptId: string,
		c: CoordinatorAuthLinkConfig,
		proof: AuthLinkStatement = { sql: "1 = 1", values: [] },
	) {
		return this.backend.first<ChangeRow>({
			sql: `SELECT * FROM ${TABLE} WHERE attempt_id = ? AND ${CONFIG} AND ${proof.sql}`,
			values: [attemptId, ...configValues(c), ...proof.values],
		});
	}
	async createAuthLinkChangeAttempt(
		input: CoordinatorAuthLinkChangeCreateInput,
		config: CoordinatorAuthBrowserConfig,
	): Promise<CoordinatorAuthLinkChangeResult> {
		const c = captureAuthBrowserConfig(config);
		const i = captureCreate(input);
		if (!c?.enabled || !i) return invalid();
		const s = i.signer;
		const now = authLinkNow(this.clock);
		const authority = await captureAuthLinkChangeAuthority(
			this.backend,
			{ signer: s, identityId: i.identityId, attemptId: i.attemptId },
			c,
			now,
		);
		if (!authority) return unavailable();
		const existing = await this.read(i.attemptId, c);
		if (existing) {
			if (!creationMatches(existing, i)) return unavailable();
			const current = await this.backend.first({
				sql: `${authority.sql} SELECT 1 FROM management_target WHERE link_id = ? AND generation = ?`,
				values: [...authority.values, existing.target_link_id, existing.target_generation],
			});
			if (!current) return unavailable();
			return { kind: "existing", status: project(existing, now) };
		}
		const origin = new URL(c.redirectUri).origin;
		try {
			await this.backend.batch([
				{
					sql: `UPDATE ${TABLE} SET state = 'expired' WHERE coordinator_id = ? AND identity_id = ? AND state IN ${LIVE} AND expires_at_ms <= ?`,
					values: [c.coordinatorId, i.identityId, now],
				},
				{
					sql: `${authority.sql} INSERT INTO ${TABLE} (
 coordinator_id,attempt_id,purpose,intent,target_link_id,target_generation,identity_id,issuer,target_subject,
 group_id,device_id,public_key,fingerprint,key_id,authority_kind,controller_attestation_id,controller_review_receipt_id,
 controller_revision,device_claim_id,auth_config_revision,origin,loopback_redirect,runtime_verifier_hash,browser_start_hash,state,created_at_ms,expires_at_ms)
 SELECT l.coordinator_id,?, '${AUTH_LINK_CHANGE_PURPOSE}',?,l.link_id,l.generation,l.identity_id,l.issuer,l.subject,
 p.group_id,p.device_id,p.public_key,p.fingerprint,p.key_id,l.authority_kind,
 a.attestation_id,a.review_receipt_id,a.revision,l.device_claim_id,?,?,?,?,?,'pending',?,?
 FROM management_target l JOIN management_requester p ON p.coordinator_id = l.coordinator_id
 LEFT JOIN coordinator_auth_controller_attestations a ON l.authority_kind = 'controller_attestation'
 AND a.coordinator_id = p.coordinator_id AND a.identity_id = p.identity_id AND a.group_id = p.group_id
 AND a.device_id = p.device_id AND a.public_key = p.public_key AND a.fingerprint = p.fingerprint
 AND a.revoked_at IS NULL AND a.revision = 1
 WHERE NOT EXISTS (SELECT 1 FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = ?)
 AND NOT EXISTS (SELECT 1 FROM coordinator_owner_enrollment_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = ?)
 AND NOT EXISTS (SELECT 1 FROM coordinator_auth_browser_transactions t WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = ?)
 AND NOT EXISTS (SELECT 1 FROM coordinator_auth_link_profiles t WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = ?)
 AND (SELECT count(*) FROM ${TABLE} t WHERE t.coordinator_id = p.coordinator_id AND t.group_id = p.group_id AND t.device_id = p.device_id AND t.created_at_ms > ?) < ${AUTH_LINK_MAX_CREATES_PER_DEVICE_WINDOW}
 AND (SELECT count(*) FROM ${TABLE} t WHERE t.coordinator_id = p.coordinator_id AND t.group_id = p.group_id AND t.device_id = p.device_id AND t.created_at_ms > ?) < ${AUTH_LINK_MAX_CREATES_PER_DEVICE_RETENTION}
 AND (SELECT count(*) FROM ${TABLE} t WHERE t.coordinator_id = p.coordinator_id AND t.group_id = p.group_id AND t.device_id = p.device_id AND t.state IN ${LIVE} AND t.expires_at_ms > ?) < ${AUTH_LINK_MAX_ACTIVE_PER_DEVICE}
 AND (SELECT count(*) FROM (SELECT 1 FROM ${TABLE} t WHERE t.coordinator_id = p.coordinator_id AND t.state <> 'completed' LIMIT ${AUTH_LINK_MAX_UNFINISHED_PER_COORDINATOR})) < ${AUTH_LINK_MAX_UNFINISHED_PER_COORDINATOR}`,
					values: [
						...authority.values,
						i.attemptId,
						String(i.intent),
						c.revision,
						origin,
						String(i.loopbackRedirect),
						i.runtimeVerifierHash,
						i.browserStartHash,
						now,
						now + 600000,
						i.attemptId,
						i.attemptId,
						i.attemptId,
						i.attemptId,
						now - AUTH_LINK_CREATE_WINDOW_MS,
						now - AUTH_LINK_RETENTION_WINDOW_MS,
						now,
					],
				},
			]);
		} catch {
			return unavailable();
		}
		const row = await this.read(i.attemptId, c);
		return row && creationMatches(row, i)
			? { kind: "created", status: project(row, now) }
			: unavailable();
	}
	async getAuthLinkChangeAttemptStatus(
		attemptId: string,
		requester: CoordinatorAuthLinkRequester,
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeStatus | null> {
		const c = captureAuthLinkConfig(config);
		const proof = requesterProof(requester);
		if (!c?.enabled || !proof || !isAuthControllerId(attemptId)) return null;
		const row = await this.read(attemptId, c, proof);
		return row ? project(row, authLinkNow(this.clock)) : null;
	}
	async recordAuthLinkChangeOidcVerified(
		input: CoordinatorAuthLinkChangeBrowserInput & {
			account: { issuer: string; subject: string };
			profile: unknown;
		},
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult> {
		const c = captureAuthLinkConfig(config);
		const b = browserProof(input);
		const i = capture(input, ["account", "profile"]);
		const account = capture(i?.account, ["issuer", "subject"]);
		const profile = captureAuthAccountProfile(i?.profile);
		if (
			!c?.enabled ||
			!b ||
			!profile ||
			account?.issuer !== c.issuer ||
			typeof account.subject !== "string" ||
			!account.subject.length ||
			account.subject.length > 255
		)
			return invalid();
		const now = authLinkNow(this.clock);
		try {
			await this.backend.batch([
				{
					sql: `UPDATE ${TABLE} SET state = 'oidc_verified', account_subject = ?, oidc_verified_at_ms = ? WHERE attempt_id = ? AND ${CONFIG} AND state = 'browser_claimed' AND expires_at_ms > ? AND browser_transaction_hash = ? AND browser_binder_hash = ? AND target_subject = ?
 AND EXISTS (SELECT 1 FROM coordinator_auth_browser_transactions t WHERE t.coordinator_id = ${TABLE}.coordinator_id AND t.attempt_id = ${TABLE}.attempt_id AND t.purpose = 'link_change' AND t.state = 'consumed' AND t.browser_transaction_hash = ${TABLE}.browser_transaction_hash AND t.binder_hash = ${TABLE}.browser_binder_hash AND t.browser_sequence = ${TABLE}.browser_sequence AND t.issuer = ${TABLE}.issuer AND t.auth_config_revision = ${TABLE}.auth_config_revision)`,
					values: [
						account.subject,
						now,
						b.attemptId,
						...configValues(c),
						now,
						b.browserTransactionHash,
						b.binderHash,
						account.subject,
					],
				},
				assertAuthLinkChangeWrite(),
				{
					sql: `INSERT INTO coordinator_auth_link_profiles (coordinator_id,attempt_id,issuer,subject,auth_config_revision,browser_transaction_hash,display_name,email,email_verified,picture_url,verified_at_ms,source_order,source_purpose)
 SELECT coordinator_id,attempt_id,issuer,account_subject,auth_config_revision,browser_transaction_hash,?,?,?,?,oidc_verified_at_ms,browser_sequence+1,'link_change' FROM ${TABLE} WHERE attempt_id = ? AND ${CONFIG} AND state = 'oidc_verified' AND browser_transaction_hash = ? AND browser_binder_hash = ?`,
					values: [
						profile.displayName ?? null,
						profile.email ?? null,
						profile.emailVerified === undefined ? null : Number(profile.emailVerified),
						profile.pictureUrl ?? null,
						b.attemptId,
						...configValues(c),
						b.browserTransactionHash,
						b.binderHash,
					],
				},
				assertAuthLinkChangeWrite(),
			]);
		} catch {
			return unavailable();
		}
		const row = await this.read(b.attemptId, c);
		return row ? { kind: "applied", status: project(row, now) } : unavailable();
	}
	async confirmAuthLinkChangeAttempt(
		input: CoordinatorAuthLinkChangeBrowserInput & {
			completionSecretHash: string;
			confirmation: "browser" | "verified_refresh";
		},
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult> {
		const c = captureAuthLinkConfig(config);
		const b = browserProof(input);
		const i = capture(input, ["completionSecretHash", "confirmation"]);
		if (
			!c?.enabled ||
			!b ||
			!i ||
			!isHash(i.completionSecretHash) ||
			(i.confirmation !== "browser" && i.confirmation !== "verified_refresh")
		)
			return invalid();
		const now = authLinkNow(this.clock);
		const count = await this.backend.run({
			sql: `UPDATE ${TABLE} SET state = 'confirmed', completion_secret_hash = ?, confirmed_at_ms = ? WHERE attempt_id = ? AND ${CONFIG} AND state = 'oidc_verified' AND expires_at_ms > ? AND browser_transaction_hash = ? AND browser_binder_hash = ? AND intent = ?`,
			values: [
				i.completionSecretHash,
				now,
				b.attemptId,
				...configValues(c),
				now,
				b.browserTransactionHash,
				b.binderHash,
				i.confirmation === "browser" ? "disconnect" : "refresh",
			],
		});
		const row = await this.read(b.attemptId, c);
		return count === 1 && row ? { kind: "applied", status: project(row, now) } : unavailable();
	}
	async finalizeAuthLinkChangeAttempt(
		input: CoordinatorAuthLinkChangeFinalizeInput,
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult> {
		const c = captureAuthLinkConfig(config);
		const i = c?.enabled ? captureFinalize(input, c) : null;
		if (!c?.enabled || !i) return invalid();
		const s = i.signer;
		const now = authLinkNow(this.clock);
		const proof: AuthLinkStatement = {
			sql: "identity_id = ? AND group_id = ? AND device_id = ? AND public_key = ? AND fingerprint = ? AND runtime_verifier_hash = ? AND completion_secret_hash = ?",
			values: [
				i.identityId,
				s.groupId,
				s.deviceId,
				s.publicKey,
				s.fingerprint,
				i.runtimeVerifierHash,
				i.completionSecretHash,
			],
		};
		const row = await this.read(i.attemptId, c, proof);
		if (!row) return unavailable();
		if (row.state === "completed") return this.retainedResult(row, c, now);
		const authority = await captureAuthLinkChangeAuthority(
			this.backend,
			{ signer: s, identityId: i.identityId, attemptId: i.attemptId },
			c,
			now,
		);
		if (!authority) return unavailable();
		try {
			await this.backend.batch([
				{
					sql: `${authority.sql} UPDATE ${TABLE} SET state = 'completed', completed_at_ms = ? WHERE attempt_id = ? AND ${CONFIG} AND ${proof.sql} AND state = 'confirmed' AND created_at_ms <= ? AND expires_at_ms > ?
 AND EXISTS (SELECT 1 FROM management_target l WHERE l.link_id = ${TABLE}.target_link_id AND l.generation = ${TABLE}.target_generation AND l.authority_kind = ${TABLE}.authority_kind AND l.device_claim_id IS ${TABLE}.device_claim_id)
 AND EXISTS (SELECT 1 FROM management_requester p WHERE p.key_id = ${TABLE}.key_id)
 AND (${TABLE}.authority_kind = 'device_claim' OR EXISTS (
 SELECT 1 FROM coordinator_auth_controller_attestations active
 WHERE active.coordinator_id = ${TABLE}.coordinator_id AND active.attestation_id = ${TABLE}.controller_attestation_id
 AND active.review_receipt_id = ${TABLE}.controller_review_receipt_id AND active.revision = ${TABLE}.controller_revision
 AND active.identity_id = ${TABLE}.identity_id AND active.group_id = ${TABLE}.group_id
 AND active.device_id = ${TABLE}.device_id AND active.public_key = ${TABLE}.public_key
 AND active.fingerprint = ${TABLE}.fingerprint AND active.revoked_at IS NULL))
 AND EXISTS (SELECT 1 FROM coordinator_auth_browser_transactions b
 WHERE b.coordinator_id = ${TABLE}.coordinator_id AND b.attempt_id = ${TABLE}.attempt_id
 AND b.purpose = 'link_change' AND b.state = 'consumed' AND b.browser_transaction_hash = ${TABLE}.browser_transaction_hash
 AND b.binder_hash = ${TABLE}.browser_binder_hash AND b.browser_sequence = ${TABLE}.browser_sequence
 AND b.issuer = ${TABLE}.issuer AND b.auth_config_revision = ${TABLE}.auth_config_revision
 AND b.created_at_ms = ${TABLE}.claimed_at_ms AND b.consumed_at_ms BETWEEN ${TABLE}.claimed_at_ms AND ${TABLE}.oidc_verified_at_ms)
 AND EXISTS (SELECT 1 FROM coordinator_auth_link_profiles p WHERE p.coordinator_id = ${TABLE}.coordinator_id AND p.attempt_id = ${TABLE}.attempt_id AND p.source_purpose = 'link_change' AND p.link_id IS NULL AND p.issuer = ${TABLE}.issuer AND p.subject = ${TABLE}.target_subject AND p.auth_config_revision = ${TABLE}.auth_config_revision AND p.browser_transaction_hash = ${TABLE}.browser_transaction_hash AND p.source_order = ${TABLE}.browser_sequence+1 AND p.verified_at_ms = ${TABLE}.oidc_verified_at_ms)`,
					values: [
						...authority.values,
						now,
						i.attemptId,
						...configValues(c),
						...proof.values,
						now,
						now,
					],
				},
				assertAuthLinkChangeWrite(),
				...authLinkChangeEffects({
					coordinatorId: c.coordinatorId,
					attemptId: row.attempt_id,
					targetLinkId: row.target_link_id,
					targetGeneration: row.target_generation,
					intent: row.intent,
					now,
				}),
			]);
		} catch {
			return unavailable();
		}
		return this.readCompleted(i.attemptId, c, proof, now);
	}
	private async readCompleted(
		attemptId: string,
		c: CoordinatorAuthLinkConfig,
		proof: AuthLinkStatement,
		now: number,
	): Promise<CoordinatorAuthLinkChangeResult> {
		const completed = await this.read(attemptId, c, proof);
		return completed?.state === "completed"
			? { kind: "applied", status: project(completed, now) }
			: unavailable();
	}
	private async retainedResult(
		row: ChangeRow,
		c: CoordinatorAuthLinkConfig,
		now: number,
	): Promise<CoordinatorAuthLinkChangeResult> {
		const committed = await this.backend.first({
			sql: `SELECT 1 FROM coordinator_auth_account_links l WHERE l.coordinator_id = ? AND l.link_id = ? AND l.generation = ? AND (? = 'refresh' OR (l.end_attempt_id = ? AND l.ended_at_ms = ? AND l.end_reason = 'user_disconnected'))`,
			values: [
				c.coordinatorId,
				row.target_link_id,
				row.target_generation,
				row.intent,
				row.attempt_id,
				row.completed_at_ms,
			],
		});
		return committed ? { kind: "existing", status: project(row, now) } : unavailable();
	}
	async failAuthLinkChangeAttempt(
		input: {
			attemptId: string;
			requester: CoordinatorAuthLinkRequester;
			reason: "cancelled" | "provider_failure";
		},
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult> {
		const c = captureAuthLinkConfig(config);
		const i = capture(input, ["attemptId", "requester", "reason"]);
		const proof = requesterProof(i?.requester);
		const requester = capture(i?.requester, ["kind"]);
		if (
			!c?.enabled ||
			!i ||
			!proof ||
			!isAuthControllerId(i.attemptId) ||
			(i.reason !== "cancelled" && i.reason !== "provider_failure") ||
			(requester?.kind === "device" && i.reason !== "cancelled")
		)
			return invalid();
		const now = authLinkNow(this.clock);
		const reason = i.reason === "cancelled" ? `${requester?.kind}_cancelled` : "provider_failure";
		await this.backend.batch([
			{
				sql: `UPDATE ${TABLE} SET state = 'failed', failure_reason = ?, failed_at_ms = ? WHERE attempt_id = ? AND ${CONFIG} AND ${proof.sql} AND state IN ${LIVE} AND expires_at_ms > ?`,
				values: [reason, now, i.attemptId, ...configValues(c), ...proof.values, now],
			},
			{
				sql: `DELETE FROM coordinator_auth_link_profiles WHERE coordinator_id = ? AND attempt_id = ? AND source_purpose = 'link_change' AND link_id IS NULL AND EXISTS (SELECT 1 FROM ${TABLE} WHERE attempt_id = ? AND ${CONFIG} AND ${proof.sql} AND state = 'failed')`,
				values: [c.coordinatorId, i.attemptId, i.attemptId, ...configValues(c), ...proof.values],
			},
		]);
		const row = await this.read(i.attemptId, c, proof);
		return row?.state === "failed" ? { kind: "applied", status: project(row, now) } : unavailable();
	}
}
