import {
	AUTH_DEVICE_CLAIM_INPUT_SQL,
	captureDeviceClaimEligibility,
} from "./coordinator-auth-device-claim-eligibility.js";
import type { AuthLinkBackend, AuthLinkStatement } from "./coordinator-auth-link.js";
import { AUTH_LINK_CHANGE_REQUESTER_SQL } from "./coordinator-auth-link-change-authority.js";
import { assertAuthLinkChangeWrite } from "./coordinator-auth-link-change-effects.js";
import type {
	CoordinatorAuthLinkConfig,
	CoordinatorAuthLinkCreateInput,
	CoordinatorAuthLinkCreateResult,
	CoordinatorAuthLinkFinalizeInput,
	CoordinatorAuthLinkResult,
	CoordinatorAuthLinkSigner,
} from "./coordinator-auth-link-contract.js";
import {
	AUTH_LINK_CREATE_WINDOW_MS,
	AUTH_LINK_MAX_ACTIVE_PER_DEVICE,
	AUTH_LINK_MAX_ACTIVE_PER_IDENTITY,
	AUTH_LINK_MAX_CREATES_PER_DEVICE_RETENTION,
	AUTH_LINK_MAX_CREATES_PER_DEVICE_WINDOW,
	AUTH_LINK_MAX_UNFINISHED_PER_COORDINATOR,
	AUTH_LINK_RETENTION_WINDOW_MS,
} from "./coordinator-auth-link-contract.js";
import { promoteAuthLinkProfile } from "./coordinator-auth-link-profile.js";
import { authDeviceClaimProvenanceSql } from "./coordinator-auth-link-provenance.js";

interface Prior {
	link_id: string;
	generation: number;
	authority_kind: "device_claim" | "controller_attestation";
}
const ATTESTATION = `a.coordinator_id = p.coordinator_id AND a.identity_id = p.identity_id AND a.group_id = p.group_id
 AND a.device_id = p.device_id AND a.public_key = p.public_key AND a.fingerprint = p.fingerprint AND a.revoked_at IS NULL AND a.revision = 1`;
const PRIOR = `l.coordinator_id = p.coordinator_id AND l.identity_id = p.identity_id AND l.issuer = p.issuer
 AND l.ended_at_ms IS NOT NULL AND l.end_reason = 'user_disconnected' AND l.generation < 9007199254740991
 AND NOT EXISTS (SELECT 1 FROM coordinator_auth_account_links h WHERE h.coordinator_id = p.coordinator_id AND h.identity_id = p.identity_id AND (h.generation > l.generation OR h.revoked_at_ms IS NOT NULL OR h.ended_at_ms IS NULL))
 AND ((l.authority_kind = 'controller_attestation' AND EXISTS (SELECT 1 FROM coordinator_auth_controller_attestations a WHERE ${ATTESTATION}))
 OR (l.authority_kind = 'device_claim' AND ${authDeviceClaimProvenanceSql({ link: "l" })} AND EXISTS (
 SELECT 1 FROM coordinator_auth_device_claims d WHERE d.coordinator_id = p.coordinator_id AND d.claim_id = l.device_claim_id
 AND d.identity_id = p.identity_id AND d.device_id = p.device_id AND d.public_key = p.public_key AND d.fingerprint = p.fingerprint AND d.key_id = p.key_id AND d.issuer = p.issuer)))`;

export { PRIOR as AUTH_LINK_CONTINUATION_PRIOR_SQL };

/** Fresh current requester and complete historical genesis are separate proofs. */
export async function captureAuthLinkContinuation(
	backend: Pick<AuthLinkBackend, "first">,
	input: { signer: CoordinatorAuthLinkSigner; identityId: string; attemptId: string },
	c: CoordinatorAuthLinkConfig,
	now: number,
): Promise<AuthLinkStatement | null> {
	const captured = await captureDeviceClaimEligibility(backend, input, c, now);
	if (!captured) return null;
	return {
		sql: `${AUTH_DEVICE_CLAIM_INPUT_SQL}, continuation_requester AS MATERIALIZED (
 SELECT p.* FROM claim_input p WHERE ${AUTH_LINK_CHANGE_REQUESTER_SQL}), continuation_target AS MATERIALIZED (
 SELECT l.* FROM continuation_requester p JOIN coordinator_auth_account_links l ON l.coordinator_id = p.coordinator_id WHERE ${PRIOR})`,
		values: captured.values,
	};
}

/** null means no history: the caller may run its separately proven gen-1 path. */
export async function createAuthLinkContinuationAttempt(
	backend: AuthLinkBackend,
	input: CoordinatorAuthLinkCreateInput,
	c: CoordinatorAuthLinkConfig,
	now: number,
): Promise<CoordinatorAuthLinkCreateResult | null> {
	const identityId =
		input.expectedIdentityId ??
		(input.authority.kind === "device_claim" ? input.authority.identityId : null);
	if (!identityId) return null;
	const history = await backend.first<Prior>({
		sql: "SELECT link_id,generation,authority_kind FROM coordinator_auth_account_links WHERE coordinator_id = ? AND identity_id = ? ORDER BY generation DESC LIMIT 1",
		values: [c.coordinatorId, identityId],
	});
	if (!history) return null;
	if (history.authority_kind !== input.authority.kind || !input.browserStartHash)
		return { kind: "rejected", error: "attempt_unavailable" };
	const source = await captureAuthLinkContinuation(
		backend,
		{ signer: input.signer, identityId, attemptId: input.attemptId },
		c,
		now,
	);
	if (!source) return { kind: "rejected", error: "attempt_unavailable" };
	try {
		const count = await backend.run({
			sql: `${source.sql} INSERT INTO coordinator_auth_link_attempts
 (coordinator_id,attempt_id,identity_id,group_id,device_id,public_key,fingerprint,controller_attestation_id,controller_review_receipt_id,controller_revision,authority_kind,issuer,auth_config_revision,runtime_verifier_hash,loopback_redirect,browser_start_hash,state,created_at_ms,expires_at_ms,prior_link_id,prior_generation)
 SELECT l.coordinator_id,?,l.identity_id,p.group_id,p.device_id,p.public_key,p.fingerprint,a.attestation_id,a.review_receipt_id,a.revision,l.authority_kind,l.issuer,?,?,?,?,'pending',?,?,l.link_id,l.generation
 FROM continuation_target l JOIN continuation_requester p ON p.coordinator_id = l.coordinator_id
 LEFT JOIN coordinator_auth_controller_attestations a ON l.authority_kind = 'controller_attestation' AND ${ATTESTATION}
 WHERE l.link_id = ? AND l.generation = ?
 AND NOT EXISTS (SELECT 1 FROM coordinator_auth_link_change_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = ?)
 AND NOT EXISTS (SELECT 1 FROM coordinator_owner_enrollment_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = ?)
 AND NOT EXISTS (SELECT 1 FROM coordinator_auth_browser_transactions t WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = ?)
 AND (SELECT count(*) FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.identity_id = p.identity_id AND t.state IN ('pending','browser_claimed','oidc_verified','confirmed') AND t.expires_at_ms > ?) < ${AUTH_LINK_MAX_ACTIVE_PER_IDENTITY}
 AND (SELECT count(*) FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.group_id = p.group_id AND t.device_id = p.device_id AND t.state IN ('pending','browser_claimed','oidc_verified','confirmed') AND t.expires_at_ms > ?) < ${AUTH_LINK_MAX_ACTIVE_PER_DEVICE}
 AND (SELECT count(*) FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.group_id = p.group_id AND t.device_id = p.device_id AND t.created_at_ms > ?) < ${AUTH_LINK_MAX_CREATES_PER_DEVICE_WINDOW}
 AND (SELECT count(*) FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.group_id = p.group_id AND t.device_id = p.device_id AND t.created_at_ms > ?) < ${AUTH_LINK_MAX_CREATES_PER_DEVICE_RETENTION}
 AND (SELECT count(*) FROM (SELECT 1 FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = p.coordinator_id AND t.state NOT IN ('finalized','session_redeemed') LIMIT ${AUTH_LINK_MAX_UNFINISHED_PER_COORDINATOR})) < ${AUTH_LINK_MAX_UNFINISHED_PER_COORDINATOR}`,
			values: [
				...source.values,
				input.attemptId,
				c.revision,
				input.runtimeVerifierHash,
				input.loopbackRedirect,
				input.browserStartHash,
				now,
				now + 600000,
				history.link_id,
				history.generation,
				input.attemptId,
				input.attemptId,
				input.attemptId,
				now,
				now,
				now - AUTH_LINK_CREATE_WINDOW_MS,
				now - AUTH_LINK_RETENTION_WINDOW_MS,
			],
		});
		if (count !== 1) return { kind: "rejected", error: "attempt_unavailable" };
		return {
			kind: "created",
			identityId,
			status: { attemptId: input.attemptId, state: "pending", expiresAtMs: now + 600000 },
		};
	} catch {
		return { kind: "rejected", error: "attempt_unavailable" };
	}
}

/** Embed in browser/start/confirm CAS, not only a preliminary SELECT. */
export async function authLinkContinuationSource(
	backend: Pick<AuthLinkBackend, "first">,
	row: {
		identity_id: string;
		group_id: string;
		device_id: string;
		public_key: string;
		fingerprint: string;
	},
	attemptId: string,
	c: CoordinatorAuthLinkConfig,
	now: number,
	alias: "a" | "coordinator_auth_link_attempts",
): Promise<AuthLinkStatement> {
	const source = await captureAuthLinkContinuation(
		backend,
		{
			identityId: row.identity_id,
			attemptId,
			signer: {
				groupId: row.group_id,
				deviceId: row.device_id,
				publicKey: row.public_key,
				fingerprint: row.fingerprint,
			},
		},
		c,
		now,
	);
	if (!source) return { sql: "0 = 1", values: [] };
	return {
		sql: `EXISTS (${source.sql}, continuation_bound AS MATERIALIZED (
 SELECT 1 FROM continuation_target l JOIN continuation_requester p ON p.coordinator_id = l.coordinator_id
 WHERE ${alias}.coordinator_id = p.coordinator_id AND ${alias}.identity_id = p.identity_id AND ${alias}.group_id = p.group_id AND ${alias}.device_id = p.device_id
 AND ${alias}.public_key = p.public_key AND ${alias}.fingerprint = p.fingerprint AND ${alias}.issuer = p.issuer AND ${alias}.auth_config_revision = p.revision
 AND ${alias}.prior_link_id = l.link_id AND ${alias}.prior_generation = l.generation AND ${alias}.authority_kind = l.authority_kind)
 SELECT 1 FROM continuation_bound)`,
		values: source.values,
	};
}

function readContinuationFinalization(
	backend: Pick<AuthLinkBackend, "first">,
	i: CoordinatorAuthLinkFinalizeInput,
	c: CoordinatorAuthLinkConfig,
) {
	return backend.first<{
		identity_id: string;
		group_id: string;
		device_id: string;
		public_key: string;
		fingerprint: string;
		state: string;
		link_id: string;
		prior_link_id: string;
		prior_generation: number;
	}>({
		sql: "SELECT * FROM coordinator_auth_link_attempts WHERE coordinator_id = ? AND attempt_id = ? AND identity_id = ? AND group_id = ? AND device_id = ? AND public_key = ? AND fingerprint = ? AND issuer = ? AND auth_config_revision = ? AND runtime_verifier_hash = ? AND completion_secret_hash = ?",
		values: [
			c.coordinatorId,
			i.attemptId,
			i.identityId,
			i.groupId,
			i.deviceId,
			i.signer.publicKey,
			i.fingerprint,
			c.issuer,
			c.revision,
			i.runtimeVerifierHash,
			i.completionSecretHash,
		],
	});
}
export async function finalizeAuthLinkContinuation(
	backend: AuthLinkBackend,
	i: CoordinatorAuthLinkFinalizeInput,
	c: CoordinatorAuthLinkConfig,
	now: number,
	linkId: string,
): Promise<CoordinatorAuthLinkResult> {
	const row = await readContinuationFinalization(backend, i, c);
	if (!row) return { kind: "rejected", error: "attempt_unavailable" };
	if (row.state === "finalized" || row.state === "session_redeemed")
		return continuationReceipt(backend, i, c, row.link_id, "existing");
	const source = await authLinkContinuationSource(
		backend,
		row,
		i.attemptId,
		c,
		now,
		"coordinator_auth_link_attempts",
	);
	try {
		await backend.batch([
			{
				sql: `UPDATE coordinator_auth_link_attempts SET state = 'finalized', link_id = ?, finalized_at_ms = ?
 WHERE coordinator_id = ? AND attempt_id = ? AND identity_id = ? AND group_id = ? AND device_id = ? AND public_key = ? AND fingerprint = ?
 AND issuer = ? AND auth_config_revision = ? AND runtime_verifier_hash = ? AND completion_secret_hash = ? AND state = 'confirmed' AND expires_at_ms > ?
 AND created_at_ms <= claimed_at_ms AND claimed_at_ms <= oidc_verified_at_ms AND oidc_verified_at_ms <= confirmed_at_ms AND confirmed_at_ms <= ? AND ${source.sql}`,
				values: [
					linkId,
					now,
					c.coordinatorId,
					i.attemptId,
					i.identityId,
					i.groupId,
					i.deviceId,
					i.signer.publicKey,
					i.fingerprint,
					c.issuer,
					c.revision,
					i.runtimeVerifierHash,
					i.completionSecretHash,
					now,
					now,
					...source.values,
				],
			},
			assertAuthLinkChangeWrite(),
			...continuationBirthStatements(i, c, linkId, now),
			promoteAuthLinkProfile(c.coordinatorId, i.attemptId, linkId),
		]);
	} catch {
		return { kind: "rejected", error: "attempt_unavailable" };
	}
	return continuationReceipt(backend, i, c, linkId, "applied");
}
function continuationBirthStatements(
	i: CoordinatorAuthLinkFinalizeInput,
	c: CoordinatorAuthLinkConfig,
	linkId: string,
	now: number,
): AuthLinkStatement[] {
	const winner =
		"t.coordinator_id = ? AND t.attempt_id = ? AND t.state = 'finalized' AND t.link_id = ? AND t.finalized_at_ms = ?";
	const values = [c.coordinatorId, i.attemptId, linkId, now];
	return [
		{
			sql: `INSERT INTO coordinator_auth_account_associations (coordinator_id,issuer,subject,identity_id,first_link_id,created_at_ms) SELECT t.coordinator_id,t.issuer,t.account_subject,t.identity_id,t.link_id,t.finalized_at_ms FROM coordinator_auth_link_attempts t WHERE ${winner} AND NOT EXISTS (SELECT 1 FROM coordinator_auth_account_associations a WHERE a.coordinator_id = t.coordinator_id AND a.issuer = t.issuer AND a.subject = t.account_subject)`,
			values,
		},
		{
			sql: `INSERT INTO coordinator_auth_account_links (coordinator_id,link_id,issuer,subject,identity_id,attempt_id,controller_attestation_id,device_claim_id,auth_config_revision,created_at_ms,authority_kind,generation,signin_sequence_floor)
 SELECT t.coordinator_id,t.link_id,t.issuer,t.account_subject,t.identity_id,t.attempt_id,t.controller_attestation_id,prior.device_claim_id,t.auth_config_revision,t.finalized_at_ms,t.authority_kind,
 CASE WHEN prior.ended_at_ms IS NOT NULL AND prior.revoked_at_ms IS NULL AND prior.generation = t.prior_generation AND NOT EXISTS (SELECT 1 FROM coordinator_auth_account_links h WHERE h.coordinator_id = t.coordinator_id AND h.identity_id = t.identity_id AND (h.generation > prior.generation OR h.revoked_at_ms IS NOT NULL)) THEN prior.generation+1 END,
 coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'coordinator_auth_browser_transactions'),0)
 FROM coordinator_auth_link_attempts t JOIN coordinator_auth_account_links prior ON prior.coordinator_id = t.coordinator_id AND prior.link_id = t.prior_link_id AND prior.identity_id = t.identity_id WHERE ${winner}`,
			values,
		},
		assertAuthLinkChangeWrite(),
		{
			sql: `INSERT INTO coordinator_auth_link_audit_log (coordinator_id,link_id,action,attempt_id,identity_id,group_id,device_id,fingerprint,controller_attestation_id,device_claim_id,auth_config_revision,created_at_ms,authority_kind) SELECT t.coordinator_id,t.link_id,'link_created',t.attempt_id,t.identity_id,t.group_id,t.device_id,t.fingerprint,t.controller_attestation_id,l.device_claim_id,t.auth_config_revision,t.finalized_at_ms,t.authority_kind FROM coordinator_auth_link_attempts t JOIN coordinator_auth_account_links l ON l.coordinator_id = t.coordinator_id AND l.link_id = t.link_id WHERE ${winner}`,
			values,
		},
		assertAuthLinkChangeWrite(),
	];
}
async function continuationReceipt(
	backend: Pick<AuthLinkBackend, "first">,
	i: CoordinatorAuthLinkFinalizeInput,
	c: CoordinatorAuthLinkConfig,
	linkId: string,
	kind: "applied" | "existing",
): Promise<CoordinatorAuthLinkResult> {
	const receipt = await backend.first<{
		attempt_id: string;
		state: "finalized" | "session_redeemed";
		expires_at_ms: number;
	}>({
		sql: `SELECT t.attempt_id,t.state,t.expires_at_ms FROM coordinator_auth_link_attempts t JOIN coordinator_auth_account_links l ON l.coordinator_id = t.coordinator_id AND l.link_id = t.link_id JOIN coordinator_auth_link_audit_log a ON a.coordinator_id = l.coordinator_id AND a.link_id = l.link_id AND a.action = 'link_created' WHERE t.coordinator_id = ? AND t.attempt_id = ? AND t.link_id = ? AND l.attempt_id = t.attempt_id AND l.identity_id = t.identity_id AND l.generation = t.prior_generation+1 AND a.attempt_id = t.attempt_id`,
		values: [c.coordinatorId, i.attemptId, linkId],
	});
	if (!receipt) return { kind: "rejected", error: "attempt_unavailable" };
	return {
		kind,
		status: {
			attemptId: receipt.attempt_id,
			state: receipt.state,
			expiresAtMs: receipt.expires_at_ms,
		},
	};
}
