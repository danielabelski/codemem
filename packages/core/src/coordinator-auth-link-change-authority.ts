import {
	AUTH_DEVICE_CLAIM_CURRENT_SUBJECT_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_INPUT_SQL,
	AUTH_DEVICE_CLAIM_LEGACY_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_REQUESTER_ATTESTATION_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_REQUESTER_INVITE_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_REQUESTER_LINK_COMPATIBLE_SQL,
	captureDeviceClaimEligibility,
} from "./coordinator-auth-device-claim-eligibility.js";
import type { AuthLinkBackend, AuthLinkStatement } from "./coordinator-auth-link.js";
import type {
	CoordinatorAuthLinkConfig,
	CoordinatorAuthLinkSigner,
} from "./coordinator-auth-link-contract.js";
import { authLinkLiveGenerationSql } from "./coordinator-auth-link-liveness.js";
import { authDeviceClaimProvenanceSql } from "./coordinator-auth-link-provenance.js";

/** Current requester checks, not first-claim admission. A historical claim cannot
 * mint ownership, grants, invitations, or a second genesis claim through this path.
 */
export const AUTH_LINK_CHANGE_REQUESTER_SQL = `EXISTS (
 SELECT 1 FROM enrolled_devices e JOIN groups g ON g.group_id = e.group_id
 WHERE e.group_id = p.group_id AND e.device_id = p.device_id AND e.public_key = p.public_key
 AND e.fingerprint = p.fingerprint AND e.enabled = 1 AND g.archived_at IS NULL
 AND (e.identity_id = p.identity_id OR (e.identity_id IS NULL AND p.assignment_snapshot IS NOT NULL)))
 AND NOT EXISTS (SELECT 1 FROM coordinator_device_revocations r
 WHERE (r.subject_kind = 'device_id' AND r.subject_value = p.device_id)
 OR (r.subject_kind = 'ed25519_key' AND r.subject_value = p.key_id))
 AND (${AUTH_DEVICE_CLAIM_CURRENT_SUBJECT_COMPATIBLE_SQL})
 AND (${AUTH_DEVICE_CLAIM_REQUESTER_ATTESTATION_COMPATIBLE_SQL})
 AND (${AUTH_DEVICE_CLAIM_REQUESTER_INVITE_COMPATIBLE_SQL})
 AND (${AUTH_DEVICE_CLAIM_REQUESTER_LINK_COMPATIBLE_SQL})
 AND (${AUTH_DEVICE_CLAIM_LEGACY_COMPATIBLE_SQL})`;

export const AUTH_LINK_CHANGE_TARGET_SQL = `${authLinkLiveGenerationSql({ link: "l" })}
 AND l.coordinator_id = p.coordinator_id AND l.identity_id = p.identity_id AND l.issuer = p.issuer
 AND ((l.authority_kind = 'controller_attestation' AND EXISTS (
 SELECT 1 FROM coordinator_auth_controller_attestations a
 WHERE a.coordinator_id = p.coordinator_id AND a.identity_id = p.identity_id
 AND a.group_id = p.group_id AND a.device_id = p.device_id AND a.public_key = p.public_key
 AND a.fingerprint = p.fingerprint AND a.revoked_at IS NULL AND a.revision = 1))
 OR (l.authority_kind = 'device_claim' AND EXISTS (
 SELECT 1 FROM coordinator_auth_device_claims d WHERE d.coordinator_id = p.coordinator_id
 AND d.claim_id = l.device_claim_id AND d.identity_id = p.identity_id AND d.device_id = p.device_id
 AND d.public_key = p.public_key AND d.fingerprint = p.fingerprint AND d.key_id = p.key_id
 AND d.issuer = p.issuer) AND ${authDeviceClaimProvenanceSql({ link: "l" })}))`;

/** Capture key aliases and legacy assignment once, then recheck them inside CAS. */
export async function captureAuthLinkChangeAuthority(
	backend: Pick<AuthLinkBackend, "first">,
	input: { signer: CoordinatorAuthLinkSigner; identityId: string; attemptId: string },
	config: CoordinatorAuthLinkConfig,
	now: number,
): Promise<AuthLinkStatement | null> {
	const captured = await captureDeviceClaimEligibility(backend, input, config, now);
	if (!captured) return null;
	return {
		sql: `${AUTH_DEVICE_CLAIM_INPUT_SQL}, management_requester AS MATERIALIZED (
 SELECT p.* FROM claim_input p WHERE ${AUTH_LINK_CHANGE_REQUESTER_SQL}),
 management_target AS MATERIALIZED (SELECT l.* FROM management_requester p
 JOIN coordinator_auth_account_links l ON l.coordinator_id = p.coordinator_id
 WHERE ${AUTH_LINK_CHANGE_TARGET_SQL})`,
		values: captured.values,
	};
}
