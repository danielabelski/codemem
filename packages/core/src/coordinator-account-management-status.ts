import { captureAuthAccountProfile } from "./coordinator-auth-account-profile.js";
import { projectAccountProfileView } from "./coordinator-auth-browser-view.js";
import { isAuthControllerId } from "./coordinator-auth-controller.js";
import {
	AUTH_DEVICE_CLAIM_CURRENT_SUBJECT_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_ELIGIBLE_SQL,
	AUTH_DEVICE_CLAIM_INPUT_SQL,
	AUTH_DEVICE_CLAIM_LEGACY_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_REQUESTER_ATTESTATION_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_REQUESTER_INVITE_COMPATIBLE_SQL,
	AUTH_DEVICE_CLAIM_REQUESTER_LINK_COMPATIBLE_SQL,
	captureDeviceClaimEligibility,
} from "./coordinator-auth-device-claim-eligibility.js";
import { AUTH_CURRENT_LEGACY_ASSIGNMENT_SQL } from "./coordinator-auth-legacy-assignment.js";
import type { AuthLinkBackend } from "./coordinator-auth-link.js";
import {
	AUTH_LINK_CONTROLLER_SOURCE_SQL,
	authLinkControllerSourceValues,
	authLinkNow,
} from "./coordinator-auth-link.js";
import type { CoordinatorAuthLinkAuthorityKind } from "./coordinator-auth-link-authority.js";
import {
	AUTH_LINK_CHANGE_REQUESTER_SQL,
	AUTH_LINK_CHANGE_TARGET_SQL,
} from "./coordinator-auth-link-change-authority.js";
import { AUTH_LINK_CONTINUATION_PRIOR_SQL } from "./coordinator-auth-link-continuation.js";
import type {
	CoordinatorAuthLinkConfig,
	CoordinatorAuthLinkSigner,
} from "./coordinator-auth-link-contract.js";
import { captureAuthLinkConfig, captureAuthLinkSigner } from "./coordinator-auth-link-input.js";
import { authLinkLiveGenerationSql } from "./coordinator-auth-link-liveness.js";
import { authDeviceClaimProvenanceSql } from "./coordinator-auth-link-provenance.js";
import {
	AUTH_PROFILE_SOURCE_FIELDS_SQL,
	AUTH_PROFILE_SOURCE_JOINS_SQL,
	AUTH_PROFILE_SOURCE_VERIFIED_AT_SQL,
} from "./coordinator-auth-profile-sources.js";
import { ed25519KeyIdForRevocation } from "./coordinator-ed25519-key-id-compat.js";

export type CoordinatorAccountProfileV3 =
	| { state: "unavailable" }
	| {
			state: "verified";
			verifiedAtMs: number;
			displayName?: string;
			email?: string;
			pictureUrl?: string;
	  };
export interface CoordinatorAccountLinkStatusV3 {
	version: 3;
	coordinatorId: string;
	groupId: string;
	deviceId: string;
	fingerprint: string;
	identityId: string | null;
	authority: CoordinatorAuthLinkAuthorityKind | null;
	state: "unlinked" | "disconnected" | "linked" | "revoked" | "conflict" | "review_required";
	profile: CoordinatorAccountProfileV3;
	actions: { connect: boolean; disconnect: boolean; refresh: boolean };
}
interface StatusRow {
	identity_id: string;
	claim_count: number;
	controller_count: number;
	controller_identity: string | null;
	authority_kind: CoordinatorAuthLinkAuthorityKind;
	link_id: string | null;
	ended_at_ms: number | null;
	issuer: string | null;
	security_revoked: number;
	readable: number;
	manageable: number;
	display_name: string | null;
	email: string | null;
	email_verified: number | null;
	picture_url: string | null;
	verified_at_ms: number | null;
	reconnectable: number;
}
function conflictingClaim(row: StatusRow): boolean {
	return (
		row.claim_count > 0 &&
		(row.claim_count !== 1 ||
			row.readable !== 1 ||
			row.controller_count > 1 ||
			(row.controller_identity !== null && row.controller_identity !== row.identity_id))
	);
}

/** V3-only device-authenticated reader. Profiles and actions share its SQL snapshot. */
export class AccountManagementStatusOperations {
	constructor(
		private readonly backend: Pick<AuthLinkBackend, "first">,
		private readonly clock: () => number = Date.now,
	) {}
	async readAccountManagementStatus(
		signer: CoordinatorAuthLinkSigner,
		config: CoordinatorAuthLinkConfig,
		options: { identityId: string },
	): Promise<CoordinatorAccountLinkStatusV3> {
		const c = captureAuthLinkConfig(config);
		const s = captureAuthLinkSigner(signer);
		if (!c?.enabled || !s || !isAuthControllerId(options?.identityId))
			throw new Error("account_link_status_unavailable");
		const base: CoordinatorAccountLinkStatusV3 = {
			version: 3,
			coordinatorId: c.coordinatorId,
			groupId: s.groupId,
			deviceId: s.deviceId,
			fingerprint: s.fingerprint,
			identityId: null,
			authority: null,
			state: "review_required",
			profile: { state: "unavailable" },
			actions: { connect: false, disconnect: false, refresh: false },
		};
		const captured = await captureDeviceClaimEligibility(
			this.backend,
			{ signer: s, identityId: options.identityId },
			c,
			authLinkNow(this.clock),
		);
		if (!captured) return base;
		const keyId = await ed25519KeyIdForRevocation(s.publicKey);
		if (!keyId) return base;
		const row = await this.backend.first<StatusRow>({
			sql: `${AUTH_DEVICE_CLAIM_INPUT_SQL}, attested_reader AS MATERIALIZED (
 SELECT a.identity_id ${AUTH_LINK_CONTROLLER_SOURCE_SQL}
 AND NOT EXISTS (SELECT 1 FROM coordinator_device_revocations r
 WHERE (r.subject_kind = 'device_id' AND r.subject_value = a.device_id)
 OR (r.subject_kind = 'ed25519_key' AND r.subject_value = (SELECT key_id FROM claim_input)))),
 strict_requester AS MATERIALIZED (SELECT p.* FROM claim_input p WHERE ${AUTH_LINK_CHANGE_REQUESTER_SQL}),
 status_assignment AS MATERIALIZED (SELECT 1 FROM claim_input p
 WHERE (${AUTH_CURRENT_LEGACY_ASSIGNMENT_SQL} AND ${AUTH_DEVICE_CLAIM_LEGACY_COMPATIBLE_SQL})
 AND (${AUTH_DEVICE_CLAIM_CURRENT_SUBJECT_COMPATIBLE_SQL})
 AND (${AUTH_DEVICE_CLAIM_REQUESTER_ATTESTATION_COMPATIBLE_SQL} AND ${AUTH_DEVICE_CLAIM_REQUESTER_INVITE_COMPATIBLE_SQL})
 AND (${AUTH_DEVICE_CLAIM_REQUESTER_LINK_COMPATIBLE_SQL})),
 readable_claims AS MATERIALIZED (SELECT d.identity_id,l.link_id,l.issuer,l.ended_at_ms,
 CASE WHEN l.identity_id = d.identity_id AND EXISTS (
 SELECT 1 FROM enrolled_devices e JOIN groups g ON g.group_id = e.group_id
 WHERE e.group_id = p.group_id AND e.device_id = p.device_id AND e.public_key = p.public_key
 AND e.fingerprint = p.fingerprint AND e.enabled = 1 AND g.archived_at IS NULL
 AND (e.identity_id IS NULL OR e.identity_id = d.identity_id))
 AND NOT EXISTS (SELECT 1 FROM coordinator_device_revocations r
 WHERE (r.subject_kind = 'device_id' AND r.subject_value = p.device_id)
 OR (r.subject_kind = 'ed25519_key' AND r.subject_value = p.key_id))
 AND ((((l.generation = 1 AND d.group_id = p.group_id) OR (l.generation > 1 AND EXISTS (
 SELECT 1 FROM coordinator_auth_link_attempts current_scope WHERE current_scope.coordinator_id = l.coordinator_id
 AND current_scope.attempt_id = l.attempt_id AND current_scope.link_id = l.link_id AND current_scope.group_id = p.group_id)))
 AND d.device_id = p.device_id AND d.key_id = p.key_id AND d.fingerprint = p.fingerprint
 AND ${authDeviceClaimProvenanceSql({ link: "l", canonicalKeyId: "?" })})
 OR (d.identity_id = p.identity_id AND d.device_id <> p.device_id AND d.key_id <> p.key_id AND d.fingerprint <> p.fingerprint
 AND EXISTS (SELECT 1 FROM status_assignment) AND ${authDeviceClaimProvenanceSql({ link: "l" })}))
 THEN 1 ELSE 0 END AS readable
 FROM claim_input p JOIN coordinator_auth_device_claims d ON d.coordinator_id = p.coordinator_id
 LEFT JOIN coordinator_auth_account_links l ON l.coordinator_id = d.coordinator_id AND l.device_claim_id = d.claim_id
 AND l.generation = (SELECT max(latest.generation) FROM coordinator_auth_account_links latest WHERE latest.coordinator_id = d.coordinator_id AND latest.identity_id = d.identity_id)
 WHERE d.device_id = p.device_id OR d.key_id = p.key_id
 OR (d.identity_id = p.identity_id AND EXISTS (SELECT 1 FROM status_assignment))),
 read_candidates AS MATERIALIZED (
 SELECT *, 'device_claim' AS authority_kind FROM readable_claims
 UNION ALL SELECT a.identity_id,l.link_id,l.issuer,l.ended_at_ms,
 CASE WHEN l.link_id IS NULL AND EXISTS (SELECT 1 FROM coordinator_auth_account_links occupied
 WHERE occupied.coordinator_id = p.coordinator_id AND occupied.identity_id = a.identity_id) THEN 0 ELSE 1 END,'controller_attestation'
 FROM attested_reader a CROSS JOIN claim_input p LEFT JOIN coordinator_auth_account_links l
 ON l.coordinator_id = p.coordinator_id AND l.identity_id = a.identity_id AND l.authority_kind = 'controller_attestation'
 AND l.controller_attestation_id IS NOT NULL AND l.device_claim_id IS NULL
 AND l.generation = (SELECT max(latest.generation) FROM coordinator_auth_account_links latest WHERE latest.coordinator_id = p.coordinator_id AND latest.identity_id = a.identity_id)
 WHERE NOT EXISTS (SELECT 1 FROM readable_claims)
 UNION ALL SELECT p.identity_id,NULL,NULL,NULL,1,'device_claim' FROM claim_input p
 WHERE NOT EXISTS (SELECT 1 FROM readable_claims) AND NOT EXISTS (SELECT 1 FROM attested_reader)
 AND ${AUTH_DEVICE_CLAIM_ELIGIBLE_SQL}),
 history AS MATERIALIZED (SELECT l.* FROM read_candidates candidate CROSS JOIN claim_input p
 JOIN coordinator_auth_account_links l ON l.coordinator_id = p.coordinator_id AND l.link_id = candidate.link_id AND l.identity_id = candidate.identity_id),
 current_profile AS MATERIALIZED (SELECT l.link_id,${AUTH_PROFILE_SOURCE_FIELDS_SQL},${AUTH_PROFILE_SOURCE_VERIFIED_AT_SQL}
 FROM history l ${AUTH_PROFILE_SOURCE_JOINS_SQL}
 WHERE l.identity_id = (SELECT identity_id FROM claim_input) AND ${authLinkLiveGenerationSql({ link: "l" })})
 SELECT candidate.*, (SELECT count(*) FROM readable_claims) AS claim_count,
 (SELECT count(*) FROM attested_reader) AS controller_count,(SELECT identity_id FROM attested_reader LIMIT 1) AS controller_identity,
 EXISTS (SELECT 1 FROM coordinator_auth_account_links h WHERE h.coordinator_id = p.coordinator_id AND h.identity_id = candidate.identity_id AND h.revoked_at_ms IS NOT NULL) AS security_revoked,
 CASE WHEN l.link_id IS NULL OR candidate.identity_id <> p.identity_id OR NOT EXISTS (SELECT 1 FROM strict_requester) THEN 0 ELSE (${AUTH_LINK_CHANGE_TARGET_SQL}) END AS manageable,
 CASE WHEN l.link_id IS NULL OR candidate.identity_id <> p.identity_id OR NOT EXISTS (SELECT 1 FROM strict_requester) THEN 0 ELSE (${AUTH_LINK_CONTINUATION_PRIOR_SQL}) END AS reconnectable,
 m.display_name,m.email,m.email_verified,m.picture_url,m.verified_at_ms
 FROM read_candidates candidate CROSS JOIN claim_input p
 LEFT JOIN history l ON l.coordinator_id = p.coordinator_id AND l.link_id = candidate.link_id AND l.identity_id = candidate.identity_id
 LEFT JOIN current_profile m ON m.link_id = l.link_id LIMIT 1`,
			values: [...captured.values, ...authLinkControllerSourceValues(c, s), keyId],
		});
		if (row && conflictingClaim(row)) return { ...base, state: "conflict" };
		if (row?.readable !== 1) return base;
		if (row.controller_count > 1) return base;
		const derived = { ...base, identityId: row.identity_id, authority: row.authority_kind };
		if (row.security_revoked) return { ...derived, state: "revoked" };
		if (row.link_id === null && row.identity_id !== options.identityId) return base;
		if (row.link_id === null)
			return {
				...derived,
				state: "unlinked",
				actions: { connect: true, disconnect: false, refresh: false },
			};
		if (row.issuer !== c.issuer) return { ...base, state: "conflict" };
		if (row.ended_at_ms !== null)
			return {
				...derived,
				state: "disconnected",
				actions: { connect: row.reconnectable === 1, disconnect: false, refresh: false },
			};
		const profile = projectProfile(row, c.issuer);
		return {
			...derived,
			state: "linked",
			profile,
			actions: { connect: false, disconnect: row.manageable === 1, refresh: row.manageable === 1 },
		};
	}
}
function projectProfile(row: StatusRow, issuer: string): CoordinatorAccountProfileV3 {
	if (
		row.verified_at_ms === null ||
		!Number.isSafeInteger(row.verified_at_ms) ||
		row.verified_at_ms < 0
	)
		return { state: "unavailable" };
	const view = projectAccountProfileView(
		{
			displayName: row.display_name,
			email: row.email_verified === 1 ? row.email : undefined,
			pictureUrl: row.picture_url,
			emailVerified: row.email_verified === 1,
		},
		issuer,
	);
	const captured = captureAuthAccountProfile({ displayName: row.display_name });
	return {
		state: "verified",
		verifiedAtMs: row.verified_at_ms,
		...(captured?.displayName ? { displayName: captured.displayName } : {}),
		...(view.email ? { email: view.email } : {}),
		...(view.pictureUrl ? { pictureUrl: view.pictureUrl } : {}),
	};
}
