import { captureAuthAccountProfile } from "./coordinator-auth-account-profile.js";
import { projectAccountProfileView } from "./coordinator-auth-browser-view.js";
import { isAuthControllerId } from "./coordinator-auth-controller.js";
import {
	AUTH_DEVICE_CLAIM_ELIGIBLE_SQL,
	AUTH_DEVICE_CLAIM_INPUT_SQL,
	captureDeviceClaimEligibility,
} from "./coordinator-auth-device-claim-eligibility.js";
import type { AuthLinkBackend } from "./coordinator-auth-link.js";
import { authLinkNow } from "./coordinator-auth-link.js";
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
const CURRENT_ATTESTATION = `EXISTS (SELECT 1 FROM coordinator_auth_controller_attestations a
 WHERE a.coordinator_id = p.coordinator_id AND a.identity_id = p.identity_id AND a.group_id = p.group_id
 AND a.device_id = p.device_id AND a.public_key = p.public_key AND a.fingerprint = p.fingerprint
 AND a.revoked_at IS NULL AND a.revision = 1)`;
const ORIGINAL_DEVICE = `EXISTS (SELECT 1 FROM coordinator_auth_device_claims d
 WHERE d.coordinator_id = p.coordinator_id AND d.claim_id = l.device_claim_id AND d.identity_id = p.identity_id
 AND d.device_id = p.device_id AND d.public_key = p.public_key AND d.fingerprint = p.fingerprint AND d.key_id = p.key_id)`;

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
		const row = await this.backend.first<StatusRow>({
			sql: `${AUTH_DEVICE_CLAIM_INPUT_SQL}, requester AS MATERIALIZED (SELECT p.* FROM claim_input p WHERE (${AUTH_LINK_CHANGE_REQUESTER_SQL}) OR (${AUTH_DEVICE_CLAIM_ELIGIBLE_SQL})),
 history AS MATERIALIZED (SELECT l.* FROM requester p JOIN coordinator_auth_account_links l ON l.coordinator_id = p.coordinator_id AND l.identity_id = p.identity_id ORDER BY l.generation DESC LIMIT 1),
 snapshots AS MATERIALIZED (
 SELECT r.link_id,r.display_name,r.email,r.email_verified,r.picture_url,r.verified_at_ms,r.source_order FROM coordinator_auth_link_profile_refreshes r
 JOIN coordinator_auth_link_change_attempts receipt ON receipt.coordinator_id = r.coordinator_id
 AND receipt.attempt_id = r.source_attempt_id AND receipt.target_link_id = r.link_id
 AND receipt.state = 'completed' AND receipt.intent = 'refresh' AND receipt.browser_sequence+1 = r.source_order
 AND receipt.oidc_verified_at_ms = r.verified_at_ms WHERE r.coordinator_id = ?
 UNION ALL SELECT m.link_id,m.display_name,m.email,m.email_verified,m.picture_url,m.source_signed_in_at_ms,m.source_order FROM coordinator_auth_account_profiles m WHERE m.coordinator_id = ?
 UNION ALL SELECT b.link_id,b.display_name,b.email,b.email_verified,b.picture_url,b.verified_at_ms,b.source_order FROM coordinator_auth_link_profiles b WHERE b.coordinator_id = ? AND b.source_purpose = 'link' AND b.link_id IS NOT NULL),
 current_profile AS MATERIALIZED (SELECT m.* FROM snapshots m JOIN history l ON l.link_id = m.link_id WHERE ${authLinkLiveGenerationSql({ link: "l" })} ORDER BY m.source_order DESC LIMIT 1)
 SELECT l.link_id,l.ended_at_ms,l.issuer,
 CASE WHEN l.link_id IS NOT NULL THEN l.authority_kind WHEN ${CURRENT_ATTESTATION} THEN 'controller_attestation' ELSE 'device_claim' END AS authority_kind,
 EXISTS (SELECT 1 FROM coordinator_auth_account_links h WHERE h.coordinator_id = p.coordinator_id AND h.identity_id = p.identity_id AND h.revoked_at_ms IS NOT NULL) AS security_revoked,
 CASE WHEN l.link_id IS NULL THEN (${CURRENT_ATTESTATION} OR ${AUTH_DEVICE_CLAIM_ELIGIBLE_SQL})
 WHEN l.authority_kind = 'controller_attestation' THEN ${CURRENT_ATTESTATION}
 ELSE (${authDeviceClaimProvenanceSql({ link: "l" })} AND (${ORIGINAL_DEVICE} OR p.assignment_snapshot IS NOT NULL)) END AS readable,
 CASE WHEN l.link_id IS NULL THEN 0 ELSE (${AUTH_LINK_CHANGE_TARGET_SQL}) END AS manageable,
 CASE WHEN l.link_id IS NULL THEN 0 ELSE (${AUTH_LINK_CONTINUATION_PRIOR_SQL}) END AS reconnectable,
 m.display_name,m.email,m.email_verified,m.picture_url,m.verified_at_ms
 FROM requester p LEFT JOIN history l ON l.coordinator_id = p.coordinator_id LEFT JOIN current_profile m ON m.link_id = l.link_id`,
			values: [...captured.values, c.coordinatorId, c.coordinatorId, c.coordinatorId],
		});
		if (row?.readable !== 1) return base;
		const derived = { ...base, identityId: options.identityId, authority: row.authority_kind };
		if (row.security_revoked) return { ...derived, state: "revoked" };
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
