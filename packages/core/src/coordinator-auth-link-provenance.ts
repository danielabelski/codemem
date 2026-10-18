/** Trusted SQL aliases only. Historical ownership is independent of current enrollment.
 * The immutable proof's key ID was derived at commit. Signed-device receipts also
 * pass a freshly derived canonical key ID; account sessions need no current key.
 * Link revocation is deliberately checked by the caller, including post-revoke audit.
 */
export function authDeviceClaimGenesisSql(options: {
	link: "l" | "cl" | "genesis";
	canonicalKeyId?: "?";
}): string {
	// Keep provenance independent of the outer session/browser expression tree.
	// Native D1 limits expression depth to 100, including correlated subqueries.
	const l = "pl";
	return `EXISTS (WITH committed_claim AS MATERIALIZED (
 SELECT ct.coordinator_id, ct.link_id, cd.key_id FROM coordinator_auth_link_attempts ct
 JOIN coordinator_auth_account_links pl ON pl.coordinator_id = ct.coordinator_id AND pl.link_id = ct.link_id
 JOIN coordinator_auth_device_claims cd ON cd.coordinator_id = ct.coordinator_id AND cd.claim_id = ${l}.device_claim_id
 JOIN coordinator_auth_link_audit_log ca ON ca.coordinator_id = ct.coordinator_id AND ca.link_id = ct.link_id AND ca.action = 'link_created'
 WHERE ct.coordinator_id = ${options.link}.coordinator_id AND ct.link_id = ${options.link}.link_id
 AND ct.attempt_id = ${l}.attempt_id
 AND ct.authority_kind = 'device_claim' AND ct.controller_attestation_id IS NULL
 AND ct.controller_review_receipt_id IS NULL AND ct.controller_revision IS NULL AND ct.state IN ('finalized','session_redeemed')
 AND ${l}.authority_kind = 'device_claim' AND ${l}.controller_attestation_id IS NULL
 AND ct.identity_id = ${l}.identity_id AND ct.issuer = ${l}.issuer AND ct.account_subject = ${l}.subject
 AND ct.auth_config_revision = ${l}.auth_config_revision AND ct.finalized_at_ms = ${l}.created_at_ms
 AND ct.browser_transaction_hash IS NOT NULL AND ct.browser_start_hash IS NOT NULL
 AND ct.runtime_verifier_hash IS NOT NULL AND ct.completion_secret_hash IS NOT NULL
 AND ct.created_at_ms <= ct.claimed_at_ms AND ct.claimed_at_ms <= ct.oidc_verified_at_ms
 AND ct.oidc_verified_at_ms <= ct.confirmed_at_ms AND ct.confirmed_at_ms <= ct.finalized_at_ms AND ct.finalized_at_ms < ct.expires_at_ms
 AND cd.attempt_id = ct.attempt_id AND cd.identity_id = ct.identity_id AND cd.group_id = ct.group_id AND cd.device_id = ct.device_id
 AND cd.public_key = ct.public_key AND cd.fingerprint = ct.fingerprint
 AND cd.issuer = ct.issuer AND cd.auth_config_revision = ct.auth_config_revision AND cd.created_at_ms = ct.finalized_at_ms
 AND ca.authority_kind = 'device_claim' AND ca.controller_attestation_id IS NULL AND ca.device_claim_id IS ${l}.device_claim_id
 AND ca.attempt_id = ct.attempt_id AND ca.identity_id = ct.identity_id AND ca.group_id = ct.group_id AND ca.device_id = ct.device_id
 AND ca.fingerprint = ct.fingerprint AND ca.auth_config_revision = ct.auth_config_revision AND ca.created_at_ms = ct.finalized_at_ms)
 SELECT 1 FROM committed_claim cp WHERE cp.coordinator_id = ${options.link}.coordinator_id AND cp.link_id = ${options.link}.link_id
 ${options.canonicalKeyId ? `AND cp.key_id = ${options.canonicalKeyId}` : ""})`;
}

/** Continuations reuse the original complete genesis proof. Birth revisions and
 * the original group remain historical; the new attempt/audit pin current ones.
 */
export function authDeviceClaimProvenanceSql(options: {
	link: "l" | "cl";
	canonicalKeyId?: "?";
}): string {
	return `((${options.link}.generation = 1 AND ${authDeviceClaimGenesisSql(options)}) OR
 (${options.link}.generation > 1 AND EXISTS (WITH continuation AS MATERIALIZED (
 SELECT nl.coordinator_id,nl.link_id,d.key_id FROM coordinator_auth_account_links nl
 JOIN coordinator_auth_link_attempts t ON t.coordinator_id = nl.coordinator_id AND t.attempt_id = nl.attempt_id AND t.link_id = nl.link_id
 JOIN coordinator_auth_device_claims d ON d.coordinator_id = nl.coordinator_id AND d.claim_id = nl.device_claim_id
 JOIN coordinator_auth_account_links genesis ON genesis.coordinator_id = d.coordinator_id AND genesis.device_claim_id = d.claim_id AND genesis.attempt_id = d.attempt_id AND genesis.generation = 1
 JOIN coordinator_auth_account_links prior ON prior.coordinator_id = nl.coordinator_id AND prior.link_id = t.prior_link_id
 JOIN coordinator_auth_link_audit_log a ON a.coordinator_id = nl.coordinator_id AND a.link_id = nl.link_id AND a.action = 'link_created'
 WHERE nl.coordinator_id = ${options.link}.coordinator_id AND nl.link_id = ${options.link}.link_id
 AND nl.authority_kind = 'device_claim' AND nl.controller_attestation_id IS NULL
 AND t.authority_kind = 'device_claim' AND t.controller_attestation_id IS NULL AND t.controller_review_receipt_id IS NULL AND t.controller_revision IS NULL
 AND t.state IN ('finalized','session_redeemed') AND t.identity_id = nl.identity_id AND t.issuer = nl.issuer
 AND t.account_subject = nl.subject AND t.auth_config_revision = nl.auth_config_revision AND t.finalized_at_ms = nl.created_at_ms
 AND t.browser_transaction_hash IS NOT NULL AND t.browser_start_hash IS NOT NULL AND t.runtime_verifier_hash IS NOT NULL AND t.completion_secret_hash IS NOT NULL
 AND t.created_at_ms <= t.claimed_at_ms AND t.claimed_at_ms <= t.oidc_verified_at_ms AND t.oidc_verified_at_ms <= t.confirmed_at_ms
 AND t.confirmed_at_ms <= t.finalized_at_ms AND t.finalized_at_ms < t.expires_at_ms
 AND d.identity_id = t.identity_id AND d.device_id = t.device_id AND d.public_key = t.public_key AND d.fingerprint = t.fingerprint AND d.issuer = t.issuer
 AND ${authDeviceClaimGenesisSql({ link: "genesis" })}
 AND prior.identity_id = nl.identity_id AND prior.generation = t.prior_generation AND prior.generation = nl.generation-1
 AND prior.ended_at_ms IS NOT NULL AND prior.end_reason = 'user_disconnected'
 AND a.attempt_id = t.attempt_id AND a.identity_id = t.identity_id AND a.group_id = t.group_id AND a.device_id = t.device_id
 AND a.fingerprint = t.fingerprint AND a.device_claim_id = d.claim_id AND a.authority_kind = 'device_claim' AND a.controller_attestation_id IS NULL
 AND a.auth_config_revision = t.auth_config_revision AND a.created_at_ms = t.finalized_at_ms)
 SELECT 1 FROM continuation cp WHERE cp.coordinator_id = ${options.link}.coordinator_id AND cp.link_id = ${options.link}.link_id
 ${options.canonicalKeyId ? "AND cp.key_id = ?" : ""})))`;
}

/** Account management only; privileged enrollment/grant proofs remain attested-only. */
export function authAccountLinkProvenanceSql(link: "l"): string {
	return `((${link}.authority_kind = 'controller_attestation' AND ${link}.controller_attestation_id IS NOT NULL AND ${link}.device_claim_id IS NULL)
 OR (${authDeviceClaimProvenanceSql({ link })}))`;
}
