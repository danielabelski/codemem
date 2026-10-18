import { captureAuthAccountProfile } from "./coordinator-auth-account-profile.js";
import type { AuthLinkStatement } from "./coordinator-auth-link.js";
import type {
	CoordinatorAuthLinkConfig,
	CoordinatorAuthLinkOidcInput,
} from "./coordinator-auth-link-contract.js";
import { authLinkLiveGenerationSql } from "./coordinator-auth-link-liveness.js";

/** Display metadata only. A nullable link_id separates staging from publication. */
export const AUTH_LINK_PROFILE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS coordinator_auth_link_profiles (
 coordinator_id TEXT NOT NULL,
 attempt_id TEXT NOT NULL,
 issuer TEXT NOT NULL,
 subject TEXT NOT NULL,
 auth_config_revision TEXT NOT NULL,
 browser_transaction_hash TEXT NOT NULL,
 link_id TEXT,
 display_name TEXT,
 email TEXT,
 email_verified INTEGER CHECK (email_verified IS NULL OR (email_verified IN (0,1) AND email IS NOT NULL)),
 picture_url TEXT,
 verified_at_ms INTEGER NOT NULL,
 PRIMARY KEY (coordinator_id, attempt_id),
 UNIQUE (coordinator_id, link_id)
);`;

/** Must immediately follow the verified OIDC update in the same atomic batch.
 * The native change count prevents same-timestamp replays from filling missing claims.
 */
export function stageAuthLinkProfile(
	i: CoordinatorAuthLinkOidcInput,
	c: CoordinatorAuthLinkConfig,
	now: number,
): AuthLinkStatement | null {
	const p = captureAuthAccountProfile(i.profile);
	if (!p) return null;
	let emailVerified: number | null = null;
	if (p.emailVerified !== undefined) emailVerified = Number(p.emailVerified);
	return {
		sql: `INSERT INTO coordinator_auth_link_profiles
 (coordinator_id,attempt_id,issuer,subject,auth_config_revision,browser_transaction_hash,
 display_name,email,email_verified,picture_url,verified_at_ms,source_order,source_purpose)
 SELECT t.coordinator_id,t.attempt_id,t.issuer,t.account_subject,t.auth_config_revision,t.browser_transaction_hash,?,?,?,?,t.oidc_verified_at_ms,proof.browser_sequence+1,'link'
  FROM coordinator_auth_link_attempts t JOIN coordinator_auth_browser_transactions proof
 ON proof.coordinator_id = t.coordinator_id AND proof.attempt_id = t.attempt_id
 AND proof.browser_transaction_hash = t.browser_transaction_hash AND proof.purpose = 'link'
 AND proof.state = 'consumed' AND proof.issuer = t.issuer AND proof.auth_config_revision = t.auth_config_revision
 WHERE changes() = 1 AND t.coordinator_id = ? AND t.attempt_id = ? AND t.issuer = ?
 AND t.account_subject = ? AND t.auth_config_revision = ? AND t.browser_transaction_hash = ?
 AND t.state = 'oidc_verified' AND t.oidc_verified_at_ms = ? AND t.expires_at_ms > ?
 ON CONFLICT(coordinator_id,attempt_id) DO NOTHING`,
		values: [
			p.displayName ?? null,
			p.email ?? null,
			emailVerified,
			p.pictureUrl ?? null,
			c.coordinatorId,
			i.attemptId,
			c.issuer,
			i.account.subject,
			c.revision,
			i.browserTransactionHash,
			now,
			now,
		],
	};
}

/** Append to the finalization batch after the link/audit inserts; conflicts roll back all writes. */
export function promoteAuthLinkProfile(
	coordinatorId: string,
	attemptId: string,
	linkId: string,
): AuthLinkStatement {
	return {
		sql: `UPDATE coordinator_auth_link_profiles AS p SET link_id = ? WHERE p.coordinator_id = ?
 AND p.attempt_id = ? AND p.link_id IS NULL AND p.source_purpose = 'link' AND EXISTS (
 SELECT 1 FROM coordinator_auth_link_attempts t JOIN coordinator_auth_account_links l
 ON l.coordinator_id = t.coordinator_id AND l.attempt_id = t.attempt_id AND l.link_id = t.link_id
 AND l.issuer = t.issuer AND l.subject = t.account_subject AND l.identity_id = t.identity_id
 AND l.auth_config_revision = t.auth_config_revision AND ${authLinkLiveGenerationSql({ link: "l" })}
 WHERE t.coordinator_id = p.coordinator_id AND t.attempt_id = p.attempt_id AND t.link_id = ?
 AND t.state = 'finalized' AND t.issuer = p.issuer AND t.account_subject = p.subject
 AND t.auth_config_revision = p.auth_config_revision AND t.browser_transaction_hash = p.browser_transaction_hash
 AND t.oidc_verified_at_ms = p.verified_at_ms AND EXISTS (
 SELECT 1 FROM coordinator_auth_browser_transactions proof
 WHERE proof.coordinator_id = t.coordinator_id AND proof.attempt_id = t.attempt_id AND proof.purpose = 'link'
 AND proof.state = 'consumed' AND proof.browser_transaction_hash = t.browser_transaction_hash
 AND proof.issuer = t.issuer AND proof.auth_config_revision = t.auth_config_revision
 AND p.source_order = proof.browser_sequence+1))`,
		values: [linkId, coordinatorId, attemptId, linkId],
	};
}

/** Delete private staging promptly on failure/expiry/config change, and published rows on revocation.
 * Publication never depends on cleanup having run. No authority records are modified.
 */
export function cleanAuthLinkProfiles(
	c: CoordinatorAuthLinkConfig,
	now: number,
	limit: number,
): AuthLinkStatement {
	return {
		sql: `DELETE FROM coordinator_auth_link_profiles WHERE coordinator_id = ? AND attempt_id IN (
 SELECT p.attempt_id FROM coordinator_auth_link_profiles p WHERE p.coordinator_id = ? AND (
 (p.link_id IS NULL AND (p.issuer <> ? OR p.auth_config_revision <> ? OR NOT (
 (p.source_purpose = 'link' AND EXISTS (SELECT 1 FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = p.coordinator_id
 AND t.attempt_id = p.attempt_id AND t.state IN ('oidc_verified','confirmed') AND t.expires_at_ms > ?))
 OR (p.source_purpose = 'link_change' AND EXISTS (SELECT 1 FROM coordinator_auth_link_change_attempts change_attempt
 JOIN coordinator_auth_account_links l ON l.coordinator_id = change_attempt.coordinator_id AND l.link_id = change_attempt.target_link_id
 WHERE change_attempt.coordinator_id = p.coordinator_id AND change_attempt.attempt_id = p.attempt_id
 AND change_attempt.state IN ('oidc_verified','confirmed') AND change_attempt.expires_at_ms > ?
 AND change_attempt.issuer = p.issuer AND change_attempt.account_subject = p.subject
 AND change_attempt.target_subject = p.subject AND change_attempt.target_generation = l.generation
 AND change_attempt.auth_config_revision = p.auth_config_revision
 AND change_attempt.browser_transaction_hash = p.browser_transaction_hash AND ${authLinkLiveGenerationSql({ link: "l" })})))))
 OR (p.link_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM coordinator_auth_account_links l
 WHERE l.coordinator_id = p.coordinator_id AND l.link_id = p.link_id AND l.attempt_id = p.attempt_id
 AND l.issuer = p.issuer AND l.subject = p.subject AND l.auth_config_revision = p.auth_config_revision
 AND ${authLinkLiveGenerationSql({ link: "l" })}))) LIMIT ?)`,
		values: [c.coordinatorId, c.coordinatorId, c.issuer, c.revision, now, now, limit],
	};
}
