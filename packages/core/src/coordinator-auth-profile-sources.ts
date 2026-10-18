/** Fixed aliases for the two current profile readers. An empty newest snapshot
 * clears older display fields; field-by-field COALESCE would revive stale data.
 */
export const AUTH_PROFILE_SOURCE_FIELDS_SQL = [
	"display_name",
	"email",
	"email_verified",
	"picture_url",
]
	.map(
		(field) => `CASE
 WHEN r.source_order > coalesce(p.source_order,-1) AND r.source_order > coalesce(b.source_order,-1) THEN r.${field}
 WHEN p.source_order > coalesce(b.source_order,-1) THEN p.${field}
 ELSE b.${field} END AS ${field}`,
	)
	.join(",\n");

export const AUTH_PROFILE_SOURCE_JOINS_SQL = `LEFT JOIN coordinator_auth_account_profiles p
 ON p.coordinator_id = l.coordinator_id AND p.link_id = l.link_id
 LEFT JOIN coordinator_auth_link_profiles b ON b.coordinator_id = l.coordinator_id AND b.link_id = l.link_id
 AND b.source_purpose = 'link' AND b.attempt_id = l.attempt_id AND b.issuer = l.issuer
 AND b.subject = l.subject AND b.auth_config_revision = l.auth_config_revision
 LEFT JOIN coordinator_auth_link_profile_refreshes r ON r.coordinator_id = l.coordinator_id AND r.link_id = l.link_id
 AND EXISTS (SELECT 1 FROM coordinator_auth_link_change_attempts change_receipt
  WHERE change_receipt.coordinator_id = r.coordinator_id AND change_receipt.attempt_id = r.source_attempt_id
  AND change_receipt.state = 'completed' AND change_receipt.intent = 'refresh'
  AND change_receipt.target_link_id = l.link_id AND change_receipt.target_generation = l.generation
  AND change_receipt.identity_id = l.identity_id AND change_receipt.issuer = l.issuer
  AND change_receipt.target_subject = l.subject AND change_receipt.account_subject = l.subject
  AND change_receipt.browser_sequence + 1 = r.source_order AND change_receipt.oidc_verified_at_ms = r.verified_at_ms)`;
