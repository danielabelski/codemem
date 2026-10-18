import type { AuthLinkStatement } from "./coordinator-auth-link.js";
import { AUTH_LINK_CHANGE_PURPOSE } from "./coordinator-auth-link-change-contract.js";

export const AUTH_LINK_CHANGE_TABLE = "coordinator_auth_link_change_attempts";

/** The malformed birth aborts the whole native SQLite/D1 batch, never just the
 * last statement. Keep this assertion immediately after its winning write.
 */
export function assertAuthLinkChangeWrite(): AuthLinkStatement {
	return {
		sql: `INSERT INTO ${AUTH_LINK_CHANGE_TABLE} (purpose) SELECT '${AUTH_LINK_CHANGE_PURPOSE}' WHERE changes() <> 1`,
		values: [],
	};
}

function assertRefreshPublished(coordinatorId: string, attemptId: string): AuthLinkStatement {
	return {
		sql: `INSERT INTO ${AUTH_LINK_CHANGE_TABLE} (purpose) SELECT '${AUTH_LINK_CHANGE_PURPOSE}' WHERE NOT EXISTS (
 SELECT 1 FROM ${AUTH_LINK_CHANGE_TABLE} a JOIN coordinator_auth_link_profiles p
 ON p.coordinator_id = a.coordinator_id AND p.attempt_id = a.attempt_id AND p.source_purpose = 'link_change'
 JOIN coordinator_auth_link_profile_refreshes r ON r.coordinator_id = a.coordinator_id AND r.link_id = a.target_link_id
 JOIN ${AUTH_LINK_CHANGE_TABLE} retained ON retained.coordinator_id = r.coordinator_id AND retained.attempt_id = r.source_attempt_id
 WHERE a.coordinator_id = ? AND a.attempt_id = ? AND a.state = 'completed' AND a.intent = 'refresh'
 AND retained.state = 'completed' AND retained.intent = 'refresh' AND retained.target_link_id = r.link_id
 AND retained.browser_sequence+1 = r.source_order AND retained.oidc_verified_at_ms = r.verified_at_ms
 AND (r.source_order > p.source_order OR (r.source_order = p.source_order AND r.source_attempt_id = p.attempt_id
 AND r.verified_at_ms = p.verified_at_ms AND r.display_name IS p.display_name AND r.email IS p.email
 AND r.email_verified IS p.email_verified AND r.picture_url IS p.picture_url)))`,
		values: [coordinatorId, attemptId],
	};
}

function assertDisconnectPurged(
	coordinatorId: string,
	linkId: string,
	attemptId: string,
): AuthLinkStatement {
	return {
		sql: `INSERT INTO ${AUTH_LINK_CHANGE_TABLE} (purpose) SELECT '${AUTH_LINK_CHANGE_PURPOSE}' WHERE
 EXISTS (SELECT 1 FROM coordinator_auth_sessions WHERE coordinator_id = ? AND link_id = ? AND revoked_at_ms IS NULL)
 OR EXISTS (SELECT 1 FROM coordinator_auth_account_profiles WHERE coordinator_id = ? AND link_id = ?)
 OR EXISTS (SELECT 1 FROM coordinator_auth_link_profiles WHERE coordinator_id = ? AND (link_id = ? OR (attempt_id = ? AND source_purpose = 'link_change')))
 OR EXISTS (SELECT 1 FROM coordinator_auth_link_profile_refreshes WHERE coordinator_id = ? AND link_id = ?)`,
		values: [
			coordinatorId,
			linkId,
			coordinatorId,
			linkId,
			coordinatorId,
			linkId,
			attemptId,
			coordinatorId,
			linkId,
		],
	};
}

export function authLinkChangeEffects(input: {
	coordinatorId: string;
	attemptId: string;
	targetLinkId: string;
	targetGeneration: number;
	intent: "disconnect" | "refresh";
	now: number;
}): AuthLinkStatement[] {
	const { coordinatorId, attemptId, targetLinkId, targetGeneration, intent, now } = input;
	const target = [coordinatorId, targetLinkId];
	if (intent === "refresh")
		return [
			{
				sql: `INSERT INTO coordinator_auth_link_profile_refreshes (coordinator_id,link_id,display_name,email,email_verified,picture_url,source_attempt_id,verified_at_ms,source_order)
 SELECT p.coordinator_id,a.target_link_id,p.display_name,p.email,p.email_verified,p.picture_url,p.attempt_id,p.verified_at_ms,p.source_order FROM coordinator_auth_link_profiles p JOIN ${AUTH_LINK_CHANGE_TABLE} a ON a.coordinator_id = p.coordinator_id AND a.attempt_id = p.attempt_id
 WHERE a.coordinator_id = ? AND a.attempt_id = ? AND a.state = 'completed' AND a.intent = 'refresh' AND p.source_purpose = 'link_change' AND p.link_id IS NULL
 ON CONFLICT(coordinator_id,link_id) DO UPDATE SET display_name=excluded.display_name,email=excluded.email,email_verified=excluded.email_verified,picture_url=excluded.picture_url,source_attempt_id=excluded.source_attempt_id,verified_at_ms=excluded.verified_at_ms,source_order=excluded.source_order WHERE excluded.source_order > coordinator_auth_link_profile_refreshes.source_order`,
				values: [coordinatorId, attemptId],
			},
			assertRefreshPublished(coordinatorId, attemptId),
			{
				sql: "DELETE FROM coordinator_auth_link_profiles WHERE coordinator_id = ? AND attempt_id = ? AND source_purpose = 'link_change' AND link_id IS NULL",
				values: [coordinatorId, attemptId],
			},
			assertAuthLinkChangeWrite(),
		];
	return [
		{
			sql: "UPDATE coordinator_auth_account_links SET ended_at_ms = ?, end_reason = 'user_disconnected', end_attempt_id = ? WHERE coordinator_id = ? AND link_id = ? AND generation = ? AND ended_at_ms IS NULL AND revoked_at_ms IS NULL",
			values: [now, attemptId, ...target, targetGeneration],
		},
		assertAuthLinkChangeWrite(),
		{
			sql: "UPDATE coordinator_auth_sessions SET revoked_at_ms = ? WHERE coordinator_id = ? AND link_id = ? AND revoked_at_ms IS NULL",
			values: [now, ...target],
		},
		...["coordinator_auth_account_profiles", "coordinator_auth_link_profile_refreshes"].map(
			(table) => ({
				sql: `DELETE FROM ${table} WHERE coordinator_id = ? AND link_id = ?`,
				values: target,
			}),
		),
		{
			sql: "DELETE FROM coordinator_auth_link_profiles WHERE coordinator_id = ? AND (link_id = ? OR (attempt_id = ? AND source_purpose = 'link_change'))",
			values: [...target, attemptId],
		},
		assertDisconnectPurged(coordinatorId, targetLinkId, attemptId),
	];
}
