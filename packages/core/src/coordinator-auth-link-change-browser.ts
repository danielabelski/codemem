import { captureAuthBrowserConfig } from "./coordinator-auth-browser-transaction.js";
import type { CoordinatorAuthBrowserConfig } from "./coordinator-auth-browser-transaction-contract.js";
import { isAuthControllerId } from "./coordinator-auth-controller.js";
import type { AuthLinkBackend } from "./coordinator-auth-link.js";
import { authLinkNow } from "./coordinator-auth-link.js";
import { assertAuthLinkChangeWrite } from "./coordinator-auth-link-change-effects.js";
import { capture, isHash } from "./coordinator-auth-link-input.js";

const ATTEMPTS = "coordinator_auth_link_change_attempts";
const TRANSACTIONS = "coordinator_auth_browser_transactions";
export interface AuthLinkChangeBrowserStart {
	attemptId: string;
	browserStartHash: string;
	stateHash: string;
	binderHash: string;
	nonce: string;
	pkceVerifier: string;
}
export interface AuthLinkChangeBrowserProof {
	attemptId: string;
	browserTransactionHash: string;
	binderHash: string;
	intent: "disconnect" | "refresh";
	destination: string;
}
export interface AuthLinkChangeBrowserStore {
	startAuthLinkChangeBrowser(
		input: AuthLinkChangeBrowserStart,
		config: CoordinatorAuthBrowserConfig,
	): Promise<boolean>;
	consumeAuthLinkChangeBrowser(
		input: { stateHash: string; binderHash: string },
		config: CoordinatorAuthBrowserConfig,
	): Promise<(AuthLinkChangeBrowserProof & { nonce: string; pkceVerifier: string }) | null>;
	resolveAuthLinkChangeBrowser(
		input: { binderHash: string },
		config: CoordinatorAuthBrowserConfig,
	): Promise<AuthLinkChangeBrowserProof | null>;
}
interface BrowserRow {
	attempt_id: string;
	browser_transaction_hash: string;
	binder_hash: string;
	intent: "disconnect" | "refresh";
	loopback_redirect: string;
	nonce: string;
	pkce_verifier: string;
}
function proof(row: BrowserRow): AuthLinkChangeBrowserProof {
	return {
		attemptId: row.attempt_id,
		browserTransactionHash: row.browser_transaction_hash,
		binderHash: row.binder_hash,
		intent: row.intent,
		destination: row.loopback_redirect,
	};
}
function configValues(c: CoordinatorAuthBrowserConfig) {
	return [c.coordinatorId, c.issuer, c.revision, c.redirectUri];
}
const MATCH_CONFIG =
	"b.coordinator_id = ? AND b.issuer = ? AND b.auth_config_revision = ? AND b.redirect_uri = ?";
const MATCH_ATTEMPT = `a.coordinator_id = b.coordinator_id AND a.attempt_id = b.attempt_id
 AND a.issuer = b.issuer AND a.auth_config_revision = b.auth_config_revision
 AND a.browser_transaction_hash = b.browser_transaction_hash AND a.browser_binder_hash = b.binder_hash
 AND a.browser_sequence = b.browser_sequence AND a.expires_at_ms > ?`;

function captureStart(value: unknown): AuthLinkChangeBrowserStart | null {
	const i = capture(value, [
		"attemptId",
		"browserStartHash",
		"stateHash",
		"binderHash",
		"nonce",
		"pkceVerifier",
	]);
	if (
		!i ||
		!isAuthControllerId(i.attemptId) ||
		!isHash(i.browserStartHash) ||
		!isHash(i.stateHash) ||
		!isHash(i.binderHash) ||
		typeof i.nonce !== "string" ||
		typeof i.pkceVerifier !== "string" ||
		!/^[A-Za-z0-9._~-]{43,128}$/.test(i.nonce) ||
		!/^[A-Za-z0-9._~-]{43,128}$/.test(i.pkceVerifier)
	)
		return null;
	return {
		attemptId: i.attemptId,
		browserStartHash: i.browserStartHash,
		stateHash: i.stateHash,
		binderHash: i.binderHash,
		nonce: i.nonce,
		pkceVerifier: i.pkceVerifier,
	};
}

/** Browser secrets stay in the shared ledger and are burned before OIDC exchange. */
export class AuthLinkChangeBrowserOperations implements AuthLinkChangeBrowserStore {
	constructor(
		private readonly backend: AuthLinkBackend,
		private readonly clock: () => number = Date.now,
	) {}
	async startAuthLinkChangeBrowser(
		input: AuthLinkChangeBrowserStart,
		config: CoordinatorAuthBrowserConfig,
	): Promise<boolean> {
		const c = captureAuthBrowserConfig(config);
		const i = captureStart(input);
		if (!c?.enabled || !i) return false;
		const now = authLinkNow(this.clock);
		const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
		const hash = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
		try {
			await this.backend.batch([
				{
					sql: `INSERT INTO ${TRANSACTIONS} (coordinator_id,browser_transaction_hash,purpose,attempt_id,state_hash,binder_hash,issuer,auth_config_revision,redirect_uri,state,nonce,pkce_verifier,created_at_ms,expires_at_ms)
 SELECT coordinator_id,?,'link_change',attempt_id,?,?,issuer,auth_config_revision,?,'pending',?,?,?,expires_at_ms FROM ${ATTEMPTS}
 WHERE coordinator_id = ? AND issuer = ? AND auth_config_revision = ? AND attempt_id = ? AND browser_start_hash = ? AND state = 'pending' AND expires_at_ms > ? AND origin = ?
 AND NOT EXISTS (SELECT 1 FROM coordinator_auth_link_attempts t WHERE t.coordinator_id = ${ATTEMPTS}.coordinator_id AND t.attempt_id = ${ATTEMPTS}.attempt_id)
 AND NOT EXISTS (SELECT 1 FROM coordinator_owner_enrollment_attempts t WHERE t.coordinator_id = ${ATTEMPTS}.coordinator_id AND t.attempt_id = ${ATTEMPTS}.attempt_id)`,
					values: [
						hash,
						String(i.stateHash),
						String(i.binderHash),
						c.redirectUri,
						i.nonce,
						i.pkceVerifier,
						now,
						c.coordinatorId,
						c.issuer,
						c.revision,
						i.attemptId,
						String(i.browserStartHash),
						now,
						new URL(c.redirectUri).origin,
					],
				},
				assertAuthLinkChangeWrite(),
				{
					sql: `UPDATE ${ATTEMPTS} SET state = 'browser_claimed', browser_transaction_hash = ?, browser_binder_hash = ?, browser_sequence = (SELECT browser_sequence FROM ${TRANSACTIONS} WHERE coordinator_id = ? AND browser_transaction_hash = ?), claimed_at_ms = ? WHERE coordinator_id = ? AND attempt_id = ? AND state = 'pending' AND expires_at_ms > ?`,
					values: [
						hash,
						String(i.binderHash),
						c.coordinatorId,
						hash,
						now,
						c.coordinatorId,
						i.attemptId,
						now,
					],
				},
				assertAuthLinkChangeWrite(),
			]);
			return true;
		} catch {
			return false;
		}
	}
	async consumeAuthLinkChangeBrowser(
		input: { stateHash: string; binderHash: string },
		config: CoordinatorAuthBrowserConfig,
	): Promise<(AuthLinkChangeBrowserProof & { nonce: string; pkceVerifier: string }) | null> {
		const c = captureAuthBrowserConfig(config);
		const i = capture(input, ["stateHash", "binderHash"]);
		if (!c?.enabled || !i || !isHash(i.stateHash) || !isHash(i.binderHash)) return null;
		const now = authLinkNow(this.clock);
		const row = await this.backend.first<BrowserRow>({
			sql: `SELECT b.*,a.intent,a.loopback_redirect FROM ${TRANSACTIONS} b JOIN ${ATTEMPTS} a ON ${MATCH_ATTEMPT} WHERE ${MATCH_CONFIG} AND b.purpose = 'link_change' AND b.state = 'pending' AND b.state_hash = ? AND b.binder_hash = ? AND b.created_at_ms <= ? AND b.expires_at_ms > ? AND a.state = 'browser_claimed'`,
			values: [now, ...configValues(c), i.stateHash, i.binderHash, now, now],
		});
		if (!row) return null;
		const token = globalThis.crypto.randomUUID();
		const count = await this.backend.run({
			sql: `UPDATE ${TRANSACTIONS} AS b SET state = 'consumed', nonce = NULL, pkce_verifier = NULL, claim_token = ?, consumed_at_ms = ? WHERE ${MATCH_CONFIG} AND b.purpose = 'link_change' AND b.browser_transaction_hash = ? AND b.state_hash = ? AND b.binder_hash = ? AND b.state = 'pending' AND b.nonce = ? AND b.pkce_verifier = ? AND b.expires_at_ms > ? AND EXISTS (SELECT 1 FROM ${ATTEMPTS} a WHERE ${MATCH_ATTEMPT} AND a.state = 'browser_claimed')`,
			values: [
				token,
				now,
				...configValues(c),
				row.browser_transaction_hash,
				i.stateHash,
				i.binderHash,
				row.nonce,
				row.pkce_verifier,
				now,
				now,
			],
		});
		return count === 1
			? { ...proof(row), nonce: row.nonce, pkceVerifier: row.pkce_verifier }
			: null;
	}
	async resolveAuthLinkChangeBrowser(
		input: { binderHash: string },
		config: CoordinatorAuthBrowserConfig,
	): Promise<AuthLinkChangeBrowserProof | null> {
		const c = captureAuthBrowserConfig(config);
		const i = capture(input, ["binderHash"]);
		if (!c?.enabled || !isHash(i?.binderHash)) return null;
		const now = authLinkNow(this.clock);
		const row = await this.backend.first<BrowserRow>({
			sql: `SELECT b.*,a.intent,a.loopback_redirect FROM ${TRANSACTIONS} b JOIN ${ATTEMPTS} a ON ${MATCH_ATTEMPT} WHERE ${MATCH_CONFIG} AND b.purpose = 'link_change' AND b.state = 'consumed' AND b.binder_hash = ? AND a.state IN ('oidc_verified','confirmed')`,
			values: [now, ...configValues(c), i.binderHash],
		});
		return row ? proof(row) : null;
	}
}
