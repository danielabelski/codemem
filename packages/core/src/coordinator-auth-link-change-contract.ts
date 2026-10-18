import type { CoordinatorAuthBrowserConfig } from "./coordinator-auth-browser-transaction-contract.js";
import type {
	CoordinatorAuthLinkConfig,
	CoordinatorAuthLinkRequester,
	CoordinatorAuthLinkSigner,
} from "./coordinator-auth-link-contract.js";

export const AUTH_LINK_CHANGE_PURPOSE = "coordinator-account-link-change-v1";
export type CoordinatorAuthLinkChangeIntent = "disconnect" | "refresh";
export type CoordinatorAuthLinkChangeState =
	| "pending"
	| "browser_claimed"
	| "oidc_verified"
	| "confirmed"
	| "completed"
	| "failed"
	| "expired";
export interface CoordinatorAuthLinkChangeStatus {
	attemptId: string;
	intent: CoordinatorAuthLinkChangeIntent;
	state: CoordinatorAuthLinkChangeState;
	expiresAtMs: number;
}
export type CoordinatorAuthLinkChangeResult =
	| { kind: "applied" | "existing" | "created"; status: CoordinatorAuthLinkChangeStatus }
	| { kind: "rejected"; error: "attempt_unavailable" | "invalid_input" | "attempt_limited" };
export interface CoordinatorAuthLinkChangeCreateInput {
	attemptId: string;
	identityId: string;
	intent: CoordinatorAuthLinkChangeIntent;
	signer: CoordinatorAuthLinkSigner;
	runtimeVerifierHash: string;
	browserStartHash: string;
	loopbackRedirect: string;
}
export interface CoordinatorAuthLinkChangeBrowserInput {
	attemptId: string;
	browserTransactionHash: string;
	binderHash: string;
}
export interface CoordinatorAuthLinkChangeFinalizeInput {
	purpose: typeof AUTH_LINK_CHANGE_PURPOSE;
	coordinatorId: string;
	attemptId: string;
	groupId: string;
	identityId: string;
	deviceId: string;
	fingerprint: string;
	signer: CoordinatorAuthLinkSigner;
	runtimeVerifierHash: string;
	completionSecretHash: string;
}
export interface CoordinatorAuthLinkChangeStore {
	createAuthLinkChangeAttempt(
		input: CoordinatorAuthLinkChangeCreateInput,
		config: CoordinatorAuthBrowserConfig,
	): Promise<CoordinatorAuthLinkChangeResult>;
	getAuthLinkChangeAttemptStatus(
		attemptId: string,
		requester: CoordinatorAuthLinkRequester,
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeStatus | null>;
	recordAuthLinkChangeOidcVerified(
		input: CoordinatorAuthLinkChangeBrowserInput & {
			account: { issuer: string; subject: string };
			profile: unknown;
		},
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult>;
	confirmAuthLinkChangeAttempt(
		input: CoordinatorAuthLinkChangeBrowserInput & {
			completionSecretHash: string;
			confirmation: "browser" | "verified_refresh";
		},
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult>;
	finalizeAuthLinkChangeAttempt(
		input: CoordinatorAuthLinkChangeFinalizeInput,
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult>;
	failAuthLinkChangeAttempt(
		input: {
			attemptId: string;
			requester: CoordinatorAuthLinkRequester;
			reason: "cancelled" | "provider_failure";
		},
		config: CoordinatorAuthLinkConfig,
	): Promise<CoordinatorAuthLinkChangeResult>;
}
