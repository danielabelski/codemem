import type {
	CoordinatorAuthBrowserConfig,
	CoordinatorAuthBrowserTransactionStore,
} from "./coordinator-auth-browser-transaction-contract.js";
import {
	renderAuthBrowserNotice,
	renderAuthLinkChangeConfirmPage,
	renderAuthLinkCompletionHopPage,
} from "./coordinator-auth-browser-view.js";
import type {
	AuthLinkChangeBrowserProof,
	AuthLinkChangeBrowserStore,
} from "./coordinator-auth-link-change-browser.js";
import type { CoordinatorAuthLinkChangeStore } from "./coordinator-auth-link-change-contract.js";
import {
	encodeCoordinatorAuthProof32,
	hashCoordinatorAuthProofBytes32,
} from "./coordinator-auth-proof.js";
import type { CoordinatorBrowserAuthConfig } from "./coordinator-browser-auth-config.js";
import { captureCoordinatorBrowserAuthConfig } from "./coordinator-browser-auth-config.js";
import { readBrowserCookie } from "./coordinator-browser-credential.js";
import { type BrowserCsrfKey, issueBrowserCsrfToken } from "./coordinator-browser-csrf.js";
import { guardBrowserForm } from "./coordinator-browser-form-guard.js";
import { createCoordinatorBrowserLinkStart } from "./coordinator-browser-link-start.js";
import { snapshotBrowserRequest } from "./coordinator-browser-request.js";
import type { CoordinatorOidcOptions } from "./coordinator-oidc.js";
import { createCoordinatorOidcClient } from "./coordinator-oidc.js";
import type { InMemoryRequestRateLimiter } from "./request-rate-limit.js";

export type CoordinatorBrowserLinkChangeStore = AuthLinkChangeBrowserStore &
	CoordinatorAuthLinkChangeStore &
	Pick<CoordinatorAuthBrowserTransactionStore, "readAuthBrowserTransactionActivity">;
interface Input {
	config: CoordinatorBrowserAuthConfig;
	store: CoordinatorBrowserLinkChangeStore;
	csrfKey: BrowserCsrfKey;
	limiter: InMemoryRequestRateLimiter;
	oidcOptions?: CoordinatorOidcOptions;
}
type Settings = Extract<
	ReturnType<typeof captureCoordinatorBrowserAuthConfig>,
	{ kind: "enabled" }
>;
type Context = Input & { settings: Settings };
async function unavailable(status = 403) {
	const page = await renderAuthBrowserNotice("auth_unavailable");
	return new Response(page.body, { status, headers: page.headers });
}
async function failConsumedChange(
	context: Context,
	proof: AuthLinkChangeBrowserProof,
	status = 403,
): Promise<Response> {
	const failed = await context.store.failAuthLinkChangeAttempt(
		{
			attemptId: proof.attemptId,
			requester: { kind: "browser", browserTransactionHash: proof.browserTransactionHash },
			reason: "provider_failure",
		},
		context.settings.store,
	);
	if (failed.kind === "rejected" || failed.status.state !== "failed") return unavailable(503);
	return unavailable(status);
}
async function releaseCompletion(context: Context, proof: AuthLinkChangeBrowserProof) {
	const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
	const completionSecret = encodeCoordinatorAuthProof32(bytes);
	const completionSecretHash = await hashCoordinatorAuthProofBytes32(bytes);
	const page = await renderAuthLinkCompletionHopPage({
		destination: proof.destination,
		attemptId: proof.attemptId,
		completionSecret,
	});
	const written = await context.store.confirmAuthLinkChangeAttempt(
		{
			...proof,
			completionSecretHash,
			confirmation: proof.intent === "refresh" ? "verified_refresh" : "browser",
		},
		context.settings.store,
	);
	if (written.kind !== "applied") return unavailable();
	return new Response(page.body, { headers: page.headers });
}
async function post(
	context: Context,
	request: Request,
	clientKey: string,
	action: "confirm" | "cancel",
) {
	const snapshot = snapshotBrowserRequest(request);
	if (
		snapshot.url !== `${context.settings.publicOrigin}/auth/link-change/${action}` ||
		snapshot.method !== "POST"
	)
		return unavailable(404);
	const guard = await guardBrowserForm({
		request,
		clientKey,
		csrfKey: context.csrfKey,
		limiter: context.limiter,
		action: "transaction_attempt",
		scope: context.settings,
	});
	if (!guard.ok || guard.action !== "transaction_attempt") return unavailable();
	const proof = await context.store.resolveAuthLinkChangeBrowser(
		{ binderHash: guard.cookieHash },
		context.settings.store,
	);
	if (!proof || proof.attemptId !== guard.attemptId) return unavailable();
	if (action === "confirm") {
		if (proof.intent !== "disconnect") return unavailable();
		return releaseCompletion(context, proof);
	}
	const failed = await context.store.failAuthLinkChangeAttempt(
		{
			attemptId: proof.attemptId,
			requester: { kind: "browser", browserTransactionHash: proof.browserTransactionHash },
			reason: "cancelled",
		},
		context.settings.store,
	);
	if (failed.kind === "rejected") return unavailable();
	const page = await renderAuthBrowserNotice("link_cancelled");
	// Never clear a cookie from a cancellation/GET: a newer start may own it now.
	return new Response(page.body, { headers: page.headers });
}
async function callback(context: Context, request: Request) {
	const snapshot = snapshotBrowserRequest(request);
	const url = new URL(snapshot.url);
	const redirect = new URL(context.settings.store.redirectUri);
	if (
		snapshot.method !== "GET" ||
		url.origin !== redirect.origin ||
		url.pathname !== redirect.pathname ||
		snapshot.url.length > 8192 ||
		url.hash ||
		url.searchParams.getAll("state").length !== 1
	)
		return unavailable();
	const state = url.searchParams.get("state");
	if (!state || !/^[A-Za-z0-9._~-]{43,128}$/.test(state)) return unavailable();
	const cookie = await readBrowserCookie(snapshot.cookie, "transaction");
	if (cookie.kind !== "present") return unavailable();
	const stateHash = Array.from(
		new Uint8Array(
			await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(state)),
		),
		(b) => b.toString(16).padStart(2, "0"),
	).join("");
	const proof = await context.store.consumeAuthLinkChangeBrowser(
		{ stateHash, binderHash: cookie.cookieHash },
		context.settings.store,
	);
	if (!proof) return unavailable();
	const oidc = await createCoordinatorOidcClient(context.settings.oidc, context.oidcOptions);
	if (!oidc.ok) return failConsumedChange(context, proof, 503);
	const verified = await oidc.client.verifyCallback({
		callbackUrl: snapshot.url,
		material: { state, nonce: proof.nonce, pkceVerifier: proof.pkceVerifier },
	});
	if (!verified.ok) return failConsumedChange(context, proof);
	const recorded = await context.store.recordAuthLinkChangeOidcVerified(
		{ ...proof, account: verified.account, profile: verified.profile },
		context.settings.store,
	);
	if (recorded.kind !== "applied") return failConsumedChange(context, proof);
	if (proof.intent === "refresh") return releaseCompletion(context, proof);
	const csrfToken = await issueBrowserCsrfToken(
		context.csrfKey,
		cookie.secret,
		"transaction",
		context.settings,
	);
	const page = await renderAuthLinkChangeConfirmPage({
		attemptId: proof.attemptId,
		csrfToken,
		issuer: context.settings.store.issuer,
		profile: verified.profile,
	});
	return new Response(page.body, { headers: page.headers });
}

/** Reuses private-code entry, CSRF, cookie replacement and provider verification.
 * No website-session completion; only the signed runtime can publish a change.
 */
export interface CoordinatorBrowserLinkChangeHandlers {
	startPage(request: Request): Promise<{ response: Response }>;
	start(request: Request, clientKey: string): Promise<{ response: Response }>;
	confirm(request: Request, clientKey: string): Promise<{ response: Response }>;
	cancel(request: Request, clientKey: string): Promise<{ response: Response }>;
	callback(request: Request): Promise<Response>;
}
export async function createCoordinatorBrowserLinkChange(
	input: Input,
): Promise<CoordinatorBrowserLinkChangeHandlers> {
	const settings = captureCoordinatorBrowserAuthConfig(input.config);
	if (settings.kind !== "enabled") throw new Error("auth_link_change_unavailable");
	const context: Context = { ...input, settings };
	const start = await createCoordinatorBrowserLinkStart({
		...input,
		flow: "link_change",
		store: {
			readAuthBrowserTransactionActivity: input.store.readAuthBrowserTransactionActivity.bind(
				input.store,
			),
			async startAuthBrowserTransaction(i, config: CoordinatorAuthBrowserConfig) {
				if (i.purpose !== "link" || !i.browserStartHash)
					return { kind: "rejected", error: "invalid_input" };
				const started = await input.store.startAuthLinkChangeBrowser(
					{
						attemptId: i.attemptId,
						browserStartHash: i.browserStartHash,
						stateHash: i.stateHash,
						binderHash: i.binderHash,
						nonce: i.nonce,
						pkceVerifier: i.pkceVerifier,
					},
					config,
				);
				if (!started) return { kind: "rejected", error: "attempt_unavailable" };
				return { kind: "started", expiresAtMs: Date.now() + 600000 };
			},
		},
	});
	if (!start.ok) throw new Error("auth_link_change_unavailable");
	return {
		startPage: start.handlers.linkStartPage,
		start: start.handlers.linkStart,
		async confirm(request: Request, key: string) {
			try {
				return { response: await post(context, request, key, "confirm") };
			} catch {
				return { response: await unavailable(503) };
			}
		},
		async cancel(request: Request, key: string) {
			try {
				return { response: await post(context, request, key, "cancel") };
			} catch {
				return { response: await unavailable(503) };
			}
		},
		async callback(request: Request) {
			try {
				return await callback(context, request);
			} catch {
				return unavailable(503);
			}
		},
	};
}
