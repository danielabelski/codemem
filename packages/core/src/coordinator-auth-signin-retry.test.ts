import { createHash, randomBytes } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { NOW } from "./coordinator-auth-link-test-fixtures.js";
import { linked } from "./coordinator-auth-session-test-fixtures.js";
import { setupStore } from "./coordinator-auth-store-test-fixtures.js";
import { createCoordinatorBrowserAuthCallback } from "./coordinator-browser-auth-callback.js";
import {
	BROWSER_COOKIE_NAMES,
	issueBrowserCookie,
	readBrowserCookie,
} from "./coordinator-browser-credential.js";
import { importBrowserCsrfKey, issueBrowserCsrfToken } from "./coordinator-browser-csrf.js";
import { createCoordinatorBrowserSigninStart } from "./coordinator-browser-signin-start.js";
import { createCoordinatorOidcClient } from "./coordinator-oidc.js";
import { oidcFixture, PROVIDER } from "./coordinator-oidc-test-fixtures.js";
import { createInMemoryRequestRateLimiter } from "./request-rate-limit.js";

const cfg = {
	enabled: true,
	coordinatorId: "coordinator-a",
	issuer: "https://accounts.google.com",
	revision: "a".repeat(64),
	redirectUri: PROVIDER.redirectUri,
};
const origin = new URL(cfg.redirectUri).origin;
const cleanups: (() => void)[] = [];
afterEach(() => {
	vi.restoreAllMocks();
	for (const close of cleanups.splice(0)) close();
});
async function setup(options: { internalError?: boolean } = {}) {
	vi.spyOn(Date, "now").mockReturnValue(NOW);
	const f = setupStore("SQLite", { authClock: () => NOW });
	cleanups.push(() => {
		if (f.db.open) f.db.close();
	});
	const oidc = oidcFixture({ issuer: cfg.issuer });
	oidc.claims.sub = "opaque-subject-a";
	const config = { ...cfg, clientId: PROVIDER.clientId, clientSecret: PROVIDER.clientSecret };
	const provider = await createCoordinatorOidcClient(config, { fetch: oidc.fetch });
	if (!provider.ok) throw new Error("Missing synthetic provider");
	const authorization = await provider.client.createAuthorizationRequest();
	const cookie = await issueBrowserCookie("transaction");
	const material = {
		purpose: "signin" as const,
		stateHash: createHash("sha256").update(authorization.material.state).digest("hex"),
		binderHash: cookie.cookieHash,
		nonce: authorization.material.nonce,
		pkceVerifier: authorization.material.pkceVerifier,
	};
	const csrfKey = await importBrowserCsrfKey(randomBytes(32));
	const start = await createCoordinatorBrowserSigninStart({
		config,
		store: f.store,
		csrfKey,
		limiter: createInMemoryRequestRateLimiter({ now: () => NOW }),
		oidcOptions: { fetch: oidc.fetch },
	});
	if (options.internalError)
		vi.spyOn(f.store, "signInWithConsumedBrowserTransaction").mockRejectedValue(
			new Error("Synthetic admission unavailable"),
		);
	const callback = await createCoordinatorBrowserAuthCallback({
		config,
		store: f.store,
		completeLink: async () => {
			throw new Error("Unexpected link dispatch");
		},
		oidcOptions: { fetch: oidc.fetch },
	});
	if (!start.ok || !callback.ok) throw new Error("Missing browser handlers");
	const callbackUrl = oidc.authorize(authorization.authorizationUrl);
	const header = cookie.setCookie.split(";")[0] ?? "";
	return {
		...f,
		oidc,
		material,
		cookie,
		header,
		callbackUrl,
		csrfKey,
		start: start.handlers,
		callback: callback.handlers,
	};
}
function post(cookie: string, csrf: string) {
	return new Request(`${origin}/auth/sign-in`, {
		method: "POST",
		headers: {
			Origin: origin,
			Cookie: cookie,
			"Content-Type": "application/x-www-form-urlencoded",
		},
		body: new URLSearchParams({ csrf }),
	});
}
async function retryWithOldCookie(f: Awaited<ReturnType<typeof setup>>) {
	const page = await f.start.signInPage(
		new Request(`${origin}/auth/sign-in`, { headers: { Cookie: f.header } }),
	);
	expect(page.response.status).toBe(200);
	expect(
		page.response.headers
			.getSetCookie()
			.some((cookie) => cookie.startsWith(`${BROWSER_COOKIE_NAMES.transaction}=`)),
	).toBe(false);
	const html = await page.response.text();
	const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
	const startCookie = page.response.headers
		.getSetCookie()
		.find((cookie) => cookie.startsWith(`${BROWSER_COOKIE_NAMES.start}=`))
		?.split(";")[0];
	if (!csrf || !startCookie) throw new Error("Missing credential-bearing retry form");
	const response = await f.start.signInStart(
		post(`${f.header}; ${startCookie}`, csrf),
		"retry-browser",
	);
	expect(response.response.status).toBe(200);
	const replacement = response.response.headers
		.getSetCookie()
		.find((cookie) => cookie.startsWith(`${BROWSER_COOKIE_NAMES.transaction}=`))
		?.split(";")[0];
	const cookie = await readBrowserCookie(replacement, "transaction");
	if (cookie.kind !== "present") throw new Error("Missing replacement transaction");
	expect(cookie.cookieHash).not.toBe(f.cookie.cookieHash);
	expect(
		response.response.headers
			.getSetCookie()
			.some((cookie) => cookie.startsWith(`${BROWSER_COOKIE_NAMES.session}=`)),
	).toBe(false);
}

it.each(["provider-denial", "unlinked-account", "revoked-admission", "internal-error"] as const)(
	"a consumed %s signin is terminal and permits credential-bearing retry with the same old cookie",
	async (failure) => {
		const f = await setup({ internalError: failure === "internal-error" });
		if (failure === "revoked-admission") {
			await linked({ ...f, now: NOW, cfg }, { signinProof: false });
			const link = f.db.prepare("SELECT link_id FROM coordinator_auth_account_links").get() as {
				link_id: string;
			};
			expect(await f.store.revokeAuthAccountLink({ linkId: link.link_id }, cfg)).toEqual({
				kind: "revoked",
			});
		}
		expect(await f.store.startAuthBrowserTransaction(f.material, cfg)).toMatchObject({
			kind: "started",
		});
		if (failure === "provider-denial") {
			f.callbackUrl.searchParams.delete("code");
			f.callbackUrl.searchParams.set("error", "access_denied");
		}
		const response = await f.callback.callback(
			new Request(f.callbackUrl, { headers: { Cookie: f.header } }),
		);
		expect(response.response.status).toBe(failure === "internal-error" ? 503 : 403);
		expect(response.response.headers.getSetCookie()).toEqual([]);
		expect(
			f.db
				.prepare(
					"SELECT state,nonce,pkce_verifier FROM coordinator_auth_browser_transactions WHERE binder_hash = ?",
				)
				.get(f.cookie.cookieHash),
		).toEqual({ state: "consumed", nonce: null, pkce_verifier: null });
		expect(f.db.prepare("SELECT * FROM coordinator_auth_session_receipts").all()).toEqual([]);
		expect(f.db.prepare("SELECT * FROM coordinator_auth_sessions").all()).toEqual([]);
		expect(
			await f.store.readAuthBrowserTransactionActivity({ binderHash: f.cookie.cookieHash }, cfg),
		).toEqual({ kind: "inactive" });
		const calls = f.oidc.fetch.mock.calls.length;
		const replay = await f.callback.callback(
			new Request(f.callbackUrl, { headers: { Cookie: f.header } }),
		);
		expect(replay.response.status).toBe(403);
		expect(replay.response.headers.getSetCookie()).toEqual([]);
		expect(f.oidc.fetch).toHaveBeenCalledTimes(calls);
		await retryWithOldCookie(f);
	},
);

it("pre-consumption signin stays active and blocks a competing start", async () => {
	const f = await setup();
	await f.store.startAuthBrowserTransaction(f.material, cfg);
	expect(
		await f.store.readAuthBrowserTransactionActivity({ binderHash: f.cookie.cookieHash }, cfg),
	).toEqual({ kind: "active" });
	const start = await issueBrowserCookie("start");
	const csrf = await issueBrowserCsrfToken(f.csrfKey, start.secret, "start", {
		publicOrigin: origin,
		store: cfg,
	});
	const response = await f.start.signInStart(
		post(`${f.header}; ${start.setCookie.split(";")[0]}`, csrf),
		"competing-browser",
	);
	expect(response.response.status).toBe(409);
	expect(response.response.headers.getSetCookie()).toEqual([]);
	expect(
		f.db
			.prepare("SELECT state,nonce,pkce_verifier FROM coordinator_auth_browser_transactions")
			.get(),
	).toEqual({ state: "pending", nonce: f.material.nonce, pkce_verifier: f.material.pkceVerifier });
});

it("consumption never bypasses coordinator, issuer, revision, redirect, or cookie validation", async () => {
	const f = await setup();
	await f.store.startAuthBrowserTransaction(f.material, cfg);
	expect(await f.store.consumeAuthBrowserTransaction(f.material, cfg)).toMatchObject({
		kind: "consumed",
	});
	for (const config of [
		{ ...cfg, coordinatorId: "other-coordinator" },
		{ ...cfg, issuer: "https://other.example.test" },
		{ ...cfg, revision: "f".repeat(64) },
		{ ...cfg, redirectUri: "https://other.example.test/auth/callback" },
	])
		expect(
			await f.store.readAuthBrowserTransactionActivity({ binderHash: f.cookie.cookieHash }, config),
		).toEqual({ kind: "rejected", error: "auth_config_changed" });
	expect(await f.store.readAuthBrowserTransactionActivity({ binderHash: "bad" }, cfg)).toEqual({
		kind: "rejected",
		error: "invalid_input",
	});
	const response = await f.start.signInPage(
		new Request(`${origin}/auth/sign-in`, {
			headers: { Cookie: `${BROWSER_COOKIE_NAMES.transaction}=bad` },
		}),
	);
	expect(response.response.status).toBe(400);
	expect(response.response.headers.getSetCookie()).toEqual([]);
});
