import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { browserCapability, TABLE } from "./coordinator-auth-browser-transaction-test-fixtures.js";
import { consumeSigninProof, NOW } from "./coordinator-auth-link-test-fixtures.js";
import { linked } from "./coordinator-auth-session-test-fixtures.js";
import { type Backend, setupStore } from "./coordinator-auth-store-test-fixtures.js";
import { createCoordinatorBrowserAuthCallback } from "./coordinator-browser-auth-callback.js";
import {
	BROWSER_COOKIE_NAMES,
	issueBrowserCookie,
	readBrowserCookie,
} from "./coordinator-browser-credential.js";
import { importBrowserCsrfKey } from "./coordinator-browser-csrf.js";
import { createCoordinatorBrowserSigninStart } from "./coordinator-browser-signin-start.js";
import { oidcFixture, PROVIDER } from "./coordinator-oidc-test-fixtures.js";

const ORIGIN = "https://app.example.test";
const config = () => ({
	enabled: true,
	coordinatorId: "coordinator-a",
	issuer: "https://accounts.google.com",
	redirectUri: PROVIDER.redirectUri,
	revision: "a".repeat(64),
	clientId: PROVIDER.clientId,
	clientSecret: PROVIDER.clientSecret,
});
function publicConfig() {
	const { clientId: _clientId, clientSecret: _clientSecret, ...publicValue } = config();
	return publicValue;
}
const databases: ReturnType<typeof setupStore>["db"][] = [];
beforeEach(() => {
	vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network forbidden"));
	vi.spyOn(Date, "now").mockReturnValue(NOW);
});
afterEach(() => {
	try {
		expect(globalThis.fetch).not.toHaveBeenCalled();
	} finally {
		vi.restoreAllMocks();
		for (const db of databases.splice(0)) db.close();
	}
});

async function harness(backend: Backend = "SQLite") {
	const f = setupStore(backend, { authClock: () => NOW });
	databases.push(f.db);
	const oidc = oidcFixture({ issuer: config().issuer });
	oidc.claims.sub = "opaque-subject-a";
	const store = {
		consumeAuthBrowserTransaction: vi.fn(f.store.consumeAuthBrowserTransaction.bind(f.store)),
		readAuthSession: vi.fn(f.store.readAuthSession.bind(f.store)),
		signInWithConsumedBrowserTransaction: vi.fn(
			f.store.signInWithConsumedBrowserTransaction.bind(f.store),
		),
		recordAuthAccountProfile: vi.fn(f.store.recordAuthAccountProfile.bind(f.store)),
	};
	const completeLink = vi.fn(async () => new Response("link", { status: 202 }));
	const input = { config: config(), store, completeLink, oidcOptions: { fetch: oidc.fetch } };
	const callback = await createCoordinatorBrowserAuthCallback(input);
	const start = await createCoordinatorBrowserSigninStart({
		config: config(),
		store: f.store,
		csrfKey: await importBrowserCsrfKey(new Uint8Array(32).fill(7)),
		limiter: { check: () => ({ allowed: true, retryAfterS: 0 }) },
		oidcOptions: { fetch: oidc.fetch },
	});
	if (!callback.ok || !start.ok) throw new Error("Expected actual SDK factories");
	oidc.fetch.mockClear();
	return {
		...f,
		now: NOW,
		cfg: config(),
		oidc,
		store,
		persistence: f.store,
		completeLink,
		input,
		callback: callback.handlers.callback,
		start: start.handlers,
	};
}
type Harness = Awaited<ReturnType<typeof harness>>;
function rows(f: Harness, table = TABLE) {
	return f.db.prepare(`SELECT * FROM ${table}`).all() as Record<string, unknown>[];
}
function authority(f: Harness, options: { browserAllocation?: boolean } = {}) {
	const tables = f.db
		.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
		.all() as { name: string }[];
	const allowed = new Set([
		TABLE,
		"coordinator_auth_sessions",
		"coordinator_auth_session_receipts",
		"coordinator_auth_account_profiles",
	]);
	return tables
		.filter(({ name }) => !allowed.has(name))
		.map(({ name }) => [
			name,
			rows(f, name).filter(
				(row) => !options.browserAllocation || name !== "sqlite_sequence" || row.name !== TABLE,
			),
		]);
}
async function ceremony(f: Harness) {
	const page = await f.start.signInPage(new Request(`${ORIGIN}/auth/sign-in`));
	const startCookie = page.response.headers.getSetCookie()[0]?.split(";")[0];
	const csrf = /name="csrf" value="([A-Za-z0-9_-]+)"/.exec(await page.response.text())?.[1];
	if (!startCookie || !csrf) throw new Error("Expected real HMAC ceremony");
	const start = await f.start.signInStart(
		new Request(`${ORIGIN}/auth/sign-in`, {
			method: "POST",
			headers: {
				cookie: startCookie,
				origin: ORIGIN,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: `csrf=${csrf}`,
		}),
		"trusted-client",
	);
	const href = /href="(https:\/\/accounts\.google\.com\/authorize[^"]+)"/.exec(
		await start.response.text(),
	)?.[1];
	const cookie = start.response.headers.getSetCookie()[0]?.split(";")[0];
	if (!href || !cookie) throw new Error("Expected admitted provider link and TXN cookie");
	const authorization = new URL(href.replaceAll("&amp;", "&"));
	const stateHash = createHash("sha256")
		.update(authorization.searchParams.get("state") ?? "")
		.digest("hex");
	const original = rows(f).find((row) => row.state_hash === stateHash);
	if (!original) throw new Error("Expected matching transaction row");
	return {
		cookie,
		startCookie,
		csrf,
		response: start.response,
		authorization,
		url: f.oidc.authorize(authorization),
		original: { ...original },
	};
}
type Ceremony = Awaited<ReturnType<typeof ceremony>>;
function request(c: Ceremony, cookie = c.cookie) {
	return new Request(c.url, { headers: { cookie } });
}
function consumed(f: Harness, c: Ceremony) {
	expect(rows(f).find((row) => row.state_hash === c.original.state_hash)).toMatchObject({
		state: "consumed",
		nonce: null,
		pkce_verifier: null,
		consumed_at_ms: NOW,
	});
}
async function privateSafe(response: Response, c: Ceremony, outcome: unknown) {
	const visible = JSON.stringify({
		body: await response.clone().text(),
		headers: [...response.headers],
		outcome,
	});
	for (const secret of [
		PROVIDER.clientSecret,
		"fixture-access-token",
		"fixture-refresh-token",
		c.url.searchParams.get("code"),
		c.original.nonce,
		c.original.pkce_verifier,
		c.original.binder_hash,
		c.original.state_hash,
		c.original.browser_transaction_hash,
	]) {
		if (typeof secret === "string") expect(visible).not.toContain(secret);
	}
}
function providerAfterConsume(f: Harness) {
	const transport = f.oidc.fetch.getMockImplementation();
	if (!transport) throw new Error("Expected fixture transport");
	const observations: { url: string; rows: Record<string, unknown>[] }[] = [];
	f.oidc.fetch.mockImplementation(async (url, options) => {
		observations.push({ url, rows: rows(f) });
		return transport(url, options);
	});
	return observations;
}
function assertProviderProof(observations: ReturnType<typeof providerAfterConsume>, c: Ceremony) {
	for (const observed of observations) {
		expect(
			observed.rows.find(
				(row) => row.browser_transaction_hash === c.original.browser_transaction_hash,
			),
		).toMatchObject({ state: "consumed", nonce: null, pkce_verifier: null });
	}
}

type RetryFault =
	| "provider-denied"
	| "provider-nonce"
	| "unlinked"
	| "revoked"
	| "internal-admission";
async function failedSignin(f: Harness, fault: RetryFault) {
	if (fault !== "unlinked") await linked({ ...f, store: f.persistence });
	const c = await ceremony(f);
	if (fault === "revoked") {
		// Admin-only store capability is fixture setup, never authority from browser claims.
		const link = rows(f, "coordinator_auth_account_links")[0];
		if (!link || typeof link.link_id !== "string") throw new Error("Expected reviewed link");
		expect(await f.persistence.revokeAuthAccountLink({ linkId: link.link_id }, f.cfg)).toEqual({
			kind: "revoked",
		});
	}
	if (fault === "provider-denied") {
		c.url.searchParams.delete("code");
		c.url.searchParams.set("error", "access_denied");
	}
	if (fault === "provider-nonce") f.oidc.claims.nonce = "wrong-nonce";
	if (fault === "internal-admission")
		f.store.signInWithConsumedBrowserTransaction.mockRejectedValueOnce(
			new Error(PROVIDER.clientSecret),
		);
	const before = authority(f);
	const reply = await f.callback(request(c));
	expect(reply.response.status).toBe(fault === "internal-admission" ? 503 : 403);
	expect(reply.response.headers.getSetCookie()).toEqual([]);
	consumed(f, c);
	expect(rows(f, "coordinator_auth_sessions")).toEqual([]);
	expect(rows(f, "coordinator_auth_session_receipts")).toEqual([]);
	expect(authority(f)).toEqual(before);
	await privateSafe(reply.response, c, reply.outcome);
	if (fault === "provider-nonce") delete f.oidc.claims.nonce;
	return { c, reply };
}

async function staleStartDenied(f: Harness, c: Ceremony, cookie: string) {
	// Deliberately replay the original nonempty START credential, not its deletion header.
	const result = await f.start.signInStart(
		new Request(`${ORIGIN}/auth/sign-in`, {
			method: "POST",
			headers: {
				cookie: `${cookie}; ${c.startCookie}`,
				origin: ORIGIN,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ csrf: c.csrf }),
		}),
		"trusted-client",
	);
	expect(result.response.status).toBe(409);
	expect(result.outcome).toBe("start_conflict");
	expect(result.response.headers.getSetCookie()).toEqual([]);
}

// HTTP cookie-header model only: expiration/deletion headers never become Cookie pairs.
function callbackCookies() {
	const cookies = new Map<string, { value: string; expiresAt: number }>();
	return {
		apply(response: Response) {
			for (const header of response.headers.getSetCookie()) {
				const [pair, ...attributes] = header.split(";").map((value) => value.trim());
				const separator = pair.indexOf("=");
				const name = pair.slice(0, separator);
				const maxAge = attributes.find((value) => /^max-age=/i.test(value))?.slice(8);
				const expiry = attributes.find((value) => /^expires=/i.test(value))?.slice(8);
				let expiresAt = expiry === undefined ? Number.POSITIVE_INFINITY : Date.parse(expiry);
				if (maxAge !== undefined && /^-?\d+$/.test(maxAge)) expiresAt = NOW + Number(maxAge) * 1000;
				if (expiresAt <= NOW) cookies.delete(name);
				else cookies.set(name, { value: pair.slice(separator + 1), expiresAt });
			}
		},
		header(now = NOW) {
			return [...cookies]
				.filter(([, cookie]) => cookie.expiresAt > now)
				.map(([name, cookie]) => `${name}=${cookie.value}`)
				.join("; ");
		},
	};
}

async function retryStart(f: Harness, jar: ReturnType<typeof callbackCookies>) {
	const page = await f.start.signInPage(
		new Request(`${ORIGIN}/auth/sign-in`, { headers: { cookie: jar.header() } }),
	);
	expect(page.response.status).toBe(200);
	expect(page.outcome).toBe("signin_page");
	jar.apply(page.response);
	const csrf = /name="csrf" value="([A-Za-z0-9_-]+)"/.exec(await page.response.text())?.[1];
	if (!csrf) throw new Error("Expected fresh retry CSRF form");
	const credential = await readBrowserCookie(jar.header(), "start");
	if (credential.kind !== "present") throw new Error("Expected fresh retry START credential");
	const result = await f.start.signInStart(
		new Request(`${ORIGIN}/auth/sign-in`, {
			method: "POST",
			headers: {
				cookie: jar.header(),
				origin: ORIGIN,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ csrf }),
		}),
		"trusted-client",
	);
	expect(result.response.status).toBe(200);
	expect(result.outcome).toBe("signin_started");
	jar.apply(result.response);
	expect(await readBrowserCookie(jar.header(), "start")).toMatchObject({ kind: "absent" });
	const transaction = await readBrowserCookie(jar.header(), "transaction");
	if (transaction.kind !== "present") throw new Error("Expected replacement retry TXN");
	expect(transaction.cookieHash).toBe(credential.cookieHash);
	const href = /href="(https:\/\/accounts\.google\.com\/authorize[^"]+)"/.exec(
		await result.response.text(),
	)?.[1];
	if (!href) throw new Error("Expected retry provider authorization link");
	const url = new URL(href.replaceAll("&amp;", "&"));
	const stateHash = createHash("sha256")
		.update(url.searchParams.get("state") ?? "")
		.digest("hex");
	const row = rows(f).find((row) => row.state_hash === stateHash);
	expect(row).toMatchObject({
		purpose: "signin",
		state: "pending",
		binder_hash: transaction.cookieHash,
		nonce: expect.any(String),
		pkce_verifier: expect.any(String),
	});
	return { transaction, row };
}

describe.each(["SQLite", "D1"] as const)(
	"%s callback uses original durable proof before SDK exchange",
	(backend) => {
		it("issues one fresh guarded session and ID-token profile, without granting new authority", async () => {
			// Arrange: D1 here is the existing SQLite-backed adapter, not a remote service.
			const f = await harness(backend);
			await linked({ ...f, store: f.persistence });
			const c = await ceremony(f);
			const before = authority(f);
			const observations = providerAfterConsume(f);
			f.store.recordAuthAccountProfile.mockImplementation(async (...args) => {
				expect(rows(f, "coordinator_auth_sessions")).toHaveLength(1);
				return f.persistence.recordAuthAccountProfile(...args);
			});
			// Act: approved OAuth GET exception has no Origin, limiter or client-key input.
			const reply = await f.callback(request(c));
			const cookies = reply.response.headers.getSetCookie();
			const session = await readBrowserCookie(cookies[0]?.split(";")[0], "session");
			// Assert
			expect(reply.response.status).toBe(303);
			expect(reply.response.headers.get("location")).toBe(`${ORIGIN}/auth/account`);
			expect(cookies).toHaveLength(1);
			expect(cookies[0]).toMatch(
				/^__Host-codemem-session=[A-Za-z0-9_-]{43}; Max-Age=28800; Path=\/; Secure; HttpOnly; SameSite=Lax$/,
			);
			if (session.kind !== "present") throw new Error("Expected fresh session credential");
			const raw = cookies[0]?.split(";")[0]?.split("=")[1] ?? "";
			expect(session.cookieHash).toBe(
				createHash("sha256").update(Buffer.from(raw, "base64url")).digest("hex"),
			);
			expect(raw).not.toBe(c.cookie.split("=")[1]);
			expect(rows(f, "coordinator_auth_sessions")[0]).toMatchObject({
				credential_hash: session.cookieHash,
				browser_transaction_hash: c.original.browser_transaction_hash,
				subject: "opaque-subject-a",
			});
			expect(rows(f, "coordinator_auth_session_receipts")).toEqual([
				expect.objectContaining({ source: "signin", purge_eligible: 1, attempt_id: null }),
			]);
			expect(rows(f, "coordinator_auth_account_profiles")[0]).toMatchObject({
				display_name: "Fixture User",
				email: "user@example.test",
				source_session_id: rows(f, "coordinator_auth_sessions")[0]?.session_id,
			});
			expect(f.store.consumeAuthBrowserTransaction).toHaveBeenCalledWith(
				{ stateHash: c.original.state_hash, binderHash: c.original.binder_hash },
				publicConfig(),
			);
			expect(f.store.signInWithConsumedBrowserTransaction).toHaveBeenCalledOnce();
			expect(f.completeLink).not.toHaveBeenCalled();
			expect(f.oidc.requests.some((r) => r.url.endsWith("/userinfo"))).toBe(false);
			expect(f.oidc.requests.find((r) => r.url.endsWith("/token"))?.options.body).toBeInstanceOf(
				URLSearchParams,
			);
			expect(authority(f)).toEqual(before);
			consumed(f, c);
			expect(observations.some(({ url }) => url.endsWith("/token"))).toBe(true);
			assertProviderProof(observations, c);
			await privateSafe(reply.response, c, reply.outcome);
		});
		it("replay does not clear cookies belonging to a later browser ceremony", async () => {
			// Arrange
			const f = await harness(backend);
			await linked({ ...f, store: f.persistence });
			const c = await ceremony(f);
			await f.callback(request(c));
			const before = rows(f, "coordinator_auth_sessions");
			f.oidc.fetch.mockClear();
			// Act
			const reply = await f.callback(request(c));
			// Assert
			expect(reply.response.status).toBe(403);
			expect(reply.response.headers.getSetCookie()).toEqual([]);
			expect(rows(f, "coordinator_auth_sessions")).toEqual(before);
			expect(f.oidc.fetch).not.toHaveBeenCalled();
		});
	},
);

describe("pre-consume guards never burn another browser's row", () => {
	it.each([
		["method", 405],
		["origin", 404],
		["path", 404],
		["fragment", 400],
		["long-url", 400],
		["missing-state", 400],
		["duplicate-state", 400],
		["short-state", 400],
		["long-state", 400],
		["bad-state", 400],
		["missing-cookie", 403],
		["bad-cookie", 400],
		["duplicate-cookie", 400],
		["wrong-browser", 403],
		["unknown-state", 403],
		["revision", 403],
	] as const)("rejects %s with %s and no cookie mutation/provider call", async (fault, status) => {
		// Arrange
		const f = await harness();
		const c = await ceremony(f);
		let cookie = c.cookie;
		let method = "GET";
		const mutations: Record<string, () => unknown> = {
			method: () => {
				method = "POST";
			},
			origin: () => {
				c.url.hostname = "other.example.test";
			},
			path: () => {
				c.url.pathname = "/auth/other";
			},
			fragment: () => {
				c.url.hash = "fragment";
			},
			"long-url": () => c.url.searchParams.set("extra", "x".repeat(8192)),
			"missing-state": () => c.url.searchParams.delete("state"),
			"duplicate-state": () =>
				c.url.searchParams.append("state", c.url.searchParams.get("state") ?? ""),
			"short-state": () => c.url.searchParams.set("state", "s".repeat(42)),
			"long-state": () => c.url.searchParams.set("state", "s".repeat(129)),
			"bad-state": () => c.url.searchParams.set("state", `${"s".repeat(43)}+`),
			"unknown-state": () => c.url.searchParams.set("state", "s".repeat(43)),
			"missing-cookie": () => {
				cookie = "other=value";
			},
			"bad-cookie": () => {
				cookie = `${BROWSER_COOKIE_NAMES.transaction}=bad`;
			},
			"duplicate-cookie": () => {
				cookie = `${c.cookie}; ${c.cookie}`;
			},
			"wrong-browser": async () => {
				cookie = (await issueBrowserCookie("transaction")).setCookie.split(";")[0] ?? "";
			},
			revision: () =>
				f.db.prepare(`UPDATE ${TABLE} SET auth_config_revision=?`).run("b".repeat(64)),
		};
		await mutations[fault]?.();
		const before = rows(f);
		// Act
		const reply = await f.callback(new Request(c.url, { method, headers: { cookie } }));
		// Assert
		expect(reply.response.status).toBe(status);
		if (fault === "fragment") {
			expect(reply.outcome).toBe("callback_invalid");
			expect(f.store.consumeAuthBrowserTransaction).not.toHaveBeenCalled();
		}
		if (status === 405) expect(reply.response.headers.get("allow")).toBe("GET");
		expect(reply.response.headers.getSetCookie()).toEqual([]);
		expect(rows(f)).toEqual(before);
		expect(f.oidc.fetch).not.toHaveBeenCalled();
		expect(f.store.signInWithConsumedBrowserTransaction).not.toHaveBeenCalled();
		expect(f.store.recordAuthAccountProfile).not.toHaveBeenCalled();
		await privateSafe(reply.response, c, reply.outcome);
	});
	it("accepts decoded percent-equivalent state and unknown Google query parameters", async () => {
		// Arrange
		const f = await harness();
		await linked({ ...f, store: f.persistence });
		const c = await ceremony(f);
		const state = c.url.searchParams.get("state") ?? "";
		c.url.searchParams.set("authuser", "0");
		c.url.searchParams.set("prompt", "consent");
		const encoded = c.url.href.replace(
			`state=${state}`,
			`state=%${state.charCodeAt(0).toString(16)}${state.slice(1)}`,
		);
		// Act
		const reply = await f.callback(new Request(encoded, { headers: { cookie: c.cookie } }));
		// Assert: the maintained SDK interprets decoded parameters, not a raw-percent oracle.
		expect(reply.response.status).toBe(303);
		consumed(f, c);
		expect(rows(f, "coordinator_auth_sessions")).toHaveLength(1);
	});
});

describe("actual SDK rejects token and authorization protocol attacks after consuming only the matching row", () => {
	it.each([
		"modified-signature",
		"wrong-key",
		"none",
		"missing-id",
		"nonce",
		"issuer",
		"audience",
		"expired",
		"pkce",
		"invalid-grant",
		"access-denied",
		"missing-code",
		"duplicate-code",
		"code-and-error",
		"response-issuer",
	])("burns proof for %s without issuing any session", async (fault) => {
		// Arrange
		const f = await harness();
		await linked({ ...f, store: f.persistence });
		const c = await ceremony(f);
		const victim = await ceremony(f);
		const before = authority(f);
		const attacks: Record<string, () => unknown> = {
			"modified-signature": () => {
				f.oidc.settings.signature = "modified";
			},
			"wrong-key": () => {
				f.oidc.settings.signature = "wrong-key";
			},
			none: () => {
				f.oidc.settings.alg = "none";
			},
			"missing-id": () => {
				f.oidc.settings.omitIdToken = true;
			},
			nonce: () => {
				f.oidc.claims.nonce = "wrong-nonce";
			},
			issuer: () => {
				f.oidc.claims.iss = "https://wrong.example.test";
			},
			audience: () => {
				f.oidc.claims.aud = "wrong-client";
			},
			expired: () => {
				f.oidc.claims.exp = 1;
			},
			pkce: () => {
				c.url = f.oidc.authorize(c.authorization, { challenge: "wrong-challenge" });
			},
			"invalid-grant": () => c.url.searchParams.set("code", "unknown-code"),
			"access-denied": () => {
				c.url.searchParams.delete("code");
				c.url.searchParams.set("error", "access_denied");
			},
			"missing-code": () => c.url.searchParams.delete("code"),
			"duplicate-code": () => c.url.searchParams.append("code", "second-code"),
			"code-and-error": () => c.url.searchParams.set("error", "access_denied"),
			"response-issuer": () => c.url.searchParams.set("iss", "https://wrong.example.test"),
		};
		attacks[fault]?.();
		const observations = providerAfterConsume(f);
		// Act
		const reply = await f.callback(request(c));
		// Assert
		expect(reply.response.status).toBe(403);
		expect(reply.response.headers.getSetCookie()).toEqual([]);
		consumed(f, c);
		assertProviderProof(observations, c);
		if (
			![
				"access-denied",
				"missing-code",
				"duplicate-code",
				"code-and-error",
				"response-issuer",
			].includes(fault)
		)
			expect(observations.some(({ url }) => url.endsWith("/token"))).toBe(true);
		expect(rows(f).find((row) => row.state_hash === victim.original.state_hash)).toEqual(
			victim.original,
		);
		expect(rows(f, "coordinator_auth_sessions")).toEqual([]);
		expect(f.store.signInWithConsumedBrowserTransaction).not.toHaveBeenCalled();
		expect(f.store.recordAuthAccountProfile).not.toHaveBeenCalled();
		expect(authority(f)).toEqual(before);
		await privateSafe(reply.response, c, reply.outcome);
	});
});

describe("guarded admission and existing session preservation", () => {
	it.each(["unlinked", "revoked", "coordinator", "ten-sessions", "transaction-config"])(
		"returns the same generic denial for %s",
		async (fault) => {
			// Arrange
			const f = await harness();
			if (fault !== "unlinked") await linked({ ...f, store: f.persistence });
			const c = await ceremony(f);
			if (fault === "revoked")
				f.db.prepare("UPDATE coordinator_auth_account_links SET revoked_at_ms=?").run(NOW);
			if (fault === "coordinator")
				f.store.signInWithConsumedBrowserTransaction.mockImplementation(async (...args) => {
					f.db.prepare(`UPDATE ${TABLE} SET coordinator_id=?`).run("other-coordinator");
					return f.persistence.signInWithConsumedBrowserTransaction(...args);
				});
			if (fault === "ten-sessions")
				for (let i = 0; i < 10; i++) {
					await consumeSigninProof(
						{ ...f, store: f.persistence },
						createHash("sha256").update(`browser-${i}`).digest("hex"),
						f.cfg,
					);
					expect(
						await f.persistence.signInWithConsumedBrowserTransaction(
							{
								browserTransactionHash: createHash("sha256").update(`browser-${i}`).digest("hex"),
								credentialHash: createHash("sha256").update(`credential-${i}`).digest("hex"),
								account: { issuer: f.cfg.issuer, subject: "opaque-subject-a" },
							},
							f.cfg,
						),
					).toMatchObject({ kind: "issued" });
				}
			if (fault === "transaction-config")
				f.store.signInWithConsumedBrowserTransaction.mockImplementation(async (...args) => {
					f.db.prepare(`UPDATE ${TABLE} SET auth_config_revision=?`).run("b".repeat(64));
					return f.persistence.signInWithConsumedBrowserTransaction(...args);
				});
			const before = rows(f, "coordinator_auth_sessions");
			const generic = await f.callback(new Request(PROVIDER.redirectUri));
			// Act
			const reply = await f.callback(request(c));
			// Assert
			expect(reply.response.status).toBe(403);
			expect(await reply.response.clone().text()).toBe(await generic.response.text());
			expect(reply.response.headers.getSetCookie()).toEqual([]);
			expect(rows(f, "coordinator_auth_sessions")).toEqual(before);
			expect(f.store.recordAuthAccountProfile).not.toHaveBeenCalled();
			consumed(f, c);
		},
	);
	it.each(["same-account", "different-account"])(
		"preserves live original SESSION for %s after SDK verification",
		async (account) => {
			// Arrange
			const f = await harness();
			await linked({ ...f, store: f.persistence });
			const c = await ceremony(f);
			const old = await issueBrowserCookie("session");
			await consumeSigninProof({ ...f, store: f.persistence }, "e".repeat(64), f.cfg);
			expect(
				await f.persistence.signInWithConsumedBrowserTransaction(
					{
						browserTransactionHash: "e".repeat(64),
						credentialHash: old.cookieHash,
						account: { issuer: f.cfg.issuer, subject: "opaque-subject-a" },
					},
					f.cfg,
				),
			).toMatchObject({ kind: "issued" });
			if (account === "different-account") f.oidc.claims.sub = "different-account";
			const before = rows(f, "coordinator_auth_sessions");
			const receipts = rows(f, "coordinator_auth_session_receipts");
			const req = request(c, `${c.cookie}; ${old.setCookie.split(";")[0]}`);
			f.store.consumeAuthBrowserTransaction.mockImplementation(async (...args) => {
				req.headers.delete("cookie");
				return f.persistence.consumeAuthBrowserTransaction(...args);
			});
			// Act
			const reply = await f.callback(req);
			// Assert: no account switch, rotation, false sign-in receipt, or profile write.
			expect(reply.response.status).toBe(303);
			expect(reply.response.headers.get("location")).toBe(`${ORIGIN}/auth/account`);
			expect(reply.response.headers.getSetCookie()).toEqual([]);
			expect(f.store.readAuthSession).toHaveBeenCalledWith(old.cookieHash, publicConfig());
			expect(rows(f, "coordinator_auth_sessions")).toEqual(before);
			expect(rows(f, "coordinator_auth_session_receipts")).toEqual(receipts);
			expect(f.store.signInWithConsumedBrowserTransaction).not.toHaveBeenCalled();
			expect(f.store.recordAuthAccountProfile).not.toHaveBeenCalled();
			expect(f.oidc.fetch).toHaveBeenCalled();
		},
	);
	it.each(["throw", "not-recorded", "rejected"])(
		"keeps an issued session despite profile follow-up %s",
		async (fault) => {
			// Arrange
			const f = await harness();
			await linked({ ...f, store: f.persistence });
			const c = await ceremony(f);
			if (fault === "throw")
				f.store.recordAuthAccountProfile.mockRejectedValue(new Error(PROVIDER.clientSecret));
			if (fault === "not-recorded")
				f.store.recordAuthAccountProfile.mockResolvedValue({ kind: "not_recorded" });
			if (fault === "rejected")
				f.store.recordAuthAccountProfile.mockResolvedValue({
					kind: "rejected",
					error: "auth_config_changed",
				});
			// Act
			const reply = await f.callback(request(c));
			// Assert
			expect(reply.response.status).toBe(303);
			expect(reply.outcome).toBe("signed_in_profile_not_recorded");
			expect(reply.response.headers.getSetCookie()).toHaveLength(1);
			expect(reply.response.headers.getSetCookie()[0]).toMatch(/^__Host-codemem-session=/);
			expect(rows(f, "coordinator_auth_sessions")).toHaveLength(1);
			await privateSafe(reply.response, c, reply.outcome);
		},
	);
});

describe("callback concurrency and immutable request snapshots", () => {
	it("eight callbacks through two transaction-store instances sharing one Node SQLite connection have one winner", async () => {
		// Arrange: deliberately NOT separate SQLite connections or a cross-process claim.
		const f = await harness();
		await linked({ ...f, store: f.persistence });
		const c = await ceremony(f);
		const second = browserCapability({ ...f, store: f.persistence });
		const gate = Promise.withResolvers<void>();
		const arrived = Promise.withResolvers<void>();
		let count = 0;
		const wrap = (persistence: Pick<typeof f.persistence, "consumeAuthBrowserTransaction">) => ({
			...f.store,
			async consumeAuthBrowserTransaction(
				...args: Parameters<typeof f.store.consumeAuthBrowserTransaction>
			) {
				if (++count === 8) arrived.resolve();
				await gate.promise;
				return persistence.consumeAuthBrowserTransaction(...args);
			},
		});
		const left = await createCoordinatorBrowserAuthCallback({
			...f.input,
			store: wrap(f.persistence),
		});
		const right = await createCoordinatorBrowserAuthCallback({ ...f.input, store: wrap(second) });
		if (!left.ok || !right.ok) throw new Error("Expected callback factories");
		f.oidc.fetch.mockClear();
		const observations = providerAfterConsume(f);
		// Act: barrier is before consume, never inside the one-winner admission path.
		const pending = Array.from({ length: 8 }, (_, i) =>
			(i % 2 ? left : right).handlers.callback(request(c)),
		);
		await arrived.promise;
		gate.resolve();
		const replies = await Promise.all(pending);
		// Assert
		expect(replies.map((r) => r.response.status).sort()).toEqual([
			303, 403, 403, 403, 403, 403, 403, 403,
		]);
		for (const reply of replies) {
			const cookies = reply.response.headers.getSetCookie();
			expect(cookies).toHaveLength(reply.response.status === 303 ? 1 : 0);
			if (reply.response.status === 303) expect(cookies[0]).toMatch(/^__Host-codemem-session=/);
		}
		expect(rows(f, "coordinator_auth_sessions")).toHaveLength(1);
		expect(f.oidc.fetch.mock.calls.filter(([url]) => url.endsWith("/token"))).toHaveLength(1);
		assertProviderProof(observations, c);
	});
	it("uses native original URL, method and cookies despite accessors and asynchronous mutation", async () => {
		// Arrange
		const f = await harness();
		await linked({ ...f, store: f.persistence });
		const c = await ceremony(f);
		const req = request(c);
		const headers = req.headers;
		const getter = vi.fn(() => {
			throw new Error(PROVIDER.clientSecret);
		});
		for (const key of ["url", "method", "headers"])
			Object.defineProperty(req, key, { get: getter, configurable: true });
		f.store.consumeAuthBrowserTransaction.mockImplementation(async (...args) => {
			headers.set("cookie", `${BROWSER_COOKIE_NAMES.transaction}=bad`);
			Object.defineProperty(req, "url", {
				value: `${PROVIDER.redirectUri}?code=changed`,
				configurable: true,
			});
			return f.persistence.consumeAuthBrowserTransaction(...args);
		});
		// Act
		const reply = await f.callback(req);
		// Assert
		expect(reply.response.status).toBe(303);
		expect(getter).not.toHaveBeenCalled();
		const tokenBody = f.oidc.fetch.mock.calls.find(([url]) => url.endsWith("/token"))?.[1].body;
		if (!(tokenBody instanceof URLSearchParams)) throw new Error("Expected token POST body");
		expect(tokenBody.get("code")).toBe(c.url.searchParams.get("code"));
		expect(rows(f, "coordinator_auth_sessions")).toHaveLength(1);
	});
});

describe.each(["SQLite", "D1"] as const)(
	"%s failed signin retry with retained browser cookies",
	(backend) => {
		it.each([
			"provider-denied",
			"provider-nonce",
			"unlinked",
			"revoked",
			"internal-admission",
		] as const)(
			"%s consumption permits a fresh credential-bearing start but never reuses the old proof",
			async (fault) => {
				// Arrange: exercise the real callback, SDK, store consumption and failure boundary.
				const f = await harness(backend);
				const { c, reply } = await failedSignin(f, fault);
				const jar = callbackCookies();
				jar.apply(c.response);
				const retained = jar.header();
				jar.apply(reply.response);
				expect(jar.header()).toBe(retained);
				expect(await readBrowserCookie(jar.header(), "start")).toMatchObject({ kind: "absent" });
				const txn = await readBrowserCookie(jar.header(), "transaction");
				if (txn.kind !== "present") throw new Error("Expected retained failed TXN");
				const before = authority(f, { browserAllocation: true });
				const history = rows(f);
				// Act / Assert: failed proof is inactive, but malformed credentials/config stay denied.
				expect(
					await f.persistence.readAuthBrowserTransactionActivity(
						{ binderHash: txn.cookieHash },
						f.cfg,
					),
				).toEqual({ kind: "inactive" });
				expect(
					await f.persistence.readAuthBrowserTransactionActivity({ binderHash: "bad" }, f.cfg),
				).toEqual({ kind: "rejected", error: "invalid_input" });
				expect(
					await f.persistence.readAuthBrowserTransactionActivity(
						{ binderHash: txn.cookieHash },
						{ ...f.cfg, revision: "b".repeat(64) },
					),
				).toEqual({ kind: "rejected", error: "auth_config_changed" });
				const invalid = await f.start.signInPage(
					new Request(`${ORIGIN}/auth/sign-in`, {
						headers: { cookie: `${BROWSER_COOKIE_NAMES.transaction}=bad` },
					}),
				);
				expect(invalid.response.status).toBe(400);
				expect(invalid.response.headers.getSetCookie()).toEqual([]);
				await staleStartDenied(f, c, jar.header());
				expect(rows(f)).toEqual(history);
				const allocation = f.db
					.prepare("SELECT seq FROM sqlite_sequence WHERE name=?")
					.get(TABLE) as { seq: number };
				// Act: the old TXN stays in the real GET/POST cookie jar beside a newly issued START.
				const fresh = await retryStart(f, jar);
				// Assert: exactly one new pending proof, with no history/authority/SID mutation.
				expect(fresh.transaction.cookieHash).not.toBe(txn.cookieHash);
				expect(
					await f.persistence.readAuthBrowserTransactionActivity(
						{ binderHash: fresh.transaction.cookieHash },
						f.cfg,
					),
				).toEqual({ kind: "active" });
				expect(rows(f).filter((row) => row.binder_hash !== fresh.transaction.cookieHash)).toEqual(
					history,
				);
				expect(f.db.prepare("SELECT seq FROM sqlite_sequence WHERE name=?").get(TABLE)).toEqual({
					seq: allocation.seq + 1,
				});
				expect(authority(f, { browserAllocation: true })).toEqual(before);
				f.oidc.fetch.mockClear();
				const pending = rows(f);
				// Act: replay both the original request and its old URL with the replacement TXN.
				for (const cookie of [c.cookie, jar.header()]) {
					const replay = await f.callback(request(c, cookie));
					expect(replay.response.status).toBe(403);
					expect(replay.response.headers.getSetCookie()).toEqual([]);
					jar.apply(replay.response);
				}
				// Assert: no extra exchange, replay, cookie deletion, session or profile grant.
				expect(f.oidc.fetch).not.toHaveBeenCalled();
				expect(rows(f)).toEqual(pending);
				expect(rows(f, "coordinator_auth_sessions")).toEqual([]);
				expect(rows(f, "coordinator_auth_session_receipts")).toEqual([]);
				expect(f.store.recordAuthAccountProfile).not.toHaveBeenCalled();
				expect(await readBrowserCookie(jar.header(), "transaction")).toMatchObject({
					kind: "present",
					cookieHash: fresh.transaction.cookieHash,
				});
				expect(jar.header(NOW + 86_400_000)).toBe("");
			},
		);
	},
);

describe.each(["SQLite", "D1"] as const)(
	"%s ambiguous consumption keeps truthful activity",
	(backend) => {
		it.each(["before-commit", "after-commit"] as const)(
			"%s throw never guesses away a pending transaction",
			async (stage) => {
				// Arrange: only the consume operation fails; activity and start use the real store.
				const f = await harness(backend);
				const c = await ceremony(f);
				f.store.consumeAuthBrowserTransaction.mockImplementationOnce(async (...args) => {
					if (stage === "after-commit") await f.persistence.consumeAuthBrowserTransaction(...args);
					throw new Error(PROVIDER.clientSecret);
				});
				const jar = callbackCookies();
				jar.apply(c.response);
				const cookie = jar.header();
				// Act
				const reply = await f.callback(request(c));
				jar.apply(reply.response);
				const activity = await f.persistence.readAuthBrowserTransactionActivity(
					{ binderHash: String(c.original.binder_hash) },
					f.cfg,
				);
				// Assert: no provider exchange or cookie mutation on an ambiguous response.
				expect(reply.response.status).toBe(503);
				expect(reply.response.headers.getSetCookie()).toEqual([]);
				expect(jar.header()).toBe(cookie);
				expect(f.oidc.fetch).not.toHaveBeenCalled();
				if (stage === "before-commit") {
					expect(activity).toEqual({ kind: "active" });
					const blocked = await f.start.signInPage(
						new Request(`${ORIGIN}/auth/sign-in`, { headers: { cookie } }),
					);
					expect(blocked.response.status).toBe(409);
					expect(blocked.outcome).toBe("signin_in_progress");
					expect(blocked.response.headers.getSetCookie()).toEqual([]);
					expect(rows(f).find((row) => row.state_hash === c.original.state_hash)).toEqual(
						c.original,
					);
				} else {
					expect(activity).toEqual({ kind: "inactive" });
					consumed(f, c);
					await retryStart(f, jar);
				}
				expect(rows(f, "coordinator_auth_sessions")).toEqual([]);
				expect(rows(f, "coordinator_auth_session_receipts")).toEqual([]);
			},
		);
	},
);
