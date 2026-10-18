import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { createRequire } from "node:module";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import type { BrowserContext } from "@playwright/test";
import preact from "@preact/preset-vite";
import { build } from "vite";
import { BetterSqliteCoordinatorStore } from "../../core/src/better-sqlite-coordinator-store";
import { changeCoordinatorAccount } from "../../core/src/coordinator-account-link-runtime";
import { signAccountLinkRequest } from "../../core/src/coordinator-account-link-signer";
import { readCoordinatorAccountLinkStatus } from "../../core/src/coordinator-account-link-status-client";
import { createCoordinatorApp } from "../../core/src/coordinator-api";
import { review } from "../../core/src/coordinator-auth-store-test-fixtures";
import {
	captureCoordinatorBrowserAuthOptions,
	createCoordinatorBrowserAuth,
} from "../../core/src/coordinator-browser-auth-app";
import { importBrowserCsrfKey } from "../../core/src/coordinator-browser-csrf";
import { oidcFixture, PROVIDER } from "../../core/src/coordinator-oidc-test-fixtures";
import { createInMemoryRequestRateLimiter } from "../../core/src/request-rate-limit";
import { verifySignature } from "../../core/src/sync-auth";
import { fingerprintPublicKey } from "../../core/src/sync-fingerprint";
import { initTestSchema, seedMixedScopeFixture } from "../../core/src/test-utils";
import type { AccountContextResult } from "../../viewer-server/src/account/context";
import { createAccountGuard } from "../../viewer-server/src/account/guard";
import { createAccountLinkRegistry } from "../../viewer-server/src/account/link-registry";
import { accountOperationRoutes } from "../../viewer-server/src/routes/account-operations";
import { accountStatusRoutes } from "../../viewer-server/src/routes/account-status";
import { uiAliases } from "../ui-aliases";

const requireCore = createRequire(resolve(import.meta.dirname, "../../core/package.json"));
const Database = requireCore("better-sqlite3") as new (
	path: string,
) => BetterSqliteCoordinatorStore["db"];
const { Hono } = createRequire(resolve(import.meta.dirname, "../../viewer-server/package.json"))(
	"hono",
) as { Hono: new () => ReturnType<typeof createAccountGuard>["routes"] };
const hash = (raw: string) =>
	createHash("sha256").update(Buffer.from(raw, "base64url")).digest("hex");
function gate() {
	let release!: () => void;
	const promise = new Promise<void>((done) => {
		release = done;
	});
	return { promise, release };
}

// Actual browser HTTPS/HTTP, production routers/runtime, SQLite and Ed25519.
// Only provider discovery/JWKS/token exchange and authorization are synthetic.
// Signed runtime requests use app.fetch (same canonical request and real verifier).
export async function fixture(browser: BrowserContext) {
	const artifactRoot = resolve(import.meta.dirname, "../../../.tmp/account-browser");
	mkdirSync(artifactRoot, { recursive: true });
	const dir = mkdtempSync(resolve(artifactRoot, "fixture-"));
	const keysDir = resolve(dir, "keys");
	mkdirSync(keysDir);
	execFileSync(
		"openssl",
		[
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-nodes",
			"-keyout",
			resolve(dir, "tls.key"),
			"-out",
			resolve(dir, "tls.crt"),
			"-days",
			"1",
			"-subj",
			"/CN=127.0.0.1",
			"-addext",
			"subjectAltName=IP:127.0.0.1",
		],
		{ stdio: "ignore" },
	);
	const dbPath = resolve(dir, "local.sqlite");
	const local = new Database(dbPath);
	initTestSchema(local);
	const keys = generateKeyPairSync("ed25519");
	const raw = Buffer.from(keys.publicKey.export({ type: "spki", format: "der" })).subarray(-32);
	const kind = Buffer.from("ssh-ed25519");
	const wire = Buffer.alloc(8 + kind.length + raw.length);
	wire.writeUInt32BE(kind.length);
	kind.copy(wire, 4);
	wire.writeUInt32BE(raw.length, 4 + kind.length);
	raw.copy(wire, 8 + kind.length);
	const publicKey = `ssh-ed25519 ${wire.toString("base64")}`;
	const fingerprint = fingerprintPublicKey(publicKey);
	const device = { deviceId: "device-a", publicKey, fingerprint };
	writeFileSync(
		resolve(keysDir, "device.key"),
		keys.privateKey.export({ type: "pkcs8", format: "pem" }),
		{ mode: 0o600 },
	);
	writeFileSync(resolve(keysDir, "device.key.pub"), publicKey);
	local
		.prepare(
			"INSERT INTO sync_device (device_id, public_key, fingerprint, created_at) VALUES (?, ?, ?, ?)",
		)
		.run(device.deviceId, publicKey, fingerprint, new Date().toISOString());
	seedMixedScopeFixture(local, device.deviceId);
	local
		.prepare(
			"INSERT INTO actors (actor_id, display_name, is_local, created_at, updated_at) VALUES ('identity-a', 'Browser identity', 1, ?, ?)",
		)
		.run(new Date().toISOString(), new Date().toISOString());
	const remotePath = resolve(dir, "coordinator.sqlite");
	const store = new BetterSqliteCoordinatorStore(remotePath);
	await store.createGroup("group-a");
	await store.enrollDevice("group-a", { ...device, identityId: "identity-a" });
	await store.createAuthControllerAttestation(review(device));
	const grant = await store.issueIdentityGroupGrantFromControllerAttestation({
		coordinatorId: "coordinator-a",
		attestationId: "attestation-a",
	});
	if (grant.kind !== "created") throw new Error("Fixture sharing grant was not created");
	let app: ReturnType<typeof createCoordinatorApp>;
	const coordinator = httpsServer(
		{ key: readFileSync(resolve(dir, "tls.key")), cert: readFileSync(resolve(dir, "tls.crt")) },
		async (req, res) => {
			const chunks: Buffer[] = [];
			for await (const chunk of req) chunks.push(Buffer.from(chunk));
			const body = Buffer.concat(chunks);
			const reply = await app.fetch(
				new Request(`https://${req.headers.host}${req.url}`, {
					method: req.method,
					headers: req.headers as Record<string, string>,
					...(body.length ? { body } : {}),
				}),
			);
			res.writeHead(reply.status, {
				...Object.fromEntries(reply.headers),
				"set-cookie": reply.headers.getSetCookie(),
			});
			res.end(Buffer.from(await reply.arrayBuffer()));
		},
	);
	coordinator.listen(0, "127.0.0.1");
	await once(coordinator, "listening");
	const origin = `https://127.0.0.1:${(coordinator.address() as AddressInfo).port}`;
	const config = {
		...PROVIDER,
		redirectUri: `${origin}/auth/callback`,
		issuer: "https://accounts.google.com",
		enabled: true,
		coordinatorId: "coordinator-a",
		revision: "a".repeat(64),
	};
	const oidc = oidcFixture({ issuer: config.issuer });
	oidc.claims.name = "Refreshed browser profile";
	oidc.claims.picture = undefined; // No real profile image requests.
	const auth = await createCoordinatorBrowserAuth(
		captureCoordinatorBrowserAuthOptions({
			config,
			csrfKey: await importBrowserCsrfKey(randomBytes(32)),
			oidcOptions: {
				fetch: async (url, options) => {
					// The reused fixture pins its own redirect URI; adapt only this test transport.
					if (url === `${config.issuer}/token` && options.body instanceof URLSearchParams) {
						const body = new URLSearchParams(options.body);
						body.set("redirect_uri", PROVIDER.redirectUri);
						return oidc.fetch(url, { ...options, body });
					}
					return oidc.fetch(url, options);
				},
			},
		}),
		store,
		createInMemoryRequestRateLimiter(),
	);
	if (!auth.ok) throw new Error(`Browser fixture composition: ${auth.error}`);
	const storeFactory = () => new BetterSqliteCoordinatorStore(remotePath);
	app = createCoordinatorApp({
		storeFactory,
		runtime: { adminSecret: () => null, now: () => new Date().toISOString() },
		requestVerifier: (input) =>
			verifySignature({ ...input, bodyBytes: Buffer.from(input.bodyBytes) }),
		browserAuth: {
			kind: "ready",
			auth: auth.auth,
			storeFactory,
			clientKey: () => "browser-fixture",
		},
	});
	const allowed = new Set([origin]);
	const blocked: string[] = [];
	const browserPosts: string[] = [];
	const acknowledgement = gate();
	const finalization = gate();
	const dispatch = gate();
	const finalizationStarted = gate();
	const finalRequests: Request[] = [];
	let receipts = 0;
	const transport: typeof fetch = async (input, init) => {
		const request = new Request(input, init);
		if (new URL(request.url).origin !== origin) throw new Error("Unexpected runtime network");
		if (request.method === "POST" && new URL(request.url).pathname === "/v1/auth/link-changes") {
			const body = await request.clone().json();
			allowed.add(new URL(body.loopback_redirect).origin); // Exactly the port allocated by the actual runtime.
		}
		if (request.url.includes("/link-changes/") && request.url.endsWith("/finalize")) {
			finalizationStarted.release();
			await dispatch.promise;
		}
		const response = await app.fetch(request.clone());
		if (request.url.includes("/link-changes/") && request.url.endsWith("/finalize")) {
			finalRequests.push(request);
			if (!response.ok) throw new Error(`Signed finalization failed: ${response.status}`);
			finalization.release();
			await acknowledgement.promise; // Effects committed; trusted receipt still cannot report success.
		}
		return response;
	};
	// Seed the initial link using real store transaction proof plus signed API finalize.
	const proofRaw = randomBytes(32).toString("base64url");
	const signed = async (path: string, value: unknown) => {
		const bodyBytes = Buffer.from(JSON.stringify(value));
		return app.fetch(
			new Request(`${origin}${path}`, {
				method: "POST",
				headers: {
					...signAccountLinkRequest({
						dbPath,
						keysDir,
						device,
						method: "POST",
						url: `${origin}${path}`,
						bodyBytes,
					}),
					"content-type": "application/json",
				},
				body: bodyBytes,
			}),
		);
	};
	const created = await signed("/v1/auth/link-attempts", {
		group_id: "group-a",
		identity_id: "identity-a",
		authority: "controller_attestation",
		attempt_id: "genesis",
		runtime_verifier_hash: hash(proofRaw),
		browser_start_hash: hash(proofRaw),
		loopback_redirect: "http://127.0.0.1:4567/codemem/auth/complete",
	});
	if (created.status !== 201)
		throw new Error(`Genesis create ${created.status}: ${await created.text()}`);
	const material = {
		purpose: "link" as const,
		attemptId: "genesis",
		browserStartHash: hash(proofRaw),
		stateHash: "1".repeat(64),
		binderHash: "2".repeat(64),
		nonce: "n".repeat(43),
		pkceVerifier: "p".repeat(43),
	};
	await store.startAuthBrowserTransaction(material, config);
	const consumed = await store.consumeAuthBrowserTransaction(material, config);
	if (consumed.kind !== "consumed") throw new Error("Genesis consume failed");
	const proof = { attemptId: "genesis", browserTransactionHash: consumed.browserTransactionHash };
	await store.recordAuthLinkOidcVerified(
		{
			...proof,
			account: { issuer: config.issuer, subject: "fixture-subject" },
			profile: { displayName: "Original profile" },
		},
		config,
	);
	await store.confirmAuthLinkAttempt({ ...proof, completionSecretHash: hash(proofRaw) }, config);
	const seeded = await signed("/v1/auth/link-attempts/genesis/finalize", {
		purpose: "coordinator-account-link-v1",
		coordinator_id: config.coordinatorId,
		attempt_id: "genesis",
		group_id: "group-a",
		identity_id: "identity-a",
		device_id: device.deviceId,
		fingerprint,
		runtime_verifier: proofRaw,
		completion: proofRaw,
	});
	if (!seeded.ok) throw new Error(`Genesis finalize ${seeded.status}: ${await seeded.text()}`);
	const context = {
		contextId: "context-a",
		groupId: "group-a",
		...device,
		identityId: "identity-a",
		identityLabel: "Browser identity",
		deviceLabel: "Browser device",
		dbPath,
		keysDir,
		coordinatorUrl: origin,
		fileIdentity: { dev: "1", ino: "2" },
	};
	let current = true;
	const readContext = (): AccountContextResult => ({
		setup: "ready",
		groups: ["group-a"],
		selectedGroupId: "group-a",
		coordinator: { origin },
		context: { ...context, ...(current ? {} : { contextId: "context-changed" }) },
	});
	const registry = createAccountLinkRegistry({
		readContext,
		change: (options) => changeCoordinatorAccount({ ...options, fetch: transport }),
	});
	const address = { host: "127.0.0.1", port: 0 };
	const options = {
		getListenerAddress: () => address,
		readContext,
		registry,
		readRemoteStatus: (input: Parameters<typeof readCoordinatorAccountLinkStatus>[0]) =>
			readCoordinatorAccountLinkStatus({ ...input, fetch: transport }),
	};
	const guard = createAccountGuard(options);
	const viewerApp = new Hono();
	viewerApp.use("/api/account/*", guard.middleware);
	viewerApp.route("/", guard.routes);
	viewerApp.route("/", accountStatusRoutes(options));
	viewerApp.route("/", accountOperationRoutes(options));
	const entry = resolve(dir, "account-entry.ts");
	writeFileSync(
		entry,
		`import { mountRecipientPolicySharing } from ${JSON.stringify(resolve(import.meta.dirname, "../src/tabs/recipient-policy-sharing.tsx"))}; mountRecipientPolicySharing(document.querySelector('main'), [], {version:1,identities:[],teams:[],teamMemberships:[],identityDevices:[],projectRecipients:[]});`,
	);
	const bundle = await build({
		configFile: false,
		root: resolve(import.meta.dirname, ".."),
		logLevel: "error",
		resolve: { alias: uiAliases },
		plugins: [preact()],
		build: { write: false, lib: { entry, name: "AccountFixture", formats: ["iife"] } },
	});
	const output = Array.isArray(bundle) ? bundle[0] : bundle;
	if (!output || !("output" in output)) throw new Error("Unexpected browser bundle");
	const js = output.output
		.filter((chunk) => chunk.type === "chunk")
		.map((chunk) => chunk.code)
		.join("\n");
	viewerApp.get("/app.js", (c) => c.body(js, 200, { "Content-Type": "application/javascript" }));
	viewerApp.get("/", (c) =>
		c.html('<!doctype html><html><body><main></main><script src="/app.js"></script></body></html>'),
	);
	const viewer = httpServer(async (req, res) => {
		const chunks: Buffer[] = [];
		for await (const chunk of req) chunks.push(Buffer.from(chunk));
		const body = Buffer.concat(chunks);
		const reply = await viewerApp.fetch(
			new Request(`http://${req.headers.host}${req.url}`, {
				method: req.method,
				headers: req.headers as Record<string, string>,
				...(body.length ? { body } : {}),
			}),
		);
		res.writeHead(reply.status, {
			...Object.fromEntries(reply.headers),
			"set-cookie": reply.headers.getSetCookie(),
		});
		res.end(Buffer.from(await reply.arrayBuffer()));
	});
	viewer.listen(0, "127.0.0.1");
	await once(viewer, "listening");
	address.port = (viewer.address() as AddressInfo).port;
	const viewerOrigin = `http://127.0.0.1:${address.port}`;
	allowed.add(viewerOrigin);
	await browser.route("**/*", async (route) => {
		const url = new URL(route.request().url());
		if (route.request().method() === "POST" && url.origin === origin)
			browserPosts.push(url.pathname);
		if (url.origin === config.issuer && url.pathname === "/authorize") {
			const callback = oidc.authorize(url);
			callback.protocol = "https:";
			callback.host = new URL(origin).host;
			await route.fulfill({
				status: 200,
				headers: { "content-type": "text/html", "Cross-Origin-Opener-Policy": "same-origin" },
				body: `<!doctype html><h1>Synthetic provider authorization</h1><a href="${callback.href.replaceAll("&", "&amp;")}">Complete synthetic sign-in</a>`,
			});
			return;
		}
		if (!allowed.has(url.origin)) {
			blocked.push(url.origin);
			await route.abort("blockedbyclient");
			return;
		}
		if (url.pathname === "/codemem/auth/result") receipts++;
		await route.continue();
	});
	const rows = (table: string) => store.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();
	const preserved = () => ({
		keys: readFileSync(resolve(keysDir, "device.key"), "utf8"),
		local: local.prepare("SELECT * FROM sync_device").all(),
		identities: local.prepare("SELECT * FROM actors ORDER BY actor_id").all(),
		history: local.prepare("SELECT * FROM memory_items ORDER BY id").all(),
		sessions: local.prepare("SELECT * FROM sessions ORDER BY id").all(),
		grants: rows("coordinator_identity_group_grants"),
		owners: rows("coordinator_device_ownership_bindings"),
	});
	return {
		origin,
		viewerOrigin,
		store,
		rows,
		preserved,
		finalizationStarted: finalizationStarted.promise,
		dispatch: dispatch.release,
		finalization: finalization.promise,
		finalRequests,
		release: acknowledgement.release,
		blocked,
		browserPosts,
		receipts: () => receipts,
		status: () =>
			readCoordinatorAccountLinkStatus({
				dbPath,
				keysDir,
				coordinatorUrl: origin,
				groupId: "group-a",
				identityId: "identity-a",
				fetch: transport,
			}),
		stale: () => {
			current = false;
		},
		async close() {
			dispatch.release();
			acknowledgement.release();
			await registry.close();
			await Promise.all(browser.pages().map((page) => page.close()));
			await browser.unrouteAll({ behavior: "wait" });
			for (const server of [viewer, coordinator]) {
				server.closeAllConnections();
				await new Promise<void>((done) => server.close(() => done()));
			}
			store.db.close();
			local.close();
			rmSync(dir, { recursive: true, force: true });
		},
	};
}
