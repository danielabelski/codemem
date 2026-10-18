import type { Context, Hono } from "hono";
import { isAuthControllerId } from "./coordinator-auth-controller.js";
import { AUTH_LINK_CHANGE_PURPOSE } from "./coordinator-auth-link-change-contract.js";
import type { CoordinatorAccountManagementStore } from "./coordinator-auth-link-change-store.js";
import type { CoordinatorAuthLinkSigner } from "./coordinator-auth-link-contract.js";
import { isHash } from "./coordinator-auth-link-input.js";
import { parseCoordinatorAuthLoopback } from "./coordinator-auth-loopback.js";
import {
	decodeCoordinatorAuthProof32,
	hashCoordinatorAuthProofBytes32,
} from "./coordinator-auth-proof.js";
import {
	assertConfiguredAuthSchema,
	authSchemaUpgradeResponse,
	CoordinatorAuthSchemaUpgradeRequiredError,
} from "./coordinator-auth-schema.js";
import type {
	CoordinatorDeviceAuthLinkStore,
	DeviceAuthLinkDeps,
} from "./coordinator-device-auth-link.js";

type Action = "create" | "status" | "finalize" | "cancel";
const FIELDS = {
	create: [
		"group_id",
		"identity_id",
		"intent",
		"attempt_id",
		"runtime_verifier_hash",
		"browser_start_hash",
		"loopback_redirect",
	],
	finalize: [
		"purpose",
		"coordinator_id",
		"attempt_id",
		"group_id",
		"identity_id",
		"device_id",
		"fingerprint",
		"runtime_verifier",
		"completion",
	],
	cancel: ["group_id"],
};
function exact(
	value: Record<string, unknown> | null,
	keys: string[],
): value is Record<string, string> {
	return (
		value !== null &&
		Object.keys(value).length === keys.length &&
		keys.every((k) => Object.hasOwn(value, k) && typeof value[k] === "string")
	);
}
async function readInput(
	c: Context,
	action: Action,
	deps: DeviceAuthLinkDeps,
): Promise<{ raw: Uint8Array; data: Record<string, string>; attemptId: string } | null> {
	const url = new URL(c.req.url);
	if (url.origin !== new URL(deps.config.redirectUri).origin) return null;
	if (action === "status") {
		if (
			c.req.raw.body !== null ||
			[...url.searchParams].length !== 1 ||
			url.searchParams.getAll("group_id").length !== 1
		)
			return null;
		return {
			raw: new Uint8Array(),
			data: { group_id: url.searchParams.get("group_id") ?? "" },
			attemptId: c.req.param("attemptId") ?? "",
		};
	}
	if (url.search || url.hash) return null;
	const raw = await deps.readRequestBytes(c, 4096);
	if (!raw) return null;
	const data = deps.parseJsonObject(raw);
	if (!exact(data, FIELDS[action])) return null;
	const attemptId = action === "create" ? data.attempt_id : c.req.param("attemptId");
	if (!attemptId) return null;
	return { raw, data, attemptId };
}
function valid(
	data: Record<string, string>,
	action: Action,
	attemptId: string,
	deps: DeviceAuthLinkDeps,
) {
	if (!isAuthControllerId(data.group_id) || !isAuthControllerId(attemptId)) return false;
	if (action === "create")
		return (
			isAuthControllerId(data.identity_id) &&
			["disconnect", "refresh"].includes(data.intent ?? "") &&
			isHash(data.runtime_verifier_hash) &&
			isHash(data.browser_start_hash) &&
			parseCoordinatorAuthLoopback(data.loopback_redirect).ok
		);
	if (action !== "finalize") return true;
	return (
		data.purpose === AUTH_LINK_CHANGE_PURPOSE &&
		data.coordinator_id === deps.config.coordinatorId &&
		data.attempt_id === attemptId &&
		isAuthControllerId(data.identity_id) &&
		isAuthControllerId(data.device_id) &&
		isHash(data.fingerprint) &&
		decodeCoordinatorAuthProof32(data.runtime_verifier) !== null &&
		decodeCoordinatorAuthProof32(data.completion) !== null
	);
}
async function apply(
	c: Context,
	action: Action,
	store: CoordinatorAccountManagementStore,
	data: Record<string, string>,
	attemptId: string,
	signer: CoordinatorAuthLinkSigner,
	config: DeviceAuthLinkDeps["config"],
): Promise<Response> {
	if (action === "status") {
		const status = await store.getAuthLinkChangeAttemptStatus(
			attemptId,
			{ kind: "device", signer },
			config,
		);
		return status ? c.json({ status }) : c.json({ error: "auth_link_change_unavailable" }, 404);
	}
	if (action === "create") {
		const result = await store.createAuthLinkChangeAttempt(
			{
				attemptId,
				signer,
				identityId: data.identity_id as string,
				intent: data.intent as "disconnect" | "refresh",
				runtimeVerifierHash: data.runtime_verifier_hash as string,
				browserStartHash: data.browser_start_hash as string,
				loopbackRedirect: data.loopback_redirect as string,
			},
			config,
		);
		if (result.kind === "rejected") return c.json({ error: "auth_link_change_unavailable" }, 403);
		return c.json(
			{
				status: result.status,
				coordinator_id: config.coordinatorId,
				identity_id: data.identity_id,
			},
			result.kind === "created" ? 201 : 200,
		);
	}
	if (action === "cancel") {
		const result = await store.failAuthLinkChangeAttempt(
			{ attemptId, requester: { kind: "device", signer }, reason: "cancelled" },
			config,
		);
		return result.kind === "rejected"
			? c.json({ error: "auth_link_change_unavailable" }, 403)
			: c.json({ status: result.status });
	}
	const verifier = decodeCoordinatorAuthProof32(data.runtime_verifier);
	const completion = decodeCoordinatorAuthProof32(data.completion);
	if (!verifier || !completion) return c.json({ error: "auth_link_change_unavailable" }, 403);
	const result = await store.finalizeAuthLinkChangeAttempt(
		{
			purpose: AUTH_LINK_CHANGE_PURPOSE,
			coordinatorId: config.coordinatorId,
			attemptId,
			signer,
			groupId: data.group_id as string,
			identityId: data.identity_id as string,
			deviceId: data.device_id as string,
			fingerprint: data.fingerprint as string,
			runtimeVerifierHash: await hashCoordinatorAuthProofBytes32(verifier),
			completionSecretHash: await hashCoordinatorAuthProofBytes32(completion),
		},
		config,
	);
	return result.kind === "rejected"
		? c.json({ error: "auth_link_change_unavailable" }, 403)
		: c.json({ status: result.status });
}
async function handle(c: Context, action: Action, deps: DeviceAuthLinkDeps): Promise<Response> {
	c.header("Cache-Control", "no-store");
	let store: CoordinatorDeviceAuthLinkStore | undefined;
	try {
		const input = await readInput(c, action, deps);
		if (!input || !valid(input.data, action, input.attemptId, deps))
			return c.json({ error: "auth_link_change_invalid_input" }, 400);
		store = deps.storeFactory();
		const auth = await deps.authorizeRequest(store, {
			method: c.req.method,
			url: c.req.url,
			groupId: input.data.group_id as string,
			body: input.raw,
			deviceId: c.req.header("X-Opencode-Device") ?? null,
			signature: c.req.header("X-Opencode-Signature") ?? null,
			timestamp: c.req.header("X-Opencode-Timestamp") ?? null,
			nonce: c.req.header("X-Opencode-Nonce") ?? null,
		});
		if (!auth.ok || !auth.enrollment)
			return (
				deps.rateLimitedResponse(c, `link-change:${action}`, { authenticated: false }) ??
				c.json({ error: "auth_link_change_unavailable" }, deps.authErrorStatus(auth.error))
			);
		const limited = deps.rateLimitedResponse(
			c,
			`${deps.config.coordinatorId}:${auth.enrollment.device_id}`,
			{ authenticated: true },
		);
		if (limited) return limited;
		await assertConfiguredAuthSchema(store);
		if (!store.accountManagement) return c.json({ error: "auth_link_change_unavailable" }, 503);
		const e = auth.enrollment;
		return await apply(
			c,
			action,
			store.accountManagement,
			input.data,
			input.attemptId,
			{
				groupId: e.group_id,
				deviceId: e.device_id,
				publicKey: e.public_key,
				fingerprint: e.fingerprint,
			},
			deps.config,
		);
	} catch (error) {
		if (error instanceof CoordinatorAuthSchemaUpgradeRequiredError)
			return authSchemaUpgradeResponse();
		return c.json({ error: "auth_link_change_unavailable" }, 503);
	} finally {
		await store?.close();
	}
}
export function registerCoordinatorDeviceAuthLinkChangeRoutes(
	app: Hono,
	deps: DeviceAuthLinkDeps,
): void {
	if (!deps.config.enabled) return;
	const { coordinatorId, issuer, revision, redirectUri, enabled } = deps.config;
	const captured = {
		...deps,
		config: Object.freeze({ coordinatorId, issuer, revision, redirectUri, enabled }),
	};
	const dispatch = (c: Context, action: Action) =>
		handle(c, action, captured).catch(() => c.json({ error: "auth_link_change_unavailable" }, 503));
	app.post("/v1/auth/link-changes", (c) => dispatch(c, "create"));
	app.get("/v1/auth/link-changes/:attemptId", (c) => dispatch(c, "status"));
	app.post("/v1/auth/link-changes/:attemptId/finalize", (c) => dispatch(c, "finalize"));
	app.post("/v1/auth/link-changes/:attemptId/cancel", (c) => dispatch(c, "cancel"));
}
