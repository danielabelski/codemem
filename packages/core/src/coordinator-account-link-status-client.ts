import { normalizeCoordinatorAccountLinkOrigin } from "./coordinator-account-link-receiver.js";
import {
	readAccountLinkDevice,
	signAccountLinkRequest,
} from "./coordinator-account-link-signer.js";
import { decodeCoordinatorAccountLinkStatusV3 } from "./coordinator-account-link-status-v3.js";
import type { CoordinatorAccountLinkStatusV3 } from "./coordinator-account-management-status.js";
import { isAuthControllerId } from "./coordinator-auth-controller.js";
import type { CoordinatorDeviceLocalEvidence } from "./coordinator-device-local.js";

export interface ReadCoordinatorAccountLinkStatusOptions {
	dbPath: string;
	keysDir?: string;
	groupId: string;
	coordinatorUrl: string;
	identityId: string;
	signal?: AbortSignal;
	fetch?: typeof globalThis.fetch;
}
export type CoordinatorAccountLinkStatusRead =
	| { kind: "status"; status: CoordinatorAccountLinkStatusV3 }
	| { kind: "unsupported" }
	| {
			kind: "unavailable";
			code:
				| "coordinator_unavailable"
				| "coordinator_auth_schema_upgrade_required"
				| "rate_limited"
				| "coordinator_rejected"
				| "coordinator_incompatible"
				| "coordinator_unreachable"
				| "invalid_response"
				| "device_unavailable";
	  };
type UnavailableCode = Extract<CoordinatorAccountLinkStatusRead, { kind: "unavailable" }>["code"];
function unavailable(code: UnavailableCode): CoordinatorAccountLinkStatusRead {
	return { kind: "unavailable", code };
}
/** Race even injected transports/streams that do not implement AbortSignal themselves. */
async function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
	let onAbort = () => {};
	try {
		const aborted = new Promise<never>((_, reject) => {
			onAbort = () => reject(new Error("Status read stopped."));
			signal.addEventListener("abort", onAbort, { once: true });
			if (signal.aborted) onAbort();
		});
		return await Promise.race([operation, aborted]);
	} finally {
		signal.removeEventListener("abort", onAbort);
	}
}
function discard(response: Response): void {
	void response.body?.cancel().catch(() => {});
}
async function boundedJson(response: Response, signal: AbortSignal): Promise<unknown> {
	if (!response.body) throw new Error("Invalid status.");
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	try {
		while (true) {
			const { done, value } = await abortable(reader.read(), signal);
			if (done) break;
			size += value.byteLength;
			if (size > 16384) throw new Error("Invalid status.");
			chunks.push(value);
		}
		return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
	} finally {
		// Do not let an uncooperative stream's cancel promise defeat the deadline.
		void reader.cancel().catch(() => {});
		reader.releaseLock();
	}
}
function responseFailure(response: Response): CoordinatorAccountLinkStatusRead | null {
	const status = response.status;
	if (
		status === 503 &&
		response.headers.get("X-Codemem-Auth-Error") === "coordinator_auth_schema_upgrade_required"
	)
		return unavailable("coordinator_auth_schema_upgrade_required");
	if (status === 200) return null;
	if (status === 404) return { kind: "unsupported" };
	if (status === 400) return unavailable("coordinator_incompatible");
	if (status === 408 || (status >= 500 && status < 600))
		return unavailable("coordinator_unavailable");
	if (status === 429) return unavailable("rate_limited");
	if ([401, 403, 409].includes(status)) return unavailable("coordinator_rejected");
	return unavailable("invalid_response");
}
async function readStatus(
	options: ReadCoordinatorAccountLinkStatusOptions,
	signal: AbortSignal,
): Promise<CoordinatorAccountLinkStatusRead> {
	const origin = normalizeCoordinatorAccountLinkOrigin(options.coordinatorUrl);
	const groupId = options.groupId;
	if (!origin || !isAuthControllerId(groupId) || !isAuthControllerId(options.identityId))
		return unavailable("invalid_response");
	if (signal.aborted) return unavailable("coordinator_unreachable");
	const url = new URL("/v1/auth/account-link-status", origin);
	url.searchParams.set("group_id", groupId);
	url.searchParams.set("coordinator_origin", origin);
	url.searchParams.set("identity_id", options.identityId);
	let device: CoordinatorDeviceLocalEvidence;
	let headers: ReturnType<typeof signAccountLinkRequest>;
	try {
		device = readAccountLinkDevice(options.dbPath);
		headers = signAccountLinkRequest({
			dbPath: options.dbPath,
			keysDir: options.keysDir,
			device,
			method: "GET",
			url: url.href,
			bodyBytes: Buffer.alloc(0),
		});
	} catch {
		return unavailable("device_unavailable");
	}
	if (signal.aborted) return unavailable("coordinator_unreachable");
	const pending = (options.fetch ?? globalThis.fetch)(url.href, {
		method: "GET",
		headers,
		redirect: "manual",
		signal,
	}).then((response) => {
		if (signal.aborted) discard(response);
		return response;
	});
	const response = await abortable(pending, signal);
	if (signal.aborted) {
		discard(response);
		return unavailable("coordinator_unreachable");
	}
	const failed = responseFailure(response);
	if (failed) {
		discard(response);
		return failed;
	}
	try {
		const body = await boundedJson(response, signal);
		if (signal.aborted) return unavailable("coordinator_unreachable");
		return {
			kind: "status",
			status: decodeCoordinatorAccountLinkStatusV3(body, {
				groupId,
				deviceId: device.deviceId,
				fingerprint: device.fingerprint,
				identityId: options.identityId,
			}),
		};
	} catch {
		return unavailable(signal.aborted ? "coordinator_unreachable" : "invalid_response");
	}
}

/** Read remote status only. Failures never imply that an account is unlinked. */
export async function readCoordinatorAccountLinkStatus(
	options: ReadCoordinatorAccountLinkStatusOptions,
): Promise<CoordinatorAccountLinkStatusRead> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), 10_000);
	try {
		const signal = options.signal
			? AbortSignal.any([controller.signal, options.signal])
			: controller.signal;
		return await readStatus(options, signal);
	} catch {
		return unavailable("coordinator_unreachable");
	} finally {
		clearTimeout(timer);
		controller.abort();
	}
}
