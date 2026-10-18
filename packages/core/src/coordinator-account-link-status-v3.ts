import type {
	CoordinatorAccountLinkStatusV3,
	CoordinatorAccountProfileV3,
} from "./coordinator-account-management-status.js";
import { projectAccountProfileView } from "./coordinator-auth-browser-view.js";
import { isAuthControllerId } from "./coordinator-auth-controller.js";

function record(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}
function text(value: unknown, max: number): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= max &&
		value.trim().length > 0 &&
		!/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)
	);
}
function profile(value: unknown): CoordinatorAccountProfileV3 {
	if (!record(value)) throw new Error("Invalid status.");
	if (value.state === "unavailable" && Object.keys(value).length === 1)
		return { state: "unavailable" };
	if (
		value.state !== "verified" ||
		!Object.hasOwn(value, "verifiedAtMs") ||
		typeof value.verifiedAtMs !== "number" ||
		!Number.isSafeInteger(value.verifiedAtMs) ||
		value.verifiedAtMs < 0 ||
		Object.keys(value).some(
			(k) => !["state", "verifiedAtMs", "displayName", "email", "pictureUrl"].includes(k),
		)
	)
		throw new Error("Invalid status.");
	const p: CoordinatorAccountProfileV3 = { state: "verified", verifiedAtMs: value.verifiedAtMs };
	if (Object.hasOwn(value, "displayName")) {
		if (!text(value.displayName, 256)) throw new Error("Invalid status.");
		p.displayName = value.displayName;
	}
	if (Object.hasOwn(value, "email")) {
		if (!text(value.email, 320)) throw new Error("Invalid status.");
		p.email = value.email;
	}
	if (Object.hasOwn(value, "pictureUrl")) {
		const view = projectAccountProfileView(value, "https://accounts.google.com");
		if (!view.pictureUrl || view.pictureUrl !== value.pictureUrl)
			throw new Error("Invalid status.");
		p.pictureUrl = view.pictureUrl;
	}
	return p;
}
function decodeActions(value: unknown): CoordinatorAccountLinkStatusV3["actions"] {
	if (
		!record(value) ||
		Object.keys(value).length !== 3 ||
		!["connect", "disconnect", "refresh"].every(
			(k) => Object.hasOwn(value, k) && typeof value[k] === "boolean",
		)
	)
		throw new Error("Invalid status.");
	return {
		connect: value.connect as boolean,
		disconnect: value.disconnect as boolean,
		refresh: value.refresh as boolean,
	};
}
function decodeState(
	value: Record<string, unknown>,
	p: CoordinatorAccountProfileV3,
	actions: CoordinatorAccountLinkStatusV3["actions"],
	identityId: string,
): CoordinatorAccountLinkStatusV3["state"] {
	const state = value.state;
	if (
		state !== "unlinked" &&
		state !== "disconnected" &&
		state !== "linked" &&
		state !== "revoked" &&
		state !== "conflict" &&
		state !== "review_required"
	)
		throw new Error("Invalid status.");
	validateSubject(value, state);
	if ((state !== "linked" || value.identityId !== identityId) && p.state !== "unavailable")
		throw new Error("Invalid status.");
	if (
		(state !== "unlinked" && state !== "disconnected" && actions.connect) ||
		(state !== "linked" && (actions.disconnect || actions.refresh)) ||
		(value.identityId !== identityId && (actions.connect || actions.disconnect || actions.refresh))
	)
		throw new Error("Invalid status.");
	return state;
}
function validateSubject(
	value: Record<string, unknown>,
	state: CoordinatorAccountLinkStatusV3["state"],
): void {
	if (state === "conflict" || state === "review_required") {
		if (value.identityId !== null || value.authority !== null) throw new Error("Invalid status.");
		return;
	}
	if (
		!isAuthControllerId(value.identityId) ||
		(value.authority !== "device_claim" && value.authority !== "controller_attestation")
	)
		throw new Error("Invalid status.");
}
/** No V2 fallback: the coordinated unreleased V3 contract is exact. */
export function decodeCoordinatorAccountLinkStatusV3(
	value: unknown,
	expected: { groupId: string; deviceId: string; fingerprint: string; identityId: string },
): CoordinatorAccountLinkStatusV3 {
	if (
		!record(value) ||
		Object.keys(value).length !== 10 ||
		value.version !== 3 ||
		!isAuthControllerId(value.coordinatorId) ||
		value.groupId !== expected.groupId ||
		value.deviceId !== expected.deviceId ||
		value.fingerprint !== expected.fingerprint
	)
		throw new Error("Invalid status.");
	const actions = decodeActions(value.actions);
	const p = profile(value.profile);
	const state = decodeState(value, p, actions, expected.identityId);
	return {
		version: 3,
		coordinatorId: value.coordinatorId,
		groupId: expected.groupId,
		deviceId: expected.deviceId,
		fingerprint: expected.fingerprint,
		identityId: value.identityId as string | null,
		authority: value.authority as CoordinatorAccountLinkStatusV3["authority"],
		state,
		profile: p,
		actions,
	};
}
