import { expect, it } from "vitest";
import { decodeCoordinatorAccountLinkStatusV3 } from "./coordinator-account-link-status-v3.js";

const pins = {
	groupId: "group-a",
	deviceId: "device-a",
	fingerprint: "a".repeat(64),
	identityId: "identity-a",
};
const linked = {
	...pins,
	version: 3,
	coordinatorId: "coordinator-a",
	authority: "device_claim",
	state: "linked",
	profile: { state: "unavailable" },
	actions: { connect: false, disconnect: true, refresh: true },
};
it("accepts missing display metadata without converting a live link into an unlinked account", () => {
	expect(decodeCoordinatorAccountLinkStatusV3(linked, pins)).toEqual(linked);
});
it("retains an empty verified snapshot and its verification time", () => {
	const status = { ...linked, profile: { state: "verified", verifiedAtMs: 123 } };
	expect(decodeCoordinatorAccountLinkStatusV3(status, pins)).toEqual(status);
});
it("accepts a disconnected account only with non-destructive server actions", () => {
	const status = {
		...linked,
		state: "disconnected",
		actions: { connect: true, disconnect: false, refresh: false },
	};
	expect(decodeCoordinatorAccountLinkStatusV3(status, pins)).toEqual(status);
});
it.each([
	{ ...linked, version: 2 },
	{ ...linked, groupId: "another-group" },
	{ ...linked, deviceId: "another-device" },
	{ ...linked, fingerprint: "b".repeat(64) },
	{ ...linked, account: {} },
	{ ...linked, canLink: true },
	{ ...linked, state: "switch_incomplete" },
	{ ...linked, actions: { connect: true, disconnect: true, refresh: true } },
	{ ...linked, actions: { connect: false, disconnect: "yes", refresh: true } },
	{
		...linked,
		identityId: "another-identity",
		profile: { state: "verified", verifiedAtMs: 1, email: "private@example.test" },
	},
	{ ...linked, state: "revoked", actions: { connect: false, disconnect: true, refresh: true } },
	{ ...linked, state: "conflict", identityId: null, authority: null },
	{ ...linked, profile: { state: "verified", verifiedAtMs: -1 } },
	{ ...linked, profile: { state: "verified", verifiedAtMs: 1, displayName: "unsafe\nname" } },
	{
		...linked,
		profile: {
			state: "verified",
			verifiedAtMs: 1,
			pictureUrl: "https://foreign.example.test/avatar",
		},
	},
])("rejects incompatible, misattributed, or contradictory status replies", (value) => {
	expect(() => decodeCoordinatorAccountLinkStatusV3(value, pins)).toThrow("Invalid status.");
});
