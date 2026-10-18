import { AccountManagementStatusOperations } from "./coordinator-account-management-status.js";
import type { AuthLinkBackend } from "./coordinator-auth-link.js";
import { AuthLinkChangeOperations } from "./coordinator-auth-link-change.js";
import {
	AuthLinkChangeBrowserOperations,
	type AuthLinkChangeBrowserStore,
} from "./coordinator-auth-link-change-browser.js";
import type { CoordinatorAuthLinkChangeStore } from "./coordinator-auth-link-change-contract.js";

export type CoordinatorAccountManagementStore = CoordinatorAuthLinkChangeStore &
	AuthLinkChangeBrowserStore &
	Pick<AccountManagementStatusOperations, "readAccountManagementStatus">;
export interface CoordinatorAccountManagementCapability {
	accountManagement: CoordinatorAccountManagementStore;
}

/** One backend and clock for the browser and signed-device halves. */
export function createCoordinatorAccountManagementStore(
	backend: AuthLinkBackend,
	clock?: () => number,
): CoordinatorAccountManagementStore {
	const changes = new AuthLinkChangeOperations(backend, clock);
	const browser = new AuthLinkChangeBrowserOperations(backend, clock);
	const status = new AccountManagementStatusOperations(backend, clock);
	return {
		readAccountManagementStatus: status.readAccountManagementStatus.bind(status),
		createAuthLinkChangeAttempt: changes.createAuthLinkChangeAttempt.bind(changes),
		getAuthLinkChangeAttemptStatus: changes.getAuthLinkChangeAttemptStatus.bind(changes),
		recordAuthLinkChangeOidcVerified: changes.recordAuthLinkChangeOidcVerified.bind(changes),
		confirmAuthLinkChangeAttempt: changes.confirmAuthLinkChangeAttempt.bind(changes),
		finalizeAuthLinkChangeAttempt: changes.finalizeAuthLinkChangeAttempt.bind(changes),
		failAuthLinkChangeAttempt: changes.failAuthLinkChangeAttempt.bind(changes),
		startAuthLinkChangeBrowser: browser.startAuthLinkChangeBrowser.bind(browser),
		consumeAuthLinkChangeBrowser: browser.consumeAuthLinkChangeBrowser.bind(browser),
		resolveAuthLinkChangeBrowser: browser.resolveAuthLinkChangeBrowser.bind(browser),
	};
}
