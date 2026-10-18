import { createHash } from "node:crypto";
import { expect, vi } from "vitest";
import type { CoordinatorAuthBrowserConfig } from "./coordinator-auth-browser-transaction-contract.js";
import type { LinkFixture } from "./coordinator-auth-link-test-fixtures.js";

type BrowserProofFixture = Pick<LinkFixture, "cfg"> & {
	store: Pick<
		LinkFixture["store"],
		"startAuthBrowserTransaction" | "consumeAuthBrowserTransaction"
	>;
};

function fixtureHash(key: string) {
	return createHash("sha256").update(`codemem-test-browser:${key}`).digest("hex");
}

/** Fix only the synchronous server hash draw; never changes the submitted proof. */
export function withBrowserHash<T>(hash: string, start: () => T): T {
	const entropy = vi
		.spyOn(globalThis.crypto, "getRandomValues")
		.mockReturnValueOnce(Uint8Array.from(Buffer.from(hash, "hex")));
	try {
		return start();
	} finally {
		entropy.mockRestore();
	}
}

/** Synthetic persistence proof, not a provider token or an OIDC signature fixture. */
export async function startBrowserProof(
	f: BrowserProofFixture,
	input: { browserTransactionHash: string; attemptId?: string; browserStartHash?: string },
	config: CoordinatorAuthBrowserConfig = browserProofConfig(f),
) {
	const key = `${config.coordinatorId}:${input.attemptId ?? "signin"}:${input.browserTransactionHash}`;
	const materials = {
		stateHash: fixtureHash(`state:${key}`),
		binderHash: fixtureHash(`binder:${key}`),
		nonce: fixtureHash(`nonce:${key}`),
		pkceVerifier: fixtureHash(`pkce:${key}`),
	};
	let startInput: Parameters<typeof f.store.startAuthBrowserTransaction>[0];
	if (input.attemptId === undefined) {
		startInput = { ...materials, purpose: "signin" };
	} else {
		if (input.browserStartHash === undefined)
			throw new Error("Link proof fixture requires its start commitment");
		startInput = {
			...materials,
			purpose: "link",
			attemptId: input.attemptId,
			browserStartHash: input.browserStartHash,
		};
	}
	const started = withBrowserHash(input.browserTransactionHash, () =>
		f.store.startAuthBrowserTransaction(startInput, config),
	);
	expect(await started).toMatchObject({ kind: "started" });
	return materials;
}

export function browserProofConfig(f: Pick<LinkFixture, "cfg">): CoordinatorAuthBrowserConfig {
	return { ...f.cfg };
}

export async function consumeSigninProof(
	f: BrowserProofFixture,
	hash: string,
	config = browserProofConfig(f),
) {
	const materials = await startBrowserProof(f, { browserTransactionHash: hash }, config);
	expect(await f.store.consumeAuthBrowserTransaction(materials, config)).toEqual({
		kind: "consumed",
		purpose: "signin",
		browserTransactionHash: hash,
		nonce: materials.nonce,
		pkceVerifier: materials.pkceVerifier,
	});
	return materials;
}
