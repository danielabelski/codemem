import {
	AUTH_LIFECYCLE_CURRENT_READINESS_SQL,
	AUTH_LIFECYCLE_CURRENT_READY_COUNT,
} from "./coordinator-auth-lifecycle-current-readiness.js";
import type { AuthLinkBackend, AuthLinkStatement } from "./coordinator-auth-link.js";

export const AUTH_SCHEMA_UPGRADE_REQUIRED = "coordinator_auth_schema_upgrade_required";
export const AUTH_SCHEMA_UPGRADE_MESSAGE =
	"Coordinator authentication needs the explicit lifecycle schema upgrade. Pause auth writers and review the preserving migration before applying it. Do not replay the legacy authority cutover or restore older data automatically. Device-signed sync remains available.";

export class CoordinatorAuthSchemaUpgradeRequiredError extends Error {
	constructor() {
		super(AUTH_SCHEMA_UPGRADE_MESSAGE);
		this.name = AUTH_SCHEMA_UPGRADE_REQUIRED;
	}
}

export const AUTH_SCHEMA_READY_COUNT = AUTH_LIFECYCLE_CURRENT_READY_COUNT;
export const AUTH_SCHEMA_READINESS_SQL = AUTH_LIFECYCLE_CURRENT_READINESS_SQL;

export interface CoordinatorAuthSchemaStore {
	assertAuthSchemaReady(): Promise<void>;
}

export async function assertCoordinatorAuthSchema(
	backend: Pick<AuthLinkBackend, "first">,
): Promise<void> {
	const row = await backend.first<{ ready: number }>({
		sql: AUTH_SCHEMA_READINESS_SQL,
		values: [],
	});
	if (row?.ready !== AUTH_SCHEMA_READY_COUNT) throw new CoordinatorAuthSchemaUpgradeRequiredError();
}

/** Protect every optional-auth SQL entry, including trusted callers outside HTTP. */
export function withCoordinatorAuthSchema(backend: AuthLinkBackend): AuthLinkBackend {
	return {
		first: async <T>(statement: AuthLinkStatement) => {
			await assertCoordinatorAuthSchema(backend);
			return backend.first<T>(statement);
		},
		run: async (statement) => {
			await assertCoordinatorAuthSchema(backend);
			return backend.run(statement);
		},
		batch: async (statements) => {
			await assertCoordinatorAuthSchema(backend);
			return backend.batch(statements);
		},
	};
}

export function authPersistenceError(error: unknown, fallback: string): Error {
	if (String(error).includes("no such table: coordinator_auth_link_profiles"))
		return new CoordinatorAuthSchemaUpgradeRequiredError();
	return error instanceof CoordinatorAuthSchemaUpgradeRequiredError ? error : new Error(fallback);
}

export async function assertConfiguredAuthSchema(
	store: Partial<CoordinatorAuthSchemaStore>,
): Promise<void> {
	if (typeof store.assertAuthSchemaReady !== "function")
		throw new Error("auth_schema_readiness_unavailable");
	await store.assertAuthSchemaReady();
}

export function authSchemaUpgradeResponse(): Response {
	return Response.json(
		{ error: AUTH_SCHEMA_UPGRADE_REQUIRED, message: AUTH_SCHEMA_UPGRADE_MESSAGE },
		{
			status: 503,
			headers: {
				"Cache-Control": "no-store",
				"X-Codemem-Auth-Error": AUTH_SCHEMA_UPGRADE_REQUIRED,
				"Referrer-Policy": "no-referrer",
				"X-Content-Type-Options": "nosniff",
			},
		},
	);
}
