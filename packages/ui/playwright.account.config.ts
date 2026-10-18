import { resolve } from "node:path";
import { defineConfig } from "@playwright/test";

export default defineConfig({
	testDir: "./account-e2e",
	testMatch: "management.spec.ts",
	outputDir: resolve(import.meta.dirname, "../../.tmp/account-browser/results"),
	reporter: "list",
	workers: 1,
	retries: 0,
	timeout: 60_000,
	forbidOnly: true,
	use: {
		browserName: "chromium",
		ignoreHTTPSErrors: true, // Only ephemeral contexts and the fixture's self-signed loopback server.
		serviceWorkers: "block",
		trace: "retain-on-failure",
	},
});
