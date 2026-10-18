import { expect, test } from "@playwright/test";
import { SIGNATURE_VERSION } from "../../core/src/sync-auth";
import { fixture } from "./fixture";

for (const intent of ["refresh", "disconnect"] as const) {
	test(`${intent}: real isolated popup waits for signed finalization and trusted runtime acknowledgement`, async ({
		page,
		context,
	}) => {
		// Arrange: actual Viewer registry, runtime, coordinator and isolated local TLS.
		const f = await fixture(context);
		try {
			const preserved = f.preserved();
			expect(preserved.history.length).toBeGreaterThan(0);
			expect(preserved.grants.length).toBeGreaterThan(0);
			await page.goto(f.viewerOrigin);
			const viewerUrl = page.url();
			let viewerDialogs = 0;
			page.on("dialog", async (dialog) => {
				viewerDialogs++;
				await dialog.dismiss();
			});
			const pages: string[] = [];
			context.on("response", (response) => {
				if (response.request().isNavigationRequest()) pages.push(response.url());
			});

			// Act: no Viewer confirmation. Provider authorization alone is synthetic.
			const popupPromise = context.waitForEvent("page");
			const provider = context.waitForEvent("response", {
				predicate: (response) => response.url().startsWith("https://accounts.google.com/authorize"),
			});
			await page
				.getByRole("button", {
					name: intent === "refresh" ? "Refresh profile" : "Unlink Google account",
					exact: true,
				})
				.click();
			const popup = await popupPromise;
			const hosted = await provider;
			expect(hosted.headers()["cross-origin-opener-policy"]).toBe("same-origin");
			await expect(
				popup.getByRole("heading", { name: "Synthetic provider authorization" }),
			).toBeVisible();
			expect(await popup.evaluate(() => window.opener === null)).toBe(true);
			expect(await context.cookies(f.origin)).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						name: "__Host-codemem-auth-transaction",
						secure: true,
						httpOnly: true,
						sameSite: "Lax",
						path: "/",
					}),
				]),
			);
			await popup.getByRole("link", { name: "Complete synthetic sign-in" }).click();
			if (intent === "disconnect") {
				await expect(
					popup.getByRole("button", { name: "Unlink Google account", exact: true }),
				).toHaveCount(1);
				expect(f.finalRequests).toHaveLength(0);
				await popup.getByRole("button", { name: "Unlink Google account", exact: true }).click();
			}
			await f.finalizationStarted;
			// Browser proof alone cannot publish profile data or end the link generation.
			expect(await f.status()).toMatchObject({
				kind: "status",
				status: { state: "linked", profile: { displayName: "Original profile" } },
			});
			expect(f.finalRequests).toHaveLength(0);
			f.dispatch();
			await f.finalization;
			expect(await f.status()).toMatchObject({
				kind: "status",
				status:
					intent === "refresh"
						? { state: "linked", profile: { displayName: "Refreshed browser profile" } }
						: { state: "disconnected" },
			});
			await expect.poll(f.receipts).toBeGreaterThan(0);

			// Assert negative: effects alone cannot close a physical COOP-separated popup.
			expect(viewerDialogs).toBe(0);
			expect(await popup.evaluate(() => window.opener === null)).toBe(true);
			expect(popup.isClosed()).toBe(false);
			await expect(
				popup.getByRole("heading", { name: "Finishing account request…" }),
			).toBeVisible();
			const receipt = await popup.locator("main").getAttribute("data-receipt");
			expect(
				await popup.evaluate(
					async (token) =>
						(
							await fetch("/codemem/auth/result", { headers: { "X-Codemem-Receipt": token ?? "" } })
						).json(),
					receipt,
				),
			).toEqual({ completed: false });
			const receiptOrigin = new URL(popup.url()).origin;
			// The real browser must reject a cross-origin receipt read, even with its token.
			expect(
				await page.evaluate(
					async ({ origin, token }) => {
						try {
							await fetch(`${origin}/codemem/auth/result`, {
								headers: { "X-Codemem-Receipt": token ?? "" },
							});
							return "unexpected response";
						} catch {
							return "blocked by CORS";
						}
					},
					{ origin: receiptOrigin, token: receipt },
				),
			).toBe("blocked by CORS");
			expect(page.url()).toBe(viewerUrl);
			expect(f.finalRequests).toHaveLength(1);
			expect(f.browserPosts).toEqual(
				intent === "refresh"
					? ["/auth/link-change/start"]
					: ["/auth/link-change/start", "/auth/link-change/confirm"],
			);
			expect(f.finalRequests[0]?.headers.get("X-Opencode-Signature")).toMatch(
				new RegExp(`^${SIGNATURE_VERSION}:`),
			);
			expect(f.preserved()).toEqual(preserved);
			expect(f.rows("coordinator_auth_link_change_attempts")).toEqual(
				expect.arrayContaining([expect.objectContaining({ state: "completed", intent })]),
			);

			// Assert positive: only the actual runtime's successful receipt allows close.
			const closed = popup.waitForEvent("close");
			f.release();
			await closed;
			expect(page.url()).toBe(viewerUrl);
			if (intent === "refresh")
				await expect(page.getByText("Refreshed browser profile", { exact: true })).toBeVisible();
			else
				await expect(
					page.getByText(
						"Google account disconnected. Your Identity, devices, history, and sharing remain in place.",
						{ exact: true },
					),
				).toBeVisible();
			expect(f.blocked).toEqual([]);
			expect(pages.some((url) => url.includes("/auth/callback"))).toBe(true);
		} finally {
			await f.close();
		}
	});
}

test("blocked popup offers a new-tab fallback without navigating Viewer; cancelling cannot unlink", async ({
	page,
	context,
}) => {
	// Arrange: only window.open is blocked; no operation/runtime result is mocked.
	const f = await fixture(context);
	try {
		await page.addInitScript(() => {
			const open = window.open.bind(window);
			let attempts = 0;
			window.open = (...args) => {
				if (attempts++ === 0) return null;
				return open(...args);
			};
		});
		await page.goto(f.viewerOrigin);
		const preserved = f.preserved();
		const viewerUrl = page.url();
		// Act
		await page.getByRole("button", { name: "Unlink Google account", exact: true }).click();
		await expect(
			page.getByRole("button", { name: "Open Google sign-in", exact: true }),
		).toBeVisible();
		// Assert: fallback never navigates or claims completion; cancel stays linked.
		expect(context.pages()).toHaveLength(1);
		expect(page.url()).toBe(viewerUrl);
		expect(f.finalRequests).toHaveLength(0);
		const opened = context.waitForEvent("page");
		await page.getByRole("button", { name: "Open Google sign-in", exact: true }).click();
		const popup = await opened;
		await expect(
			popup.getByRole("heading", { name: "Synthetic provider authorization" }),
		).toBeVisible();
		expect(page.url()).toBe(viewerUrl);
		await page.getByRole("button", { name: "Cancel unlinking", exact: true }).click();
		await expect
			.poll(() => f.rows("coordinator_auth_link_change_attempts"))
			.toEqual(expect.arrayContaining([expect.objectContaining({ state: "failed" })]));
		await expect(page.getByText("Original profile", { exact: true })).toBeVisible();
		expect(f.preserved()).toEqual(preserved);
		expect(f.blocked).toEqual([]);
	} finally {
		await f.close();
	}
});

for (const interruption of ["cancel", "stale"] as const) {
	test(`hosted unlink ${interruption} never publishes success`, async ({ page, context }) => {
		// Arrange
		const f = await fixture(context);
		try {
			await page.goto(f.viewerOrigin);
			const preserved = f.preserved();
			const viewerUrl = page.url();
			const opened = context.waitForEvent("page");
			await page.getByRole("button", { name: "Unlink Google account", exact: true }).click();
			const popup = await opened;
			await popup.getByRole("link", { name: "Complete synthetic sign-in" }).click();
			await expect(
				popup.getByRole("button", { name: "Unlink Google account", exact: true }),
			).toBeVisible();
			// Act
			if (interruption === "cancel")
				await popup.getByRole("button", { name: "Cancel", exact: true }).click();
			else {
				f.stale();
				await popup.getByRole("button", { name: "Unlink Google account", exact: true }).click();
			}
			// Assert
			await expect
				.poll(() => f.rows("coordinator_auth_link_change_attempts"))
				.toEqual(expect.arrayContaining([expect.objectContaining({ state: "failed" })]));
			expect(f.finalRequests).toHaveLength(0);
			expect(f.rows("coordinator_auth_account_links")).toEqual(
				expect.arrayContaining([expect.objectContaining({ ended_at_ms: null })]),
			);
			expect(f.preserved()).toEqual(preserved);
			expect(page.url()).toBe(viewerUrl);
			expect(popup.isClosed()).toBe(false);
			expect(f.blocked).toEqual([]);
		} finally {
			await f.close();
		}
	});
}
