import type { Locator, Page } from "playwright-core";

// Common consent-manager buttons. Each site can still handle its own banner.
const COOKIE_SELECTORS = [
  "#onetrust-accept-btn-handler",
  "button#didomi-notice-agree-button",
  "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
  "#CybotCookiebotDialogBodyButtonAccept",
  "button[data-testid='uc-accept-all-button']",
  "#sp-cc-accept", // Amazon
  "button#accept-recommended-btn-handler",
  "[data-cookiebanner='accept_button']",
];

const ACCEPT_TEXT =
  /^(accept( all)?( cookies)?|allow all( cookies)?|i accept|agree|alle akzeptieren|alle zulassen|akzeptieren|tout accepter|accepter( et fermer)?|aceptar( todo| todas)?|accetta tutti|alles accepteren|akceptuj(ę)?( wszystkie)?|přijmout vše|souhlasím|aceitar( todos)?|ok)$/i;

export async function acceptCookies(page: Page, timeoutMs = 6000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const sel of COOKIE_SELECTORS) {
      const el = page.locator(sel).first();
      if (await el.isVisible().catch(() => false)) {
        await el.click({ timeout: 3000 }).catch(() => {});
        return true;
      }
    }
    const byText = page.getByRole("button", { name: ACCEPT_TEXT }).first();
    if (await byText.isVisible().catch(() => false)) {
      await byText.click({ timeout: 3000 }).catch(() => {});
      return true;
    }
    await page.waitForTimeout(500);
  }
  return false;
}

// Click the first visible match among several candidate locators.
export async function clickFirstVisible(candidates: Locator[], timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const c of candidates) {
      const el = c.first();
      if (await el.isVisible().catch(() => false)) {
        await el.click();
        return;
      }
    }
    await candidates[0].page().waitForTimeout(400);
  }
  throw new Error(`none of ${candidates.length} candidates became visible`);
}

// Human-ish pause between actions; some bot managers score perfectly regular timing.
export function pause(page: Page, minMs = 400, maxMs = 1200): Promise<void> {
  return page.waitForTimeout(minMs + Math.random() * (maxMs - minMs));
}
