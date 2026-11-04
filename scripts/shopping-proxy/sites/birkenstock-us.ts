// Birkenstock US: search "care kit", add a one-size shoe care kit, guest checkout, fill shipping
// with fake contact data, stop on the payment method step.
import type { Locator, Page } from "playwright-core";
import type { SiteFlow, SiteSpec } from "../src/types.js";
import { pause } from "../src/helpers.js";

export const spec: SiteSpec = {
  key: "birkenstock-us",
  name: "Birkenstock US",
  url: "https://www.birkenstock.com/us/",
  country: "US",
  fakerLocale: "en_US",
  notes:
    "Guest checkout (cart links to /checkout/?asguest=true). OneTrust notice with only a Close button. " +
    "US visitors get a 'Want free shipping on your next purchase?' email-signup modal (declined with " +
    "'No, thanks' or its X). Care kits are one size, no variant choice. The shipping address must pass " +
    "verification: the flow picks a Google Places suggestion for a generic street ('100 Main St') and " +
    "accepts the 'Confirm address' suggestion. Narrow layouts hide the search box, so the flow falls back " +
    "to the search URL. Stops on step 2 'Payment Method' without opening any payment option.",
};

// Behind slow proxies a page can take a minute to reach DOMContentLoaded; navigations only wait for
// the response and each step then waits for the element it needs.
const NAV = { waitUntil: "commit" as const, timeout: 60_000 };

// Declines the Klaviyo email-signup modal and closes the OneTrust notice. Never subscribes.
// One combined locator per overlay keeps this cheap on slow remote browsers.
async function closeOverlays(page: Page, log: (m: string) => void): Promise<void> {
  const decline = page
    .locator("button.klaviyo-close-form")
    .or(page.getByRole("button", { name: /^\s*no,? thanks\s*$/i }))
    .or(page.locator("[role='dialog'], [aria-modal='true']").filter({ hasText: /free shipping on your next purchase/i }).getByRole("button", { name: /close|dismiss/i }))
    .filter({ visible: true })
    .first();
  if (await decline.isVisible().catch(() => false)) {
    await decline.click({ timeout: 3000 }).then(() => log("closed the email-signup modal"), () => {});
  }
  // OneTrust notice: a "close" variant (no accept button) or the usual accept button.
  const cookies = page
    .locator("#onetrust-banner-sdk")
    .getByRole("button", { name: /^close$/i })
    .or(page.locator("#onetrust-accept-btn-handler"))
    .filter({ visible: true })
    .first();
  if (await cookies.isVisible().catch(() => false)) await cookies.click({ timeout: 3000 }).catch(() => {});
}

// Clicks until `done` holds, clearing overlays between tries; a click that timed out may still
// have started a slow navigation, so each try waits for the outcome first.
async function clickUntil(
  page: Page,
  log: (m: string) => void,
  target: Locator,
  done: () => Promise<boolean>,
  what: string,
  tries = 3,
): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (i > 0) log(`${what}: no effect yet; try ${i + 1}/${tries}`);
    await closeOverlays(page, log);
    if (await done()) return;
    await target.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    const err = await target.click({ timeout: 10_000 }).then(
      () => null,
      (e: Error) => e.message.split("\n")[0],
    );
    if (err) log(`${what}: click failed (${err.slice(0, 80)}); retrying`);
    const until = Date.now() + 20_000;
    while (Date.now() < until) {
      if (await done()) return;
      await page.waitForTimeout(500);
    }
  }
  if (!(await done())) throw new Error(`${what}: no effect after ${tries} tries`);
}

export const flow: SiteFlow = async ({ page, faker, reach, log }) => {
  await page.goto(spec.url, NAV);
  // The cart link is an icon in narrow layouts; its href is stable.
  await page.locator("a[href*='/cart']").first().waitFor({ state: "attached", timeout: 60_000 });
  await page.locator("#onetrust-banner-sdk").waitFor({ timeout: 6000 }).catch(() => {});
  await closeOverlays(page, log);
  await reach("home");

  // Search through the header box; fall back to the search URL if the box is not usable.
  const box = page.getByRole("textbox", { name: /^search/i }).or(page.getByPlaceholder(/^search/i)).first();
  if (await box.isVisible().catch(() => false)) {
    await closeOverlays(page, log);
    const typed = await box
      .click({ timeout: 8000 })
      .then(() => box.pressSequentially("care kit", { delay: 80 }))
      .then(() => box.press("Enter"))
      .then(() => true, () => false);
    if (typed) await page.waitForURL(/\/search/, { ...NAV, timeout: 20_000 }).catch(() => {});
  }
  if (!/\/search/.test(page.url())) {
    log("search box not usable; opening the search URL");
    await page.goto(new URL("search/?q=care+kit", spec.url).href, NAV);
  }
  // Product tiles link to /<name>/<id>.html; the full-info link carries the product name.
  const named = page.getByRole("link", { name: /view full product information for .*care kit/i });
  const anyKit = page.locator("main a[href*='care-kit'][href$='.html'], a[href*='care-kit'][href*='.html']");
  await named.or(anyKit).first().waitFor({ state: "attached", timeout: 60_000 });
  await closeOverlays(page, log);
  // Prefer the shoe care kit; any one-size care kit works.
  const shoeKit = page.getByRole("link", { name: /view full product information for .*shoe care kit/i }).first();
  const product = (await shoeKit.count()) > 0 ? shoeKit : (await named.count()) > 0 ? named.first() : anyKit.first();
  const href = await product.getAttribute("href");
  if (!href) throw new Error("no care kit link in the search results");
  log(`product ${href}`);
  // Navigate rather than click the tile: the signup modal can cover it.
  await page.goto(new URL(href, page.url()).href, NAV);
  const add = page.getByRole("button", { name: /^add to cart$/i }).first();
  await add.waitFor({ timeout: 60_000 });
  const title = (await page.getByRole("heading", { level: 1 }).first().innerText().catch(() => "")).trim();
  await reach("product", title);

  await pause(page);
  // The header cart link announces the count: "Cart - View your cart with 1 item."
  const cartLink = page.getByRole("link", { name: /cart.*with [1-9]\d* item/i }).first();
  await clickUntil(page, log, add, () => cartLink.count().then((n) => n > 0), "add to cart", 2);
  await reach("added_to_cart", (await cartLink.getAttribute("aria-label")) ?? "cart count updated");

  await page.goto(new URL("cart/", spec.url).href, NAV);
  await page.getByRole("heading", { name: /shopping cart.*[1-9]\d* item/i }).first().waitFor({ timeout: 60_000 });
  await closeOverlays(page, log);
  await reach("cart");

  await pause(page);
  const email = page.locator("#dwfrm_shipping_email");
  const proceed = page.getByRole("link", { name: /proceed to checkout/i }).filter({ visible: true }).first();
  await clickUntil(page, log, proceed, () => Promise.resolve(/\/checkout/.test(page.url())), "proceed to checkout");
  // The checkout page can take long to render behind a slow proxy; wait for the form, not "load".
  await email.waitFor({ timeout: 60_000 });
  await reach("checkout", "guest shipping form");

  // Guest shipping details: fake contact data, a verifiable public street address.
  await closeOverlays(page, log);
  const F = "#dwfrm_shipping_shippingAddress_addressFields_";
  const first = faker.person.firstName();
  const last = faker.person.lastName();
  await email.fill(faker.internet.email({ firstName: first, lastName: last, provider: "example.com" }).toLowerCase());
  await page.locator(`${F}firstName`).fill(first);
  await page.locator(`${F}lastName`).fill(last);
  await page.locator(`${F}phone`).fill(`202555${faker.string.numeric(4)}`);
  const street = page.locator(`${F}address1`);
  const suggestion = page.locator(".pac-container .pac-item").filter({ visible: true }).first();
  // Google Places can be slow to answer behind a proxy; retype once if no suggestion shows.
  for (let i = 0; i < 2; i++) {
    await street.click();
    await street.fill("");
    await street.pressSequentially("100 Main St", { delay: 90 });
    if (await suggestion.waitFor({ timeout: 20_000 }).then(() => true, () => false)) break;
    log("no address suggestion yet; typing again");
  }
  await suggestion.click();
  // Places fills city, zip and state; wait for the zip to prove it.
  await page.waitForFunction((sel) => !!(document.querySelector(sel) as HTMLInputElement | null)?.value, `${F}postalCode`, {
    timeout: 20_000,
  });
  log(
    `address ${await street.inputValue()}, ${await page.locator(`${F}city`).inputValue()} ${await page
      .locator(`${F}postalCode`)
      .inputValue()}`,
  );
  await pause(page);
  const toPayment = page.getByRole("button", { name: /continue to payment method/i }).first();
  // Address verification usually asks to confirm the standardized address.
  const confirm = page.getByRole("button", { name: /use this address/i }).first();
  const paymentStep = page.getByRole("button", { name: /review order/i }).first();
  const onBilling = () => Promise.resolve(/step=billing/.test(page.url()));
  await clickUntil(
    page,
    log,
    toPayment,
    async () => (await onBilling()) || (await confirm.isVisible().catch(() => false)) || (await paymentStep.isVisible().catch(() => false)),
    "continue to payment method",
    2,
  );
  if (await confirm.isVisible().catch(() => false)) {
    await clickUntil(page, log, confirm, onBilling, "use this address", 2);
  }

  // Payment method step: stop here, never open a payment option.
  await page.waitForURL(/step=billing/, NAV);
  await paymentStep.waitFor({ timeout: 45_000 });
  log("payment method step shown; stopping before payment");
  await reach("checkout_details", "payment method step");
};
