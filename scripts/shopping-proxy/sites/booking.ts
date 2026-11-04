// Booking.com: search London, 1 night ~30 days ahead, 1 adult, reserve a room, fill guest details,
// stop on the "Final details" step where the card form is shown. Never books.
import type { Locator, Page } from "playwright-core";
import { BlockedError, type SiteFlow, type SiteSpec } from "../src/types.js";
import { pause } from "../src/helpers.js";

export const spec: SiteSpec = {
  key: "booking",
  name: "Booking.com",
  url: "https://www.booking.com/index.en-gb.html",
  country: "GB",
  fakerLocale: "en_GB",
  notes:
    "Guest booking without sign-in. Own cookie banner (Accept) plus a sign-in nudge. " +
    "A search scored as automated gets a 301 from /searchresults to the SEO page /city/gb/london (always with a " +
    "HeadlessChrome UA, sometimes otherwise); the flow retries once and then reports a booking soft block. " +
    "Direct searchresults URLs also redirect, so it searches through the form. Variants: 'I'll reserve' or " +
    "'Reserve', 'Next: Final details' or 'Next step', an optional address block, a members-only-price sign-in " +
    "offer (skipped) and sometimes an Insurance step. Stops on 'Finish booking' (payment), never books.",
};

function isoDate(daysAhead: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + daysAhead);
  return d.toISOString().slice(0, 10);
}

async function dismissOverlays(page: Page): Promise<void> {
  // Cookie banner (Accept) and the Genius "Sign in, save money" modal (its X is "Dismiss sign in
  // information."). Both can arrive seconds after load on a slow proxy, so this runs before each step.
  for (const name of [/^accept$/i, /dismiss sign.?in info/i]) {
    const b = page.getByRole("button", { name }).first();
    if (await b.isVisible().catch(() => false)) await b.click({ timeout: 3000 }).catch(() => {});
  }
}

// Clicks after clearing overlays; when an overlay arrives mid-click, clears it and tries again.
async function click(page: Page, target: Locator, tries = 3): Promise<void> {
  for (let i = 1; ; i++) {
    await dismissOverlays(page);
    try {
      await target.click({ timeout: i < tries ? 10_000 : 20_000 });
      return;
    } catch (error) {
      if (i >= tries) throw error;
    }
  }
}

async function openHome(page: Page): Promise<void> {
  await page.goto(spec.url, { waitUntil: "domcontentloaded" });
  await page.locator("input[name='ss']").first().waitFor({ timeout: 45_000 });
  // The cookie banner and the sign-in modal appear a moment after load; give them time to show.
  await page
    .getByRole("button", { name: /^accept$/i })
    .or(page.getByRole("button", { name: /dismiss sign.?in info/i }))
    .first()
    .waitFor({ timeout: 15_000 })
    .catch(() => {});
  await page.waitForTimeout(1000);
  await dismissOverlays(page);
}

// The city itself ("London Greater London, United Kingdom" or "London, United Kingdom"), not a
// landmark or district such as "London Bridge London, ..." or "London Heathrow Airport ...".
const CITY_OPTION = /^\s*London\s*,?\s*(Greater London|England|United Kingdom)/i;

// Fills the search form and submits it. Returns true when the search results page loaded.
async function searchLondon(page: Page, log: (m: string) => void): Promise<boolean> {
  const destination = page.locator("input[name='ss']").first();
  const suggestion = page.getByRole("option", { name: CITY_OPTION }).first();
  // Destination through the autocomplete, so the search carries Booking's own dest_id.
  let picked = false;
  for (let i = 0; i < 3 && !picked; i++) {
    await click(page, destination);
    await destination.fill("");
    await destination.pressSequentially("London", { delay: 120 });
    if (!(await suggestion.waitFor({ timeout: 10_000 }).then(() => true).catch(() => false))) {
      // The suggestion list sometimes needs one more keystroke to open.
      await destination.press("Backspace");
      await destination.type("n", { delay: 150 });
    }
    if (await suggestion.waitFor({ timeout: 8000 }).then(() => true).catch(() => false)) {
      log(`destination suggestion: ${(await suggestion.getAttribute("aria-label").catch(() => null)) ?? "London"}`);
      await click(page, suggestion);
      picked = true;
    } else {
      log("no London city suggestion; typing again");
      await page.keyboard.press("Escape").catch(() => {});
    }
  }
  if (!picked) throw new Error("the destination autocomplete never offered London");
  await dismissOverlays(page);

  const checkin = isoDate(30);
  const checkout = isoDate(31);
  log(`dates ${checkin} -> ${checkout}`);
  const checkinCell = page.locator(`[data-date="${checkin}"]`).first();
  if (!(await checkinCell.waitFor({ timeout: 3000 }).then(() => true).catch(() => false))) {
    await click(page, page.getByRole("button", { name: /select dates|check-in date/i }).first());
  }
  // The calendar can open on the current month in narrow layouts; page forward to the check-in month.
  const nextMonth = page.getByRole("button", { name: /next month/i }).first();
  for (let i = 0; i < 3 && !(await checkinCell.isVisible().catch(() => false)); i++) {
    if (!(await nextMonth.isVisible().catch(() => false))) break;
    await nextMonth.click({ timeout: 5000 }).catch(() => {});
    await page.waitForTimeout(400);
  }
  await click(page, checkinCell);
  await click(page, page.locator(`[data-date="${checkout}"]`).first());

  // Occupancy defaults to 2 adults; step it down to 1.
  await click(page, page.getByRole("button", { name: /number of travell?ers/i }).first());
  const adults = page.locator("#group_adults").first();
  await adults.waitFor({ state: "attached" });
  for (let i = 0; i < 5 && (await adults.inputValue()) !== "1"; i++) {
    await page.locator("#group_adults + button").first().click();
    await pause(page, 200, 500);
  }
  await page.getByRole("button", { name: /^done$/i }).first().click({ timeout: 5000 }).catch(() => {});
  await click(page, page.getByRole("button", { name: /^search$/i }).first());

  // Some sessions land on the SEO city page (/city/gb/london) instead of search results.
  await page.waitForURL(/\/searchresults|\/city\//, { timeout: 60_000, waitUntil: "commit" });
  if (/\/city\//.test(page.url())) {
    log(`search landed on the city page instead of results: ${page.url().slice(0, 100)}`);
    return false;
  }
  return true;
}

export const flow: SiteFlow = async ({ page, faker, reach, log }) => {
  await openHome(page);
  await reach("home");

  let ok = await searchLondon(page, log);
  if (!ok) {
    await openHome(page);
    ok = await searchLondon(page, log);
  }
  if (!ok) {
    // Booking answers a scored-as-bot search with a 301 from /searchresults to the cached SEO city
    // page (always for a HeadlessChrome UA, intermittently for automated headed Chromium).
    throw new BlockedError("booking", "searchresults 301 to /city/gb/london (SEO page) on two searches");
  }

  const cards = page.locator("[data-testid='property-card']");
  if (!(await cards.first().waitFor({ timeout: 45_000 }).then(() => true).catch(() => false))) {
    // Some layouts open the results on the full-screen map, which hides the list; reload without it.
    const url = new URL(page.url());
    if (!/map/i.test(url.hash + url.search)) throw new Error("no property cards on the search results page");
    log("results opened on the map; reloading the list view");
    url.searchParams.delete("map");
    url.hash = "";
    await page.goto(url.href, { waitUntil: "domcontentloaded" });
    await cards.first().waitFor({ timeout: 45_000 });
  }
  await dismissOverlays(page);
  log(`search results: ${page.url().slice(0, 100)}`);

  // Title links open a new tab; navigate in this tab instead. Try a few cards in case one has
  // no bookable room table (sold out or a different layout).
  const hrefs = await page
    .locator("[data-testid='property-card'] a[data-testid='title-link']")
    .evaluateAll((els) => els.slice(0, 6).map((a) => (a as HTMLAnchorElement).href));
  if (hrefs.length === 0) throw new Error("no property links in search results");

  let picked = false;
  for (const href of hrefs) {
    const loaded = await page
      .goto(href, { waitUntil: "domcontentloaded", timeout: 45_000 })
      .then(() => true)
      .catch((e: Error) => (log(`property page did not load (${e.message.split("\n")[0]}); trying next`), false));
    if (!loaded) continue;
    await dismissOverlays(page);
    const roomSelect = page.locator("select[data-testid='select-room-trigger']").first();
    if (!(await roomSelect.waitFor({ timeout: 30_000 }).then(() => true).catch(() => false))) {
      log(`no room table on ${href.split("?")[0]}; trying next property`);
      continue;
    }
    const name = (await page.title().catch(() => "")).replace(/\s*\(updated prices.*$/i, "").trim();
    await reach("product", `${name.slice(0, 60)} ${href.split("?")[0]}`);

    await roomSelect.scrollIntoViewIfNeeded();
    await roomSelect.selectOption("1");
    if ((await roomSelect.inputValue()) !== "1") throw new Error("room select did not take value 1");
    await pause(page);
    // "I'll reserve" or "Reserve" depending on the variant; the top-of-page "Reserve" only scrolls.
    await click(page, page.locator("button.js-reservation-button:visible").first());
    // A room can sell out between search and reserve; Booking then returns to the hotel or the results.
    if (
      await page
        .waitForURL(/secure\.booking\.com\/book\.html/, { timeout: 60_000, waitUntil: "commit" })
        .then(() => true, () => false)
    ) {
      picked = true;
      break;
    }
    log(`reserve did not open the booking form (now ${page.url().slice(0, 80)}); trying next property`);
  }
  if (!picked) throw new Error("no property among the first results opened the booking form");

  await reach("added_to_cart", "room selected and I'll reserve clicked");

  const firstName = page.locator("input[name='firstname']:visible").first();
  await firstName.waitFor({ timeout: 45_000 });
  await page.getByRole("heading", { name: /enter your details/i }).first().waitFor({ timeout: 30_000 });
  await reach("checkout", "Your details");

  // Guest details only, fake data. The form can re-render after a late hydration and drop typed
  // values, so filling only touches empty fields and runs again while they keep getting cleared.
  const first = faker.person.firstName();
  const last = faker.person.lastName();
  const email = faker.internet.email({ firstName: first, lastName: last, provider: "example.com" }).toLowerCase();
  const phoneNumber = `7700900${faker.string.numeric(3)}`;
  const fillIfEmpty = async (field: Locator, value: string) => {
    if ((await field.isVisible().catch(() => false)) && !(await field.inputValue().catch(() => "x"))) await field.fill(value);
  };
  const fillDetails = async () => {
    await fillIfEmpty(firstName, first);
    await fillIfEmpty(page.locator("input[name='lastname']:visible").first(), last);
    await fillIfEmpty(page.locator("input[name='email']:visible").first(), email);
    const country = page.locator("select[name='cc1']:visible").first();
    if ((await country.isVisible().catch(() => false)) && (await country.inputValue()) !== "gb") await country.selectOption("gb");
    const dial = page.locator("select[name='countryCode']:visible").first();
    if ((await dial.isVisible().catch(() => false)) && (await dial.inputValue()) !== "gb") await dial.selectOption("gb");
    await fillIfEmpty(page.locator("input[name='phoneNumber']:visible").first(), phoneNumber);
    // Some properties also require a postal address.
    const optionalFields: [RegExp, string][] = [
      [/^address/i, faker.location.streetAddress()],
      [/^city/i, faker.location.city()],
      [/zip|post ?code/i, faker.location.zipCode()],
    ];
    for (const [label, value] of optionalFields) {
      await fillIfEmpty(page.getByLabel(label).and(page.locator("input:visible")).first(), value);
    }
  };
  const detailsEmpty = async () =>
    (await firstName.isVisible().catch(() => false)) && !(await firstName.inputValue().catch(() => "x"));
  for (let i = 0; i < 3; i++) {
    await fillDetails();
    await page.waitForTimeout(1500);
    if (!(await detailsEmpty())) break;
    log("details form was cleared after filling; filling again");
  }
  await pause(page);
  // "Next: Final details", "Next step", or "Next: Insurance" when a property inserts that step.
  const next = page.getByRole("button", { name: /^next(:|\s+step)/i }).first();
  const nextLabel = ((await next.textContent()) ?? "").trim();
  log(`details button: ${nextLabel}`);
  await next.scrollIntoViewIfNeeded();
  await click(page, next);

  // "Final details" carries the card iframe and the book button: stop here, touch nothing.
  const finalStep = page
    .getByRole("heading", { name: /how would you like to pay|your payment details|final details/i })
    .or(page.getByRole("button", { name: /book with commitment|complete booking/i }))
    .first();
  // Some properties insert an optional travel-insurance step between details and payment.
  const insuranceStep = page.getByRole("heading", { name: /insurance|protect your (stay|trip)/i }).first();
  const detailsForm = page.getByRole("heading", { name: /enter your details/i }).first();
  // Genius properties may open a "members-only price" sign-in offer: skip it, never request a code.
  // The offer can render inside an account.booking.com iframe, so look in every frame.
  const skipMembersOffer = async (): Promise<boolean> => {
    for (const frame of page.frames()) {
      const skip = frame.getByText(/^\s*skip members-only price\s*$/i).first();
      if (await skip.isVisible().catch(() => false)) {
        await skip.click();
        return true;
      }
    }
    return false;
  };
  const deadline = Date.now() + 60_000;
  let lastSubmit = Date.now();
  let submits = 1;
  while (Date.now() < deadline) {
    if (await finalStep.isVisible().catch(() => false)) break;
    if (await skipMembersOffer()) {
      log("skipped the members-only price sign-in offer");
      lastSubmit = Date.now() - 6000; // resubmit shortly if the form stays put
    }
    // After the offer is skipped the form sometimes stays put; submit it again (bounded).
    if (submits < 3 && Date.now() - lastSubmit > 8000 && (await next.isVisible().catch(() => false))) {
      if (await detailsEmpty()) log("details form was cleared; filling again");
      await fillDetails();
      log("still on Your details; submitting again");
      await next.click().catch(() => {});
      lastSubmit = Date.now();
      submits++;
    }
    if (!(await detailsForm.isVisible().catch(() => false)) && (await insuranceStep.isVisible().catch(() => false))) break;
    await page.waitForTimeout(500);
  }
  const leftDetails = !(await detailsForm.isVisible().catch(() => false));
  if (!(await finalStep.isVisible().catch(() => false)) && leftDetails && (await insuranceStep.isVisible().catch(() => false))) {
    log("insurance step shown after details; stopping before payment");
    await reach("checkout_details", "details accepted; next step is the insurance offer before payment");
    return;
  }
  if (!(await finalStep.isVisible().catch(() => false))) {
    const missing = await page
      .locator("input:visible, select:visible")
      .evaluateAll((els) =>
        els
          .filter((e) => (e as HTMLInputElement).required && !(e as HTMLInputElement).value)
          .map((e) => (e as HTMLInputElement).name),
      );
    const invalid = await page
      .locator("[aria-invalid='true']:visible, [role='alert']:visible")
      .evaluateAll((els) => els.map((e) => (e as HTMLInputElement).name || (e as HTMLElement).innerText.trim().slice(0, 80)));
    const dialogs = await page.locator("[role='dialog']:visible").evaluateAll((els) => els.map((e) => (e as HTMLElement).innerText.trim().slice(0, 80)));
    throw new Error(
      `still on Your details; empty required: ${missing.join(", ") || "none"}; invalid: ${invalid.join(", ") || "none"}; dialogs: ${dialogs.join(" | ") || "none"}`,
    );
  }
  log("final details step shown; stopping before payment");
  await reach("checkout_details", "Final details (payment step)");
};
