import type { Page } from "playwright-core";

export type BlockSignal = { vendor: string; evidence: string };

// Signatures of bot challenges and block pages. Keep them specific: a false positive
// turns a working site into a "blocked" result.
const TITLE_RULES: [RegExp, string][] = [
  [/^access denied$/i, "akamai"],
  [/^challenge validation$/i, "akamai"],
  [/^just a moment\.{0,3}$/i, "cloudflare"],
  [/^un instant/i, "cloudflare"],
  [/^attention required/i, "cloudflare"],
  [/^pardon our interruption/i, "imperva"],
  [/^robot check$/i, "amazon"],
  [/^access to this page has been denied/i, "perimeterx"],
  [/^acc[eè]s bloqu[eé]/i, "cloudflare"],
];

const BODY_RULES: [RegExp, string][] = [
  [/you don't have permission to access .* on this server/i, "akamai"],
  [/reference #\d+\.[0-9a-f]+\.\d+\.[0-9a-f]+/i, "akamai"],
  [/press (?:&|and) hold/i, "perimeterx"],
  [/verify you are (?:a )?human/i, "cloudflare"],
  [/enter the characters you see below/i, "amazon"],
  [/request unsuccessful\. incapsula/i, "imperva"],
  [/ip address is blocked/i, "akamai"],
];

const FRAME_RULES: [RegExp, string][] = [
  [/captcha-delivery\.com|geo\.captcha-delivery/i, "datadome"],
  // Not challenges.cloudflare.com: sites embed self-clearing Turnstile widgets in normal
  // forms. Cloudflare's blocking interstitials are caught by their title and URL instead.
  [/hcaptcha\.com\/captcha/i, "hcaptcha"],
  [/google\.com\/recaptcha\/api2\/bframe/i, "recaptcha"],
  [/perimeterx|px-cloud\.net|px-cdn\.net\/.*captcha/i, "perimeterx"],
];

// Last two labels of a hostname, or three for second-level public suffixes like co.uk.
function siteDomain(host: string): string {
  const parts = host.split(".");
  const n = /^(co|com|org|net|gov|ac)\.[a-z]{2}$/.test(parts.slice(-2).join(".")) ? 3 : 2;
  return parts.slice(-n).join(".");
}

// Bot managers often answer the page fine but refuse the site's own API calls
// (add-to-cart, search) with a 403, leaving a generic error on screen. Records the first
// such refusal from the site's own domain so the flow can report it as a block.
export function watchBlockedResponses(page: Page, siteUrl: string): { take(): BlockSignal | null } {
  const domain = siteDomain(new URL(siteUrl).hostname);
  let found: BlockSignal | null = null;
  page.context().on("response", (response) => {
    if (found) return;
    const status = response.status();
    if (status !== 403 && status !== 429) return;
    const type = response.request().resourceType();
    if (!["document", "xhr", "fetch"].includes(type)) return;
    const url = new URL(response.url());
    if (siteDomain(url.hostname) !== domain) return;
    const headers = response.headers();
    const vendor =
      "x-datadome" in headers || /datadome/i.test(headers["set-cookie"] ?? "")
        ? "datadome"
        : /blocked-by-aws-waf/i.test(headers["coolblue-waf-custom-response"] ?? "") || "x-amzn-waf-action" in headers
          ? "aws-waf"
        : headers["cf-mitigated"] === "challenge"
          ? "cloudflare"
          : /akamaighost/i.test(headers["server"] ?? "") || /\bak_p\b/.test(headers["server-timing"] ?? "") || "x-reference-error" in headers
            ? "akamai"
            : null;
    if (vendor) found = { vendor, evidence: `${status} on ${type} ${url.pathname.slice(0, 80)}` };
  });
  return {
    take: () => {
      const signal = found;
      found = null;
      return signal;
    },
  };
}

export async function detectBlock(page: Page): Promise<BlockSignal | null> {
  const url = page.url();
  if (/\/cdn-cgi\/challenge-platform|__cf_chl_/i.test(url)) {
    return { vendor: "cloudflare", evidence: `url ${url.slice(0, 120)}` };
  }
  if (/\/risk\/action\/limit/i.test(url)) {
    return { vendor: "shein-risk", evidence: `url ${url.slice(0, 120)}` };
  }
  for (const frame of page.frames()) {
    for (const [re, vendor] of FRAME_RULES) {
      if (re.test(frame.url())) {
        // A visible challenge frame, not a passive sensor script.
        const visible = await frame
          .frameElement()
          .then((el) => el.isVisible())
          .catch(() => false);
        if (visible) return { vendor, evidence: `frame ${frame.url().slice(0, 120)}` };
      }
    }
  }
  const title = (await page.title().catch(() => "")).trim();
  for (const [re, vendor] of TITLE_RULES) {
    if (re.test(title)) return { vendor, evidence: `title "${title}"` };
  }
  const text = await page
    .evaluate(() => (document.body?.innerText ?? "").slice(0, 4000))
    .catch(() => "");
  // Only short pages: a full storefront can mention "verify you are human" in a footer.
  if (text.length < 1500) {
    for (const [re, vendor] of BODY_RULES) {
      if (re.test(text)) return { vendor, evidence: `body "${text.slice(0, 120).replace(/\s+/g, " ")}"` };
    }
  }
  return null;
}
