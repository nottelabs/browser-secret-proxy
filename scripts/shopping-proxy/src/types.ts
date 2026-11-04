import type { Faker } from "@faker-js/faker";
import type { Page } from "playwright-core";

// Ordered from least to most progress. A run passes once it reaches "checkout".
export const STAGES = [
  "home", // homepage loaded and not a block page
  "product", // a product (or room/car) detail page is open
  "added_to_cart", // the site confirmed the add (counter, toast, drawer)
  "cart", // the cart/basket page lists the item
  "checkout", // the first checkout page: sign-in/guest gate or delivery form
  "checkout_details", // guest details filled and the next step (delivery or payment choice) shown
] as const;
export type Stage = (typeof STAGES)[number];
export const PASS_STAGE: Stage = "checkout";

export type SiteSpec = {
  key: string; // file name without .ts, e.g. "argos"
  name: string;
  url: string; // start URL
  country: string; // ISO 3166-1 alpha-2 for the proxy exit, e.g. "GB"
  fakerLocale: string; // @faker-js/faker locale key, e.g. "en_GB"
  // Short notes for the next person: guest checkout or login wall, cookie banner, quirks.
  notes?: string;
};

export type FlowContext = {
  page: Page;
  faker: Faker;
  // Record progress. Call in order; each call also checks the page for a block.
  reach(stage: Stage, detail?: string): Promise<void>;
  log(message: string): void;
  // Throws BlockedError when the current page is a bot challenge or block page.
  assertNotBlocked(): Promise<void>;
};

export type SiteFlow = (ctx: FlowContext) => Promise<void>;

export type SiteModule = { spec: SiteSpec; flow: SiteFlow };

export class BlockedError extends Error {
  constructor(
    readonly vendor: string,
    readonly evidence: string,
  ) {
    super(`blocked by ${vendor}: ${evidence}`);
    this.name = "BlockedError";
  }
}

export type RunResult = {
  site: string;
  provider: string;
  attempt: number;
  startedAt: string;
  durationMs: number;
  maxStage: Stage | null;
  passed: boolean;
  stages: { stage: Stage; atMs: number; detail?: string; url: string }[];
  blocked: { vendor: string; evidence: string } | null;
  error: string | null;
  finalUrl: string | null;
  finalTitle: string | null;
  sessionId: string | null;
  proxyCountry: string | null;
  screenshot: string | null;
  log: string[];
};
