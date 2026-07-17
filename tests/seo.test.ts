import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");

function read(relativePath: string): string {
  return readFileSync(resolve(root, relativePath), "utf8");
}

describe("public search pages", () => {
  it.each([
    [
      "public/redact-cisco-config.html",
      "Redact Cisco configurations before sharing",
      "Redact the config. Preserve the evidence.",
    ],
    [
      "public/sanitize-cli-output.html",
      "Sanitize network CLI output without losing context",
      "Clean the capture. Keep the signal.",
    ],
    [
      "public/prepare-network-logs-for-ai.html",
      "Prepare network logs for AI without exposing secrets",
      "Share the problem. Not the production identity.",
    ],
  ])("uses a task-focused H1 and retains its product voice on %s", (path, heading, slogan) => {
    const html = read(path);
    expect(html).toContain(`<h1>${heading}</h1>`);
    expect(html).toContain(`<p class="guide-slogan">${slogan}</p>`);
  });

  it("publishes truthful application structured data", () => {
    const html = read("index.html");
    expect(html).toContain('"@type": "SoftwareApplication"');
    expect(html).toContain('"price": "0"');
    expect(html).not.toContain("aggregateRating");
  });
});
