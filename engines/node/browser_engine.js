import process from "node:process";
import {fileURLToPath} from "node:url";

function now() {
  return new Date().toISOString();
}

export function detectLoginSignals(html, url) {
  const lower = `${html} ${url}`.toLowerCase();
  return lower.includes("type=\"password\"") || lower.includes("/login") || lower.includes("/signin");
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Resource-blocking patterns for crawl-only mode.
 * Images, fonts, and media are blocked to cut page load time
 * substantially on media-heavy sites.
 */
const BLOCKED_RESOURCE_TYPES = [
  "**/*.{png,jpg,jpeg,gif,svg,webp,ico,bmp,tiff}",
  "**/*.{woff,woff2,ttf,eot,otf}",
  "**/*.{mp4,webm,ogg,mp3,wav,flac}",
  "**/*.{avi,mov,wmv,flv}",
];

/**
 * Default navigation timeout (ms). Uses 'domcontentloaded' instead of
 * 'networkidle' as the wait condition for non-screenshot crawling —
 * networkidle can hang indefinitely on sites with persistent
 * WebSocket/polling connections.
 */
const PAGE_TIMEOUT_MS = 10000;
const WAIT_UNTIL = "domcontentloaded";

async function main() {
  const started = now();
  const request = JSON.parse(await readStdin());
  const observations = [];
  const findings = [];
  const warnings = [];
  const screenshotMode = request.screenshot || false;

  // Try Playwright first for full browser rendering
  let usedPlaywright = false;
  try {
    const { chromium } = await import("playwright");

    // Launch ONE browser instance per scan (not one per page).
    // Browser launch is expensive (300-800ms); contexts are cheap.
    const browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-gpu"],
    });

    try {
      // Reuse a single browser context across crawled pages
      const context = await browser.newContext({
        userAgent: "PhantomScan/2.0 authorized-security-assessment",
        ignoreHTTPSErrors: true,
      });

      const page = await context.newPage();

      // Block images/fonts/media during crawl-only passes
      // Screenshot mode still loads everything for visual fidelity
      if (!screenshotMode) {
        await page.route("**/*", (route) => {
          const url = route.request().url().toLowerCase();
          const isBlocked = BLOCKED_RESOURCE_TYPES.some((pattern) => {
            const ext = url.split("?")[0].split(".").pop();
            return pattern.includes(ext);
          });
          if (isBlocked) {
            route.abort();
          } else {
            route.continue();
          }
        });
      }

      // Use domcontentloaded with hard 10s timeout instead of
      // networkidle which can hang on sites with WebSocket/polling
      await page.goto(`https://${request.target}`, {
        timeout: PAGE_TIMEOUT_MS,
        waitUntil: WAIT_UNTIL,
      });

      const html = await page.content();
      const currentUrl = page.url() || `https://${request.target}`;
      const isLoginDetected = detectLoginSignals(html, currentUrl);

      observations.push({
        name: "browser_status",
        value: 200,
        source: "node-browser",
      });
      observations.push({
        name: "login_page_detected",
        value: isLoginDetected,
        source: "node-browser",
      });

      if (isLoginDetected) {
        findings.push({
          id: "BROWSER-LOGIN-INTERFACE-EXPOSED",
          title: "Authentication / Login Interface Detected via Headless Browser",
          severity: "info",
          confidence: "high",
          category: "recon",
          target: currentUrl,
          evidence: `A login or authentication interface with credential inputs or login endpoints was rendered and confirmed by the headless browser engine at ${currentUrl}.`,
          recommendation: "Ensure authentication endpoints enforce rate limiting (brute force protection), TLS/HTTPS only, and multi-factor authentication (MFA).",
          references: [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
          ]
        });
      }

      // Capture automated visual rendering screenshot
      try {
        const screenshotBuf = await page.screenshot({ type: "jpeg", quality: 80 });
        const screenshotBase64 = screenshotBuf.toString("base64");
        const dataUri = `data:image/jpeg;base64,${screenshotBase64}`;
        observations.push({
          name: "screenshot",
          value: {
            url: currentUrl,
            data_uri: dataUri,
            image_base64: screenshotBase64,
            title: `Visual Render: ${request.target}`,
            description: `Automated headless browser rendering of ${request.target}`,
            timestamp: now(),
            status: "200",
            related_finding_id: isLoginDetected ? "BROWSER-LOGIN-INTERFACE-EXPOSED" : ""
          },
          source: "node-browser",
        });
      } catch (screenshotErr) {
        // Screenshot capture failed or not required
      }

      await context.close();
      usedPlaywright = true;
    } finally {
      await browser.close();
    }
  } catch (playwrightError) {
    // Playwright not available — fall back to fetch
    warnings.push(
      `Playwright unavailable, using fetch fallback: ${playwrightError.message || playwrightError}`
    );
  }

  // Fallback: basic fetch (no JS rendering)
  if (!usedPlaywright) {
    try {
      const response = await fetch(`https://${request.target}`, {
        method: "GET",
        headers: {"User-Agent": "PhantomScan/2.0 authorized-security-assessment"},
        signal: AbortSignal.timeout((request.timeout_seconds || 5) * 1000)
      });
      const html = await response.text();
      const currentUrl = response.url || `https://${request.target}`;
      const isLoginDetected = detectLoginSignals(html, currentUrl);

      observations.push({name: "browser_status", value: response.status, source: "node-browser"});
      observations.push({name: "login_page_detected", value: isLoginDetected, source: "node-browser"});

      if (isLoginDetected) {
        findings.push({
          id: "BROWSER-LOGIN-INTERFACE-EXPOSED",
          title: "Authentication / Login Interface Detected",
          severity: "info",
          confidence: "medium",
          category: "recon",
          target: currentUrl,
          evidence: `Login or authentication pathways detected at ${currentUrl}.`,
          recommendation: "Ensure authentication endpoints enforce rate limiting (brute force protection) and multi-factor authentication (MFA).",
          references: [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
          ]
        });
      }
    } catch (error) {
      warnings.push(String(error.message || error));
    }
  }

  const output = {
    schema: "phantomscan.engine.v1",
    engine: "node-browser",
    status: "ok",
    target: request.target,
    started_at: started,
    finished_at: now(),
    findings,
    observations,
    warnings
  };
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exit(1);
  });
}
