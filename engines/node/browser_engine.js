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

async function main() {
  const started = now();
  const request = JSON.parse(await readStdin());
  const observations = [];
  const warnings = [];
  try {
    const response = await fetch(`https://${request.target}`, {
      method: "GET",
      headers: {"User-Agent": "PhantomScan/2.0 authorized-security-assessment"},
      signal: AbortSignal.timeout((request.timeout_seconds || 5) * 1000)
    });
    const html = await response.text();
    observations.push({name: "browser_status", value: response.status, source: "node-browser"});
    observations.push({name: "login_page_detected", value: detectLoginSignals(html, response.url), source: "node-browser"});
  } catch (error) {
    warnings.push(String(error.message || error));
  }
  const output = {
    schema: "phantomscan.engine.v1",
    engine: "node-browser",
    status: "ok",
    target: request.target,
    started_at: started,
    finished_at: now(),
    findings: [],
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
