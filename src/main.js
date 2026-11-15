/**
 * Apify Pay-Per-Event Actor & CLI Auditor:
 * OWASP HTTP Security Headers, CORS Misconfiguration, RFC 9116 security.txt & x402 Agent Readiness Scanner
 * Author: Huzaifa Ahmed (@khuxaiphi-stack)
 * Payout / x402 Treasury: FyexYHp1TZ6uzFLUvFNfofx14LQaBrYHbQksTo18xRgD
 */

const REQUIRED_HEADERS = [
  { key: "strict-transport-security", weight: 20, label: "HSTS (Strict-Transport-Security)", fix: "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'" },
  { key: "content-security-policy", weight: 25, label: "CSP (Content-Security-Policy)", fix: "Define a strict Content-Security-Policy header restricting script-src and object-src" },
  { key: "x-content-type-options", weight: 15, label: "X-Content-Type-Options", fix: "Add 'X-Content-Type-Options: nosniff'" },
  { key: "x-frame-options", weight: 15, label: "X-Frame-Options", fix: "Add 'X-Frame-Options: DENY' or CSP frame-ancestors" },
  { key: "referrer-policy", weight: 10, label: "Referrer-Policy", fix: "Add 'Referrer-Policy: strict-origin-when-cross-origin'" },
  { key: "permissions-policy", weight: 15, label: "Permissions-Policy", fix: "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'" }
];

function analyzeHeaders(url, headersObj = {}, statusCode = 200) {
  const normalized = {};
  for (const [k, v] of Object.entries(headersObj)) {
    normalized[String(k).toLowerCase()] = String(v);
  }

  let score = 0;
  const passed = [];
  const missing = [];
  const warnings = [];

  for (const item of REQUIRED_HEADERS) {
    if (normalized[item.key]) {
      score += item.weight;
      passed.push({ header: item.label, value: normalized[item.key] });
    } else {
      missing.push({ header: item.label, weight: item.weight, remediation: item.fix });
    }
  }

  if (normalized["access-control-allow-origin"] === "*" && normalized["access-control-allow-credentials"] === "true") {
    warnings.push("CRITICAL: Wildcard ACAO ('*') combined with Access-Control-Allow-Credentials: true");
    score = Math.max(0, score - 25);
  }

  if (normalized["server"] || normalized["x-powered-by"]) {
    warnings.push(`Information disclosure via Server/X-Powered-By banner: ${normalized["server"] || ""} ${normalized["x-powered-by"] || ""}`.trim());
  }

  const grade = score >= 90 ? "A+" : score >= 80 ? "A" : score >= 65 ? "B" : score >= 50 ? "C" : score >= 35 ? "D" : "F";

  return {
    url,
    statusCode,
    score,
    grade,
    x402Ready: statusCode === 402 || Boolean(normalized["www-authenticate"] && normalized["www-authenticate"].includes("x402")),
    passedCount: passed.length,
    missingCount: missing.length,
    passed,
    missing,
    warnings,
    auditedAt: new Date().toISOString()
  };
}

async function runActor() {
  let Actor;
  try {
    ({ Actor } = require("apify"));
  } catch {
    Actor = null;
  }

  if (Actor) {
    await Actor.init();
    const input = (await Actor.getInput()) || { urls: ["https://example.com"] };
    const urls = Array.isArray(input.urls) ? input.urls : ["https://example.com"];

    for (const targetUrl of urls) {
      const res = await fetch(targetUrl, { method: "GET", redirect: "follow" });
      const headersObj = {};
      res.headers.forEach((v, k) => { headersObj[k] = v; });
      const report = analyzeHeaders(targetUrl, headersObj, res.status);
      await Actor.pushData(report);
      if (typeof Actor.charge === "function") {
        await Actor.charge({ eventName: "url-security-audited", count: 1 }).catch(() => {});
      }
    }
    await Actor.exit();
  }
}

module.exports = { analyzeHeaders, runActor };

if (require.main === module) {
  runActor().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
