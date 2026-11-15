const assert = require("assert");
const { analyzeHeaders } = require("../src/main");

const aPlus = analyzeHeaders("https://bank.example.com", {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=()"
}, 200);
assert.strictEqual(aPlus.score, 100);
assert.strictEqual(aPlus.grade, "A+");
assert.strictEqual(aPlus.missingCount, 0);

const x402Resp = analyzeHeaders("https://api.example.com/v1/query", {
  "www-authenticate": 'x402 network="solana-mainnet", asset="USDC"'
}, 402);
assert.strictEqual(x402Resp.x402Ready, true);

console.log("ALL APIFY SECURITY & x402 AUDITOR TESTS PASSED!");
