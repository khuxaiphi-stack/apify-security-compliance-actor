# Web Security Headers, CORS & x402 AI-Readiness Auditor (Apify Pay-Per-Event Actor) 🛡️⚡

A production-ready **Apify Actor** (configured for **Apify Store Pay-Per-Event 80% Revenue Share** via `Actor.charge({ eventName: "url-security-audited" })`) and standalone Node.js library that audits any list of domains/APIs for:

1. **OWASP HTTP Security Headers** (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`) with weighted `0–100` scoring and `A+ to F` grading.
2. **CORS & Banner Leak Detection** (detects dangerous `Access-Control-Allow-Origin: *` + `Credentials: true` combinations and `Server`/`X-Powered-By` version leaks).
3. **`x402` AI Agent Micropayment Readiness** (detects `HTTP 402 Payment Required` and `WWW-Authenticate: x402` headers).

---

## 🚀 1-Click Apify Store Deployment
1. Go to [Apify Console -> Actors -> Create new Actor -> Link Git Repository](https://console.apify.com/actors).
2. Paste `https://github.com/khuxaiphi-stack/apify-security-compliance-actor`.
3. Enable **Pay-Per-Event (`url-security-audited`)** in the Monetization tab to earn **80% revenue share** on every URL scanned by Apify users and MCP agents.

---
**Author:** Huzaifa Ahmed (`@khuxaiphi-stack`) | **Solana Treasury:** `FyexYHp1TZ6uzFLUvFNfofx14LQaBrYHbQksTo18xRgD`
