# SSR Framework Token Exposure via Client-Side State Serialization

[![Severity](https://img.shields.io/badge/severity-high-red?style=flat-square)](#)
[![CWE](https://img.shields.io/badge/CWE-CWE--798-dd6b20?style=flat-square)](https://cwe.mitre.org/data/definitions/798.html)
[![Class](https://img.shields.io/badge/class-hard--coded%20credentials-3b82f6?style=flat-square)](#)
[![Status](https://img.shields.io/badge/status-validated-16a34a?style=flat-square)](#)
[![Method](https://img.shields.io/badge/method-passive%20recon%20only-7c3aed?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-HackerOne%20VDP-0f766e?style=flat-square)](#)
[![Date](https://img.shields.io/badge/date-April%202026-ca8a04?style=flat-square)](#)

> **Vulnerability class:** CWE-798 — Use of Hard-coded Credentials
> **Target category:** Fintech / Financial Services
> **Outcome:** Validated High. Reported via responsible disclosure. No content accessed or modified.

---

## 📌 Summary

A production CMS API token was found serialized into the client-side HTML of a Nuxt.js SSR application. The token was delivered to every browser visiting a public page — fully unauthenticated, no login required. The exposed token carried `contributor` role access: read and write permissions across all datasets in the production CMS.

Discovered entirely through passive analysis of public page source. No active scanning, directory fuzzing, or authenticated access was used at any point.

---

## 🧱 Root Cause

Nuxt.js uses a `runtimeConfig` object split into two sections:

```javascript
// nuxt.config.js
export default defineNuxtConfig({
  runtimeConfig: {
    // server-only — never sent to browser
    secretKey: process.env.SECRET_KEY,

    // public — serialized into window.__NUXT__ and sent to EVERY browser
    public: {
      sanity: {
        token: process.env.SANITY_TOKEN   // ← mistake: this should be server-only
      }
    }
  }
})
```

When a key is placed inside `runtimeConfig.public`, Nuxt bakes it into the `window.__NUXT__` state blob at render time and delivers it in the raw HTML. This is by design — the mechanism exists for legitimate public config like API base URLs. The vulnerability arises when secrets are placed there instead of in the server-only section.

---

## 🔍 Discovery Walkthrough

### Step 1 — Identify the tech stack

```bash
curl -sk https://[TARGET]/legal/security | head -100
```

First 100 lines of the HTML revealed:
- `_nuxt/` asset paths → Nuxt.js SSR application
- CSP `connect-src` header included `*.sanity.io` → Sanity CMS actively in use
- Image CDN URLs in the format `cdn.sanity.io/images/[PROJECT_ID]/production/...` → project ID visible in asset paths

### Step 2 — Locate sensitive paths

```bash
curl -sk https://[TARGET]/robots.txt
curl -sk https://[TARGET]/sitemap.xml
```

`sitemap.xml` returned a full index of public URLs. `/legal/security` was selected for deeper inspection — security pages often contain modern framework configurations and are infrequently audited.

### Step 3 — Extract the token

```bash
curl -sk https://[TARGET]/legal/security | grep -o 'token:"[^"]*"'
```

The `window.__NUXT__` block at the bottom of the HTML source contained the complete Sanity client configuration:

```javascript
window.__NUXT__ = {
  config: {
    public: {
      sanity: {
        projectId: "[REDACTED]",
        dataset:   "production",
        perspective: "raw",
        token: "sk[REDACTED]"
      }
    }
  }
}
```

All values — project ID, dataset name, and the bearer token — were present in the same block.

### Step 4 — Validate (minimum viable proof of concept)

```bash
curl -sk "https://api.[CMS_PROVIDER]/v2021-06-07/projects/[REDACTED_ID]" \
  -H "Authorization: Bearer sk[REDACTED]"
```

A single read-only call to the project metadata endpoint confirmed:

```json
{
  "isCurrentUser": true,
  "isBlocked": false,
  "dataset": "production",
  "members": [{
    "isRobot": true,
    "roles": [{
      "name": "contributor",
      "description": "Read and write access to draft content within all datasets"
    }]
  }]
}
```

**Testing stopped immediately.** The metadata response was sufficient to establish:
- Token is valid and active
- Token belongs to the target organization
- Token has write access to the production dataset

---

## ⚠️ Impact

| Vector | Impact |
|---|---|
| Content tampering | Write access allows modification of any draft CMS content — could be used to inject malicious scripts (Stored XSS) or swap legitimate content with phishing pages |
| Information disclosure | Full visibility into CMS project members, roles, deployment history, and dataset structure |
| Supply chain exposure | Any third-party integration (CDN, preview environments, webhooks) using the same token is also affected |
| Scope | Production dataset — not staging or test |

**Severity: High** (CVSS 4.0: 8.8)

---

## 🛡️ Remediation

**Immediate:**
1. Revoke the exposed token from the CMS dashboard
2. Issue a new scoped token with the minimum permissions required (read-only if write is not needed client-side)
3. Audit all CMS tokens for unexpected access in the activity log

**Structural fix:**

Move the token from `runtimeConfig.public` to the server-only section:

```javascript
// nuxt.config.js — corrected
export default defineNuxtConfig({
  runtimeConfig: {
    sanityToken: process.env.SANITY_TOKEN,  // server-only, never serialized to client
    public: {
      sanityProjectId: process.env.SANITY_PROJECT_ID  // safe to expose
    }
  }
})
```

Then access it server-side only via `useRuntimeConfig()` inside server routes or `server/` directory handlers — never in components that render client-side.

---

## 📋 Commands Used (Full Reference)

```bash
# Tech stack fingerprinting
curl -sk https://[TARGET]/legal/security | head -100

# Path discovery (passive)
curl -sk https://[TARGET]/robots.txt
curl -sk https://[TARGET]/sitemap.xml

# Token extraction
curl -sk https://[TARGET]/legal/security | grep -o 'token:"[^"]*"'

# Validation (single call, read-only metadata only)
curl -sk "https://api.[CMS_PROVIDER]/v2021-06-07/projects/[REDACTED_ID]" \
  -H "Authorization: Bearer sk[REDACTED]"
```

---

## ✅ Lessons Learned

- **The `window.__NUXT__` block is fully public.** Treat anything inside `runtimeConfig.public` as if it were printed on the homepage. Server secrets belong in `runtimeConfig` (root level), not `.public`.
- **Sitemap-first recon is underrated.** The sitemap handed over the full path inventory in one request — faster and quieter than any active fuzzing approach.
- **CSP headers are a map of third-party integrations.** The `connect-src` directive named the CMS before any source inspection began.
- **One API call is enough.** Minimum viable validation protects both the researcher and the target. Anything beyond metadata confirmation is unnecessary scope creep.

---

*Reported responsibly. All identifiers redacted. No production data was accessed or exfiltrated.*
*Part of the [Supply-Chain-Secret-Hunting](https://github.com/Satz-N-Sentry/Supply-Chain-Secret-Hunting) research series by [Satz-N-Sentry](https://github.com/Satz-N-Sentry).*
