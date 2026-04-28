<div align="center">

# Supply Chain Secret Hunting

[![Severity](https://img.shields.io/badge/severity-high-red?style=flat-square)](https://github.com/Satz-N-Sentry)
[![CWE](https://img.shields.io/badge/CWE-CWE--798-dd6b20?style=flat-square)](https://cwe.mitre.org/data/definitions/798.html)
[![Class](https://img.shields.io/badge/class-hard--coded%20credentials-3b82f6?style=flat-square)](#)
[![Status](https://img.shields.io/badge/status-validated-16a34a?style=flat-square)](#)
[![Method](https://img.shields.io/badge/method-passive%20recon-7c3aed?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-HackerOne%20VDP-0f766e?style=flat-square)](#)
[![Framework](https://img.shields.io/badge/framework-Nuxt.js%20SSR-be185d?style=flat-square)](#)
[![Date](https://img.shields.io/badge/date-April%202026-ca8a04?style=flat-square)](#)

*Case study: extracting hard-coded API tokens from SSR framework client-side state blobs — no active scanning, no brute force, zero noise footprint.*

**[Satz-N-Sentry](https://github.com/Satz-N-Sentry)** · Supply Chain Secret Hunting

</div>

---

## 📌 Executive Summary

While performing passive reconnaissance on a fintech VDP target, I identified a high-severity information disclosure: a third-party CMS API token baked into the client-side JavaScript of a Nuxt.js SSR application. The exposed token granted read/write access to production draft content in the CMS.

---

## 🛠️ Methodology

| Phase | Approach | Tools |
|---|---|---|
| Recon | Passive path discovery | `curl`, `sitemap.xml`, `robots.txt` |
| Analysis | Manual source code review | Regex pattern matching, browser DevTools |
| Validation | Single metadata API call | Burp Suite Repeater, CMS API |

---

## 🔍 Discovery Walkthrough

### Phase 1 — Passive path mapping

Starting points — no fuzzing required:

```bash
curl -sk https://[TARGET]/robots.txt
curl -sk https://[TARGET]/sitemap.xml
```

The sitemap returned a complete URL inventory. The `/legal/security` path was selected for deeper analysis. CSP headers on that page confirmed an active third-party CMS connection via an allowed source directive.

### Phase 2 — Token extraction from SSR state

Nuxt.js serializes the full app config into a `window.__NUXT__` block delivered to every browser. Extracted with:

```bash
curl -sk https://[TARGET]/legal/security | grep -o 'token:"[^"]*"'
```

The config block contained the full CMS client configuration — project ID, dataset name, environment, and a live API token — all in plaintext in the HTML source:

```javascript
sanity:{
  projectId:"[REDACTED]",
  dataset:"production",
  perspective:"raw",
  token:"sk[REDACTED]"
}
```

### Phase 3 — Minimum viable validation

Single read-only API call to the CMS project metadata endpoint:

```bash
curl -sk "https://api.[CMS_PROVIDER]/v2021-06-07/projects/[REDACTED_ID]" \
  -H "Authorization: Bearer sk[REDACTED]"
```

Response confirmed token validity, project ownership, and role:

```json
{
  "isCurrentUser": true,
  "isBlocked": false,
  "members": [{
    "isRobot": true,
    "roles": [{
      "name": "contributor",
      "description": "Read and write access to draft content within all datasets"
    }]
  }]
}
```

> Testing stopped here. No content was queried, read, or modified.

---

## ⚠️ Impact Assessment

| Vector | Impact |
|---|---|
| Data integrity | Write access to CMS enables content tampering → Stored XSS, phishing via official site pages |
| Information leakage | Full visibility into project members, deployment history, and dataset structure |
| Supply chain risk | Third-party CMS integration surface — one misconfigured key exposes the full content pipeline |
| Scope | Production dataset — not staging or test |

---

## 🗺️ Path Discovery Techniques (Passive Only)

| Technique | Command | Notes |
|---|---|---|
| robots.txt | `curl -sk https://[TARGET]/robots.txt` | First stop — disallowed paths often signal sensitive routes |
| sitemap.xml | `curl -sk https://[TARGET]/sitemap.xml` | Complete URL inventory, no guessing needed |
| Wayback Machine | `waybackurls [TARGET] | sort -u` | Finds removed or forgotten pages |
| Google dorking | `site:[TARGET]` in browser | Indexed pages — zero traffic to target |
| JS file extraction | `curl -sk https://[TARGET] | grep -o 'src="[^"]*\.js"'` | Finds bundle paths, then grep bundles for secrets |
| Cert transparency | `curl -sk "https://crt.sh/?q=[TARGET]&output=json"` | Subdomain enumeration → additional attack surface |

---

## ✅ Key Takeaways

- **Passive beats active:** The sitemap provided every path needed — no directory fuzzing, no noise footprint.
- **SSR serialization risk:** SSR frameworks (Nuxt.js, Next.js) serialize the entire app config into client HTML at render time. Any key placed in the public runtime config is effectively public.
- **Minimum viable PoC:** A single metadata call is sufficient to prove token validity and permission scope without touching any content.
- **Third-party surface:** The vulnerability isn't in the app itself — it's in how the integration was configured. Supply chain token hygiene matters.

---

## 📂 Repo Structure

```
Supply-Chain-Secret-Hunting/
├── writeups/
│   └── ssrf-ssr-token-exposure.md   # this case study
├── methodology/
│   └── passive-recon-playbook.md    # recon methodology notes
├── tools/
│   └── extract-nuxt-config.sh       # helper script
├── LICENSE
├── .gitignore
└── README.md
```

---

<div align="center">

*All targets engaged under authorized VDP programs. Sensitive identifiers redacted.*
*No production data was accessed or exfiltrated. Reported responsibly via HackerOne.*

[![GitHub](https://img.shields.io/badge/GitHub-Satz--N--Sentry-181717?style=flat-square&logo=github)](https://github.com/Satz-N-Sentry)

</div>
