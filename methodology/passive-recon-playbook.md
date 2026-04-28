# Passive Recon Playbook — Supply Chain Secret Hunting

[![Method](https://img.shields.io/badge/method-passive%20only-7c3aed?style=flat-square)](#)
[![Noise](https://img.shields.io/badge/noise%20footprint-zero-16a34a?style=flat-square)](#)
[![Tools](https://img.shields.io/badge/tools-curl%20%7C%20grep%20%7C%20jq-3b82f6?style=flat-square)](#)

> A structured, passive-only recon methodology for identifying exposed secrets in third-party integrations — no active scanning, no brute force, no authenticated access.

---

## Philosophy

The goal is maximum information with minimum footprint. Most high-impact secrets are already sitting in public pages, sitemaps, and JavaScript bundles — waiting to be read, not brute-forced.

**Order of operations:**
1. Understand the tech stack before looking for bugs
2. Let the target tell you its own paths (sitemap, robots.txt)
3. Read what the browser gets — source code, JS bundles, state blobs
4. Validate with a single, scoped API call
5. Stop the moment impact is confirmed

---

## Phase 1 — Tech Stack Fingerprinting

**Goal:** Identify frameworks, CMS platforms, and third-party integrations before touching anything else.

```bash
# Fetch the first 100 lines of a target page — framework clues are in asset paths and meta tags
curl -sk https://[TARGET]/ | head -100

# Pull just the HTTP response headers — reveals server, CDN, CSP, and Set-Cookie hints
curl -sk -I https://[TARGET]/

# Extract all script src paths — reveals JS bundler and framework patterns
curl -sk https://[TARGET]/ | grep -o 'src="[^"]*\.js"'

# Extract all link hrefs — CSS frameworks, CDN usage
curl -sk https://[TARGET]/ | grep -o 'href="[^"]*"'
```

**What to look for:**

| Signal | Indicator |
|---|---|
| `/_nuxt/` asset paths | Nuxt.js (Vue SSR) |
| `/_next/` asset paths | Next.js (React SSR) |
| `window.__NUXT__` in source | Nuxt.js runtime config exposed |
| `window.__NEXT_DATA__` in source | Next.js runtime config exposed |
| `cdn.sanity.io/images/[ID]/` in image URLs | Sanity CMS + project ID |
| `*.contentful.com` in CSP | Contentful CMS |
| `*.prismic.io` in CSP | Prismic CMS |
| `*.storyblok.com` in CSP | Storyblok CMS |

**CSP header analysis — read the `connect-src` directive:**

```bash
curl -sk -I https://[TARGET]/ | grep -i content-security-policy
```

The `connect-src` directive lists every third-party service the app is allowed to talk to. This is a map of the entire integration surface — CMS, analytics, auth providers, payment processors — before you've read a single line of source code.

---

## Phase 2 — Path Discovery (Passive)

**Goal:** Build a complete URL inventory without making a single guess.

### robots.txt

```bash
curl -sk https://[TARGET]/robots.txt
```

`Disallow:` entries are especially interesting — they name paths the site is actively trying to hide from crawlers. These often include admin panels, staging routes, and internal tooling.

### sitemap.xml

```bash
curl -sk https://[TARGET]/sitemap.xml

# If the sitemap index links to child sitemaps, fetch those too
curl -sk https://[TARGET]/sitemap_index.xml
curl -sk https://[TARGET]/post-sitemap.xml
curl -sk https://[TARGET]/page-sitemap.xml
```

A well-maintained sitemap gives you the full URL inventory in one request. Look for:
- Paths with `draft`, `preview`, `old`, `legacy`, `staging` in the slug
- Paths that return 404 — they were once live and may still exist in archives
- Paths under `/studio/` — common for Sanity CMS admin surfaces

### HTTP status sweep

Once you have a path list from the sitemap, check their status codes:

```bash
curl -sk -o /dev/null -w "%{http_code}  %{url_effective}\n" \
  https://[TARGET]/path-one \
  https://[TARGET]/path-two \
  https://[TARGET]/path-three
```

| Status | Meaning |
|---|---|
| 200 | Live — inspect source |
| 301/302 | Redirect — follow and inspect destination |
| 403 | Exists but gated — note for later |
| 404 | Dead now — check Wayback Machine |
| 500 | Debug error — often leaks stack traces or config |

---

## Phase 3 — Source Code Analysis

**Goal:** Extract secrets, tokens, and internal config from public page source.

### SSR state blob extraction

Nuxt.js and Next.js both serialize application configuration into the HTML at render time.

```bash
# Nuxt.js — extract the full __NUXT__ config block
curl -sk https://[TARGET]/[PATH] | grep -o 'window\.__NUXT__[^<]*'

# Simpler token grep — works across both frameworks
curl -sk https://[TARGET]/[PATH] | grep -o 'token:"[^"]*"'

# API key pattern
curl -sk https://[TARGET]/[PATH] | grep -oE '"(api_?key|apiKey|access_?token|secret|token)"\s*:\s*"[^"]{10,}"'

# Extract the entire public config block (Nuxt)
curl -sk https://[TARGET]/[PATH] | python3 -c "
import sys, re
src = sys.stdin.read()
match = re.search(r'window\.__NUXT__\s*=\s*(\{.*?\})\s*;', src, re.DOTALL)
if match:
    print(match.group(0)[:2000])
"
```

### JavaScript bundle analysis

```bash
# List all JS bundles loaded by a page
curl -sk https://[TARGET]/ | grep -o 'src="[^"]*\.js"' | sed 's/src="//;s/"//'

# Fetch a specific bundle and search for secrets
curl -sk https://[TARGET]/_nuxt/[BUNDLE].js | grep -oE '"[A-Za-z_-]*(token|key|secret|api)[A-Za-z_-]*"\s*:\s*"[^"]{8,}"'
```

### Environment variable leaks

```bash
# Look for .env-style patterns in source
curl -sk https://[TARGET]/[PATH] | grep -oE '[A-Z_]{3,}=["'"'"'][^"'"'"']{6,}["'"'"']'

# Common variable names
curl -sk https://[TARGET]/[PATH] | grep -iE '(NEXT_PUBLIC|NUXT_PUBLIC|VITE_)[A-Z_]*\s*[:=]\s*["\x27][^"'\'']{6,}'
```

---

## Phase 4 — Archive & External Discovery

**Goal:** Find paths and secrets that existed in the past or appear in external indexes.

### Wayback Machine

```bash
# All URLs ever archived for a domain
waybackurls [TARGET] | sort -u | tee wayback-urls.txt

# Filter for interesting path patterns
cat wayback-urls.txt | grep -iE '(draft|preview|admin|studio|config|env|backup|old|legacy)'

# Fetch an archived page to check if it contained secrets
curl -sk "https://web.archive.org/web/2024*/https://[TARGET]/[PATH]"
```

### Certificate transparency

```bash
# Enumerate subdomains — each subdomain is a potential additional attack surface
curl -sk "https://crt.sh/?q=%25.[TARGET]&output=json" | jq -r '.[].name_value' | sort -u

# Filter out wildcards
curl -sk "https://crt.sh/?q=%25.[TARGET]&output=json" | jq -r '.[].name_value' | grep -v '^\*' | sort -u
```

### Google dorking

Run in a browser — zero requests to the target:

```
site:[TARGET]                          # all indexed pages
site:[TARGET] filetype:js              # indexed JS files
site:[TARGET] inurl:config             # config-named paths
site:[TARGET] inurl:api                # API paths
site:[TARGET] inurl:admin OR inurl:studio
```

---

## Phase 5 — Validation

**Goal:** Confirm impact with the absolute minimum number of API calls.

### Principles

- One call is enough. If a metadata endpoint confirms token validity and role, stop there.
- Never read, modify, or delete any content.
- Never enumerate members, datasets, or internal assets beyond what the metadata endpoint returns in a single response.
- Document the exact request and response used for validation.

### Validation call template

```bash
# Generic — replace with the third-party platform's project/account metadata endpoint
curl -sk "https://api.[PLATFORM]/[VERSION]/[RESOURCE]/[REDACTED_ID]" \
  -H "Authorization: Bearer [REDACTED_TOKEN]" \
  -H "Accept: application/json"
```

**Minimum fields needed in the response to establish impact:**
- Confirmation the token belongs to the target (display name, domain, or project name)
- Confirmation the token is active (`isBlocked: false`, `isDisabled: false`, or HTTP 200)
- The token's permission role (read-only vs read/write vs admin)

Once all three are confirmed — stop. The PoC is complete.

---

## Quick Reference — One-Liners

```bash
# Full passive recon sweep on a target page
TARGET="https://[TARGET]/[PATH]"

echo "=== HTTP Headers ===" && curl -sk -I $TARGET
echo "=== robots.txt ===" && curl -sk https://[TARGET]/robots.txt
echo "=== sitemap ===" && curl -sk https://[TARGET]/sitemap.xml | grep '<loc>' | head -30
echo "=== Tokens in source ===" && curl -sk $TARGET | grep -oE 'token:"[^"]{20,}"'
echo "=== API keys in source ===" && curl -sk $TARGET | grep -oiE '"(api_?key|apiKey|access_?token)"\s*:\s*"[^"]{10,}"'
echo "=== Script sources ===" && curl -sk $TARGET | grep -o 'src="[^"]*\.js"'
echo "=== __NUXT__ config ===" && curl -sk $TARGET | grep -o 'window\.__NUXT__[^;]*' | head -c 1000
echo "=== __NEXT_DATA__ ===" && curl -sk $TARGET | grep -o 'id="__NEXT_DATA__"[^<]*' | head -c 1000
```

---

*Part of the [Supply-Chain-Secret-Hunting](https://github.com/Satz-N-Sentry/Supply-Chain-Secret-Hunting) research series by [Satz-N-Sentry](https://github.com/Satz-N-Sentry).*
*All techniques documented here are for use on authorized targets only.*
