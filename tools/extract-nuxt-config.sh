#!/usr/bin/env bash
# ============================================================
#  extract-nuxt-config.sh
#  Satz-N-Sentry / Supply-Chain-Secret-Hunting
#
#  Fetches a target URL and extracts the window.__NUXT__ and
#  window.__NEXT_DATA__ state blobs, then greps for common
#  secret patterns (tokens, API keys, project IDs).
#
#  Usage:
#    chmod +x extract-nuxt-config.sh
#    ./extract-nuxt-config.sh https://target.com/some/page
#
#  Output:
#    Prints findings to stdout. Saves raw source to /tmp/nuxt-src.html
#
#  Requirements: curl, grep, sed, python3 (optional, for pretty-print)
# ============================================================

set -euo pipefail

# ── colours ──────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BOLD='\033[1m'; RST='\033[0m'

# ── arg check ────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo -e "${BOLD}Usage:${RST} $0 <URL>"
  echo -e "  Example: $0 https://example.com/legal/security"
  exit 1
fi

TARGET="$1"
TMP="/tmp/nuxt-src.html"

echo -e "\n${BOLD}${CYN}Supply-Chain-Secret-Hunting — Nuxt/Next Config Extractor${RST}"
echo -e "${CYN}by Satz-N-Sentry · github.com/Satz-N-Sentry${RST}"
echo -e "────────────────────────────────────────────────────────"
echo -e "Target : ${BOLD}${TARGET}${RST}"
echo -e "Saved  : ${TMP}\n"

# ── fetch ────────────────────────────────────────────────────
echo -e "${YEL}[*] Fetching page source...${RST}"
HTTP_CODE=$(curl -sk -o "$TMP" -w "%{http_code}" "$TARGET")

if [[ "$HTTP_CODE" != "200" ]]; then
  echo -e "${RED}[!] HTTP ${HTTP_CODE} — page may not be accessible${RST}"
  exit 1
fi

echo -e "${GRN}[+] HTTP 200 OK — source saved ($(wc -c < "$TMP") bytes)${RST}\n"

# ── framework detection ───────────────────────────────────────
echo -e "${YEL}[*] Detecting framework...${RST}"

if grep -q '_nuxt/' "$TMP" 2>/dev/null; then
  echo -e "${GRN}[+] Nuxt.js detected (_nuxt/ asset paths)${RST}"
fi
if grep -q '_next/' "$TMP" 2>/dev/null; then
  echo -e "${GRN}[+] Next.js detected (_next/ asset paths)${RST}"
fi
if grep -q '__NUXT__' "$TMP" 2>/dev/null; then
  echo -e "${GRN}[+] window.__NUXT__ state blob present${RST}"
fi
if grep -q '__NEXT_DATA__' "$TMP" 2>/dev/null; then
  echo -e "${GRN}[+] window.__NEXT_DATA__ state blob present${RST}"
fi

echo ""

# ── token extraction ─────────────────────────────────────────
echo -e "${YEL}[*] Scanning for tokens and API keys...${RST}"
echo -e "────────────────────────────────────────────────────────"

FOUND=0

# Generic token:"..." pattern (covers Sanity, Contentful, and similar)
if grep -oE 'token:"[^"]{10,}"' "$TMP" 2>/dev/null | while read -r match; do
  echo -e "${RED}[FOUND] ${match}${RST}"
  FOUND=1
done; then : ; fi

# apiKey / api_key patterns
if grep -oE '"(apiKey|api_key|accessToken|access_token)"\s*:\s*"[^"]{8,}"' "$TMP" 2>/dev/null | while read -r match; do
  echo -e "${RED}[FOUND] ${match}${RST}"
  FOUND=1
done; then : ; fi

# Bearer token strings
if grep -oE 'Bearer [A-Za-z0-9_.+-]{20,}' "$TMP" 2>/dev/null | while read -r match; do
  echo -e "${RED}[FOUND] ${match}${RST}"
  FOUND=1
done; then : ; fi

# Sanity-specific: project ID in CDN image URLs
if grep -oE 'cdn\.sanity\.io/images/[a-z0-9]+' "$TMP" 2>/dev/null | head -1 | while read -r match; do
  PROJECT_ID=$(echo "$match" | sed 's|cdn.sanity.io/images/||')
  echo -e "${YEL}[INFO] Sanity project ID in image URLs: ${PROJECT_ID}${RST}"
done; then : ; fi

# NEXT_PUBLIC / NUXT_PUBLIC env var leaks
if grep -oE '(NEXT_PUBLIC|NUXT_PUBLIC|VITE_)[A-Z_]+\s*[:=]\s*"[^"]{4,}"' "$TMP" 2>/dev/null | while read -r match; do
  echo -e "${RED}[FOUND] ${match}${RST}"
  FOUND=1
done; then : ; fi

echo -e "────────────────────────────────────────────────────────"

# ── __NUXT__ config block extraction ─────────────────────────
echo -e "\n${YEL}[*] Extracting window.__NUXT__ config block...${RST}"

NUXT_BLOCK=$(grep -o 'window\.__NUXT__[^;]*' "$TMP" 2>/dev/null | head -c 3000 || true)

if [[ -n "$NUXT_BLOCK" ]]; then
  echo -e "${GRN}[+] window.__NUXT__ found (first 3000 chars):${RST}"
  echo ""
  echo "$NUXT_BLOCK"
  echo ""
else
  echo -e "${CYN}[-] No window.__NUXT__ block found on this page${RST}"
fi

# ── __NEXT_DATA__ extraction ──────────────────────────────────
echo -e "${YEL}[*] Extracting __NEXT_DATA__ block...${RST}"

NEXT_BLOCK=$(grep -o 'id="__NEXT_DATA__"[^<]*' "$TMP" 2>/dev/null | head -c 3000 || true)
if [[ -z "$NEXT_BLOCK" ]]; then
  NEXT_BLOCK=$(grep -oP '(?<=<script id="__NEXT_DATA__" type="application/json">)[^<]+' "$TMP" 2>/dev/null | head -c 3000 || true)
fi

if [[ -n "$NEXT_BLOCK" ]]; then
  echo -e "${GRN}[+] __NEXT_DATA__ found (first 3000 chars):${RST}"
  echo ""
  echo "$NEXT_BLOCK"
  echo ""
else
  echo -e "${CYN}[-] No __NEXT_DATA__ block found on this page${RST}"
fi

# ── script sources ────────────────────────────────────────────
echo -e "${YEL}[*] Listing JavaScript bundle paths...${RST}"
JS_FILES=$(grep -o 'src="[^"]*\.js"' "$TMP" 2>/dev/null | sed 's/src="//;s/"//' | head -20 || true)

if [[ -n "$JS_FILES" ]]; then
  echo -e "${CYN}[i] JS bundles (check these for additional secrets):${RST}"
  echo "$JS_FILES"
else
  echo -e "${CYN}[-] No JS bundle paths found${RST}"
fi

# ── summary ───────────────────────────────────────────────────
echo -e "\n────────────────────────────────────────────────────────"
echo -e "${BOLD}Summary${RST}"
echo -e "  Target    : $TARGET"
echo -e "  HTTP code : $HTTP_CODE"
echo -e "  Raw source: $TMP"
echo -e ""
echo -e "${YEL}Next steps if a token was found:${RST}"
echo -e "  1. Identify the platform (Sanity, Contentful, Prismic, etc.)"
echo -e "  2. Call the platform's project metadata endpoint with the token"
echo -e "  3. Confirm token ownership and role in a SINGLE read-only call"
echo -e "  4. Stop immediately — document and report"
echo -e ""
echo -e "${CYN}Remember: minimum viable validation only. No content access.${RST}"
echo -e "────────────────────────────────────────────────────────\n"
