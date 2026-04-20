#!/usr/bin/env bash
# audit-staging.sh
# ----------------
# Quick exposure audit for a URL before adding it to the public Upptime
# config. Flags the common "this shouldn't be public" patterns for WP/WC
# staging sites.
#
# Usage:
#   bash audit-staging.sh https://staging.example.com
#   bash audit-staging.sh < urls.txt    # one URL per line
#
# Does NOT attempt credential guessing or anything intrusive — just
# head/get checks on well-known paths that should either 401/403 or 404
# if the site is safely configured.

set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

check_url() {
  local base="$1"
  # Strip trailing slash
  base="${base%/}"

  echo ""
  echo "=== Auditing: $base ==="

  local issues=0

  # 1. Basic reachability
  local root_code
  root_code=$(curl -o /dev/null -s -w "%{http_code}" --max-time 15 -L "$base/" || echo "000")
  if [ "$root_code" = "000" ]; then
    echo -e "${RED}FAIL${NC}: cannot reach $base (timeout or DNS error)"
    return 1
  fi
  echo "  root status: $root_code"

  # 2. Admin panels — should NOT be 200 without auth
  for path in "/wp-admin/" "/wp-login.php" "/admin/" "/administrator/" "/phpmyadmin/"; do
    local code
    code=$(curl -o /dev/null -s -w "%{http_code}" --max-time 10 -L "$base$path" || echo "000")
    if [ "$code" = "200" ]; then
      echo -e "  ${RED}RISK${NC}: $path returns 200 — admin panel exposed without auth"
      issues=$((issues + 1))
    elif [ "$code" = "401" ] || [ "$code" = "403" ]; then
      echo -e "  ${GREEN}OK${NC}: $path returns $code (protected)"
    elif [ "$code" = "404" ]; then
      echo "  ok: $path not present (404)"
    else
      echo "  info: $path returns $code"
    fi
  done

  # 3. Sensitive files — should NOT be 200
  for path in "/.env" "/.git/config" "/wp-config.php" "/wp-config.php.bak" "/composer.json" "/package.json" "/.htaccess"; do
    local code
    code=$(curl -o /dev/null -s -w "%{http_code}" --max-time 10 "$base$path" || echo "000")
    if [ "$code" = "200" ]; then
      echo -e "  ${RED}RISK${NC}: $path returns 200 — sensitive file exposed"
      issues=$((issues + 1))
    elif [ "$code" = "403" ] || [ "$code" = "404" ]; then
      :  # quiet — this is the expected state
    else
      echo "  info: $path returns $code"
    fi
  done

  # 4. Directory listing — GET /wp-content/uploads/ and check for index-of behaviour
  local listing
  listing=$(curl -s --max-time 10 "$base/wp-content/uploads/" | head -c 2000 || true)
  if echo "$listing" | grep -qiE "(<title>Index of|Directory listing for)"; then
    echo -e "  ${RED}RISK${NC}: /wp-content/uploads/ shows directory listing"
    issues=$((issues + 1))
  fi

  # 5. Is there SOME auth in front? Check if homepage requires basic auth
  local auth_header
  auth_header=$(curl -s -I --max-time 10 "$base/" | grep -i "^www-authenticate:" || true)
  if [ -n "$auth_header" ]; then
    echo -e "  ${GREEN}GOOD${NC}: site requires HTTP auth ($auth_header)"
  else
    if [ "$issues" -gt 0 ]; then
      echo -e "  ${YELLOW}NOTE${NC}: no HTTP-level auth AND risks above — consider adding basic auth before listing publicly"
    fi
  fi

  # 6. X-Robots-Tag for staging — should be noindex
  local robots
  robots=$(curl -s -I --max-time 10 "$base/" | grep -i "^x-robots-tag:" || true)
  if [ -z "$robots" ] && [[ "$base" == *staging* || "$base" == *dev* || "$base" == *test* ]]; then
    echo -e "  ${YELLOW}NOTE${NC}: no X-Robots-Tag header — staging site may get indexed by search engines"
  fi

  # Summary
  if [ "$issues" -eq 0 ]; then
    echo -e "${GREEN}CLEAN${NC}: $base — safe to add to public Upptime"
  else
    echo -e "${RED}$issues issue(s)${NC} found for $base — fix before public listing"
  fi

  return "$issues"
}

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
if [ "$#" -gt 0 ]; then
  # URL(s) as arguments
  total_issues=0
  for url in "$@"; do
    check_url "$url"
    total_issues=$((total_issues + $?))
  done
  echo ""
  echo "========================================"
  if [ "$total_issues" -eq 0 ]; then
    echo -e "${GREEN}All URLs clean.${NC}"
  else
    echo -e "${RED}Total issues: $total_issues${NC}"
  fi
  exit "$([ "$total_issues" -eq 0 ] && echo 0 || echo 1)"
elif [ ! -t 0 ]; then
  # URLs via stdin
  total_issues=0
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    [[ "$url" =~ ^# ]] && continue
    check_url "$url"
    total_issues=$((total_issues + $?))
  done
  echo ""
  if [ "$total_issues" -eq 0 ]; then
    echo -e "${GREEN}All URLs clean.${NC}"
  else
    echo -e "${RED}Total issues: $total_issues${NC}"
  fi
  exit "$([ "$total_issues" -eq 0 ] && echo 0 || echo 1)"
else
  echo "Usage: $0 <url> [<url> ...]"
  echo "   or: $0 < urls.txt"
  exit 2
fi
