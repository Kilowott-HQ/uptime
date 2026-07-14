# ---------------------------------------------------------------------------
# alert-gates.sh — shared anti-false-positive gate helpers for Slack alerts
# ---------------------------------------------------------------------------
# Sourced by uptime.yml, uptime-playwright.yml, and confirm-down-alerts.yml.
# Single source of truth for the two guarantees Ajaj requires on all Slack-
# firing paths (see memory: no-refire-slack-down):
#
#   1. External re-probe via check-host.net before firing a "down" alert.
#      If any external node sees 2xx, the runner is likely blocked and the
#      site is really up — silent-resolve, don't alert.
#   2. Cooldown after firing. Once we announce a "down" for slug X, don't
#      re-announce within COOLDOWN_SECONDS. Applies to any subsequent down
#      flip regardless of code.
#
# Also provides the pairing-invariant helpers used by the up-flip path:
#   - record_alert / clear_alert / has_pending_recovery — recovery pings
#     fire only if a matching down was previously announced.
#
# All functions are side-effecting via git (record/clear stage the file),
# so callers must be running inside a checked-out repo with git identity.
#
# Retention: recent-alerts files are NOT auto-purged. They persist until a
# paired recovery clears them (could be 24h+ for sustained outages). Bounded
# by site count (O(50)); size cost is negligible.
# ---------------------------------------------------------------------------

COOLDOWN_SECONDS_DEFAULT=1800  # 30 minutes

# check_external_up <url>
# Multi-node HTTP check via check-host.net. Fails open (returns 1) on any
# API error — safer to proceed to remaining gates than to swallow a real
# outage alert.
# Exit: 0 if any external node saw success + 2xx, 1 otherwise.
check_external_up() {
  local url="$1"
  local url_enc req_json req_id result_json ext_up ext_reported
  url_enc=$(printf %s "$url" | jq -sRr @uri)
  req_json=$(curl -s --max-time 15 -H "Accept: application/json" \
    "https://check-host.net/check-http?host=${url_enc}&max_nodes=3" 2>/dev/null || echo '{}')
  req_id=$(echo "$req_json" | jq -r '.request_id // empty' 2>/dev/null || echo "")
  if [ -z "$req_id" ]; then
    echo "[external-probe] ${url} — request failed (fail-open)"
    return 1
  fi
  sleep 8
  result_json=$(curl -s --max-time 15 -H "Accept: application/json" \
    "https://check-host.net/check-result/${req_id}" 2>/dev/null || echo '{}')
  ext_up=$(echo "$result_json" | jq '[.[] | select(. != null) | .[0] | select(.[0]==1 and (.[3] // "" | tostring | startswith("2")))] | length' 2>/dev/null || echo 0)
  ext_reported=$(echo "$result_json" | jq '[.[] | select(. != null)] | length' 2>/dev/null || echo 0)
  echo "[external-probe] ${url} up=${ext_up} reported=${ext_reported} req_id=${req_id}"
  if [ "$ext_up" -gt 0 ]; then
    return 0
  fi
  return 1
}

# check_cooldown_active <slug> [cooldown_seconds]
# Returns 0 if we've alerted this slug recently (should suppress new down).
check_cooldown_active() {
  local slug="$1"
  local cooldown="${2:-$COOLDOWN_SECONDS_DEFAULT}"
  local file=".alerts/recent-alerts/${slug}.yml"
  [ -f "$file" ] || return 1
  local last_alerted last_ts now_ts since_last
  last_alerted=$(yq -r '.alerted_at // empty' "$file" 2>/dev/null || echo "")
  [ -z "$last_alerted" ] && return 1
  last_ts=$(date -u -d "$last_alerted" +%s 2>/dev/null || echo 0)
  now_ts=$(date -u +%s)
  since_last=$((now_ts - last_ts))
  if [ "$since_last" -lt "$cooldown" ]; then
    echo "[cooldown] ${slug} — last alerted ${since_last}s ago (< ${cooldown}s)"
    return 0
  fi
  return 1
}

# record_alert <slug> <url>
# Called after a successful "down" Slack POST. Writes + stages the pairing
# record so the corresponding "up" recovery can fire and clear it.
record_alert() {
  local slug="$1"
  local url="${2:-}"
  mkdir -p .alerts/recent-alerts
  local file=".alerts/recent-alerts/${slug}.yml"
  {
    echo "slug: ${slug}"
    echo "url: ${url}"
    echo "alerted_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$file"
  git add "$file"
}

# has_pending_recovery <slug>
# 0 if there's a recorded down-alert awaiting its paired recovery.
has_pending_recovery() {
  local slug="$1"
  [ -f ".alerts/recent-alerts/${slug}.yml" ]
}

# clear_alert <slug>
# Called after a successful "up" recovery Slack POST. Resets the pairing
# state so a future down starts fresh.
clear_alert() {
  local slug="$1"
  local file=".alerts/recent-alerts/${slug}.yml"
  if [ -f "$file" ]; then
    git rm -f "$file" 2>/dev/null || rm -f "$file"
  fi
}
