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
# STATE MODEL — .alerts/recent-alerts/<slug>.yml has two timestamps:
#   alerted_at   — when we fired the "down" Slack ping. Never cleared until
#                  the file is purged. Drives the cooldown check.
#   recovered_at — set when the paired "up" recovery ping fires. Empty (or
#                  missing) means we still owe a recovery. Drives pairing.
#
# TRANSITIONS:
#   record_alert : create file, alerted_at=NOW, recovered_at empty
#                  → subsequent DOWN suppressed by cooldown (alerted_at fresh)
#                  → next UP fires recovery (has_pending_recovery true)
#   clear_alert  : set recovered_at=NOW, KEEP file
#                  → subsequent DOWN still suppressed (cooldown still counting
#                    from alerted_at, not recovered_at)
#                  → next UP suppressed (has_pending_recovery false)
#   purge (in confirm-down-alerts): delete file when recovered_at set AND
#                  alerted_at > 2 × COOLDOWN old. Frees state for a truly
#                  new incident later.
#
# Result: exactly one down + one up Slack ping per outage incident, even
# if the site flaps rapidly within the cooldown window. Two separate real
# outages > 30 min apart each get their own down+up pair.
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
# Called after a successful "down" Slack POST. Writes + stages the tracking
# record with alerted_at=NOW and recovered_at empty (pairing pending).
# Overwrites any prior record for the slug — a fresh alert starts a fresh
# cooldown window from this moment.
record_alert() {
  local slug="$1"
  local url="${2:-}"
  mkdir -p .alerts/recent-alerts
  local file=".alerts/recent-alerts/${slug}.yml"
  {
    echo "slug: ${slug}"
    echo "url: ${url}"
    echo "alerted_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "recovered_at:"
  } > "$file"
  git add "$file"
}

# has_pending_recovery <slug>
# Returns 0 if there's an unrecovered down-alert (file exists AND
# recovered_at is empty). Used by the up-flip path — fire recovery only
# when we owe one.
has_pending_recovery() {
  local slug="$1"
  local file=".alerts/recent-alerts/${slug}.yml"
  [ -f "$file" ] || return 1
  local recovered
  recovered=$(yq -r '.recovered_at // empty' "$file" 2>/dev/null || echo "")
  [ -z "$recovered" ]
}

# clear_alert <slug>
# Called after a successful "up" recovery Slack POST. Sets recovered_at
# but KEEPS the file, so check_cooldown_active still finds alerted_at and
# suppresses any near-term flap-back to down within the cooldown window.
clear_alert() {
  local slug="$1"
  local file=".alerts/recent-alerts/${slug}.yml"
  [ -f "$file" ] || return 0
  local recovered_at
  recovered_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if grep -q '^recovered_at:' "$file"; then
    sed -i "s|^recovered_at:.*|recovered_at: ${recovered_at}|" "$file"
  else
    echo "recovered_at: ${recovered_at}" >> "$file"
  fi
  git add "$file"
}

# purge_stale_alerts [max_age_seconds]
# Deletes recent-alerts files where recovered_at is set AND alerted_at is
# older than max_age. Keeps state for the full cooldown window post-recovery
# so a flap-back still gets suppressed. Called from confirm-down-alerts.
# Default max_age = 2 × COOLDOWN (1 hour).
purge_stale_alerts() {
  local max_age="${1:-3600}"
  local now_ts
  now_ts=$(date -u +%s)
  local file rec_at alerted_at alerted_ts
  for file in .alerts/recent-alerts/*.yml; do
    [ -f "$file" ] || continue
    rec_at=$(yq -r '.recovered_at // empty' "$file" 2>/dev/null || echo "")
    [ -z "$rec_at" ] && continue  # still awaiting recovery — keep
    alerted_at=$(yq -r '.alerted_at // empty' "$file" 2>/dev/null || echo "")
    [ -z "$alerted_at" ] && continue
    alerted_ts=$(date -u -d "$alerted_at" +%s 2>/dev/null || echo 0)
    if [ $((now_ts - alerted_ts)) -gt "$max_age" ]; then
      echo "[purge] $(basename "$file" .yml) — recovered + cooldown expired"
      git rm -f "$file" 2>/dev/null || rm -f "$file"
    fi
  done
}
