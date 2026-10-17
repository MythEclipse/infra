#!/usr/bin/env bash
# gmw-watchdog — health-check GMW and alert a Discord ops webhook when it breaks.
#
# WHAT THIS CATCHES (and why a plain `is-active` check does not):
#   1. unit down / crash-looping
#   2. Discord token revoked or invalid  <- invisible to is-active, because
#      Restart=always keeps systemd "happy" while the process dies on every
#      Discord login. Only probing /users/@me with the service's own token sees it.
#   3. backend HTTP not answering on :4001
#   4. moderation queue not draining (rows piling up past their wait budget)
#
# ONE BWS CALL, NOT SIX. This script used to resolve three secret IDs via three
# `bws secret list` calls and then three `bws secret get` calls per run. `bws
# secret list` already returns `.value` for every key, so that was six round
# trips where one suffices — and the extra five were what tripped Bitwarden's
# 500-requests-per-minute limiter. A 429 was then swallowed by `2>/dev/null`,
# leaving an empty variable that was misread as "the token is gone".
#
# The ordering below is the actual fix for that false alarm: the webhook AND
# every value the checks need come out of the SAME atomic fetch. If Bitwarden is
# unreachable the fetch fails as a whole, so the run reports "BWS unreachable"
# and exits WITHOUT alerting — a BWS outage can no longer masquerade as a GMW
# outage. When the two were fetched separately, a failed token read alongside a
# successful webhook read produced a confident, wrong RED.
#
# A retry loop is deliberately absent. `bws` has no retry flag, and a retry
# without a wait is pointless, so a transient 429 costs one 5-minute cycle and
# the timer tries again. Losing one cycle beats inventing an outage.
#
# DEDUP: one alert per distinct failure fingerprint; recovery posts a single
# all-clear. State lives under /var/lib so it survives reboots.
set -uo pipefail

STATE_DIR="${STATE_DIR:-/var/lib/gmw-watchdog}"
STATE="$STATE_DIR/state"
# Overridable so an operator can dry-run the script against a scratch log and
# state file without touching (or corrupting) the live alerting state.
LOG="${LOG:-/var/log/gmw-watchdog.log}"
UNIT="${UNIT:-gmw-backend}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:4001/api/health}"
BWS_PROJECT="${BWS_PROJECT:-27210268-6134-47b3-9a68-b4980079d1ec}"
BWS="${BWS:-/usr/local/bin/bws}"

# Rows that have been waiting longer than this are a stuck pipeline, not a quiet
# guild. A backlog is the honest liveness signal: a dead worker accumulates rows
# while staying `active` and answering HTTP 200, whereas journal volume is
# dominated by how chatty the Discord server happens to be.
BACKLOG_MINUTES=15

WEBHOOK_KEY=pr_agent_discord_webhook_url

log() { printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG"; }

# --- secrets: ONE fetch, shared by the webhook and the checks -------------
# bws-exec exports the gmw_* secrets into this process already, so DISCORD_TOKEN
# and MONITOR_GUILD_ID normally need no API call at all — and reading the token
# from the environment is the most faithful possible check, since it is exactly
# the value the service booted with.
export BWS_ACCESS_TOKEN="${BWS_ACCESS_TOKEN:-$(tr -d '\r\n' </etc/bws-token 2>/dev/null || true)}"

secrets_json=""
load_secrets() {
  [[ -n "$secrets_json" ]] && return 0
  secrets_json="$("$BWS" secret list "$BWS_PROJECT" --output=json 2>/dev/null || true)"
  [[ -n "$secrets_json" ]] || return 1
  printf '%s' "$secrets_json" | jq -e 'type == "array"' >/dev/null 2>&1
}

secret_value() { # secret_value <key>
  load_secrets || return 1
  printf '%s' "$secrets_json" | jq -r --arg k "$1" 'first(.[] | select(.key == $k) | .value) // ""'
}

resolve_webhook() {
  local hook
  hook="$(secret_value "$WEBHOOK_KEY")" || return 1
  [[ -n "$hook" ]] || return 1
  printf '%s' "$hook"
}

# The webhook is the one secret bws-exec cannot export (it is not gmw_-prefixed),
# so it is genuinely needed. Without it there is no way to report anything, and
# an unreportable run must stay silent rather than guess.
if ! HOOK="$(resolve_webhook)"; then
  log "SKIP: Bitwarden unreachable or ${WEBHOOK_KEY} missing — cannot alert, claiming nothing"
  exit 1
fi

# Token and guild: prefer bws-exec's environment, fall back to the fetch.
TOKEN="${DISCORD_TOKEN:-}"
[[ -n "$TOKEN" ]] || TOKEN="$(secret_value gmw_discord_token)"
GUILD="${MONITOR_GUILD_ID:-}"
[[ -n "$GUILD" ]] || GUILD="$(secret_value gmw_monitor_guild_id)"

notify() { # notify <emoji> <title> <lines...>
  local emoji="$1" title="$2"
  shift 2
  local body="**${emoji} ${title}**" line
  for line in "$@"; do body="${body}\n\`\`\`\n${line}\n\`\`\`"; done
  body="${body}\n\`host\` \`$(hostname)\` · \`$(date -Is)\`"
  local payload
  payload=$(jq -n --arg c "$body" '{content:$c, username:"GMW Watchdog"}')
  curl -s -o /dev/null -m 20 -H 'Content-Type: application/json' -d "$payload" "$HOOK" ||
    log "notify failed"
}

# --- checks ---------------------------------------------------------------
problems=()

check_unit() {
  local active restarts recent
  active="$(systemctl is-active "$UNIT" 2>/dev/null)"
  [[ "$active" == "active" ]] ||
    problems+=("unit ${UNIT} is '${active}', expected 'active'")

  restarts="$(systemctl show "$UNIT" -p NRestarts --value 2>/dev/null || echo 0)"
  recent="$(journalctl -u "$UNIT" --since '-10 min' --no-pager 2>/dev/null |
    grep -c 'Started\|GMW ready' || true)"
  # A healthy long-lived service restarts rarely; more than 3 in 10 minutes is a
  # crash loop rather than a deploy.
  if [[ "${restarts:-0}" -gt 3 && "${recent:-0}" -gt 3 ]]; then
    problems+=("crash loop: NRestarts=${restarts} with ${recent} boots in the last 10 min")
  fi
}

check_http() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$HEALTH_URL" 2>/dev/null)"
  [[ "$code" == "200" ]] ||
    problems+=("backend health ${HEALTH_URL} -> HTTP ${code:-000}, expected 200")
}

check_discord() {
  # A user token takes NO 'Bot ' prefix — the `Bot` scheme belongs to bot tokens
  # and 401s against a user token regardless of whether that token is alive.
  local me status who uid member_status
  if [[ -z "$TOKEN" ]]; then
    problems+=("DISCORD_TOKEN is empty (bws-exec env and Bitwarden both gave nothing)")
    return
  fi

  # Captured into a variable, never a /tmp file: a concurrent /tmp reaper or a
  # leftover file from an earlier run made the JSON read fail, and the empty
  # result was then reported as "account '' is not a member of guild".
  # `-w '\n%{http_code}'` keeps the status and body in one round trip.
  me="$(curl -s -m 20 -w '\n%{http_code}' -H "Authorization: $TOKEN" \
    https://discord.com/api/v10/users/@me 2>/dev/null)"
  status="${me##*$'\n'}"
  me="${me%$'\n'*}"
  if [[ "$status" != "200" ]]; then
    problems+=("Discord token REJECTED — /users/@me -> HTTP ${status:-000}. Token revoked or invalid. Fix: bws secret edit gmw_discord_token, then systemctl restart gmw-backend")
    return
  fi

  who="$(printf '%s' "$me" | jq -r '.username // "unknown"')"
  uid="$(printf '%s' "$me" | jq -r '.id // ""')"
  [[ -n "$GUILD" && -n "$uid" ]] || return
  member_status="$(curl -s -o /dev/null -w '%{http_code}' -m 20 -H "Authorization: $TOKEN" \
    "https://discord.com/api/v10/guilds/${GUILD}/members/${uid}" 2>/dev/null)"
  [[ "$member_status" == "200" ]] ||
    problems+=("account '${who}' is not a member of monitored guild ${GUILD} (HTTP ${member_status})")
}

# Queue depth, not journal volume. `message captured` lines only appear when the
# server is chatty, so the old grep fired on every genuinely quiet stretch and
# then "recovered" on its own the moment someone typed — six consecutive false
# REDs in one overnight window. Rows sitting in the queue past their budget mean
# the worker is stuck no matter how quiet the guild is, and an empty queue means
# the pipeline is fine no matter how quiet the guild is.
check_backlog() {
  local age_ms backlog
  [[ -n "${DATABASE_URL:-}" ]] || return
  command -v psql >/dev/null 2>&1 || return
  age_ms=$((BACKLOG_MINUTES * 60 * 1000))
  backlog="$(psql "$DATABASE_URL" -tAc \
    "SELECT count(*) FROM messages
      WHERE ai_status IN ('pending','retry_wait')
        AND created_at < (extract(epoch FROM now()) * 1000 - ${age_ms})::bigint" 2>/dev/null)" || return
  [[ "$backlog" =~ ^[0-9]+$ ]] || return
  [[ "$backlog" -eq 0 ]] ||
    problems+=("${backlog} message(s) queued for more than ${BACKLOG_MINUTES} min — moderation worker is not draining the queue")
}

check_unit
check_http
check_discord
check_backlog

# --- dedup + dispatch -----------------------------------------------------
mkdir -p "$STATE_DIR" 2>/dev/null || true
fingerprint="$(printf '%s' "${problems[*]-}" | sha256sum | cut -c1-16)"
previous="$(cat "$STATE" 2>/dev/null || echo none)"

if [[ "${#problems[@]}" -gt 0 ]]; then
  log "ALERT(${problems[*]}): ${#problems[@]} problem(s)"
  if [[ "$fingerprint" != "$previous" ]]; then
    notify "🔴" "GMW DEGRADED — ${#problems[@]} problem(s)" "${problems[@]}"
    printf '%s' "$fingerprint" >"$STATE"
  fi
else
  if [[ "$previous" != "none" ]]; then
    notify "🟢" "GMW recovered — all checks pass"
    log "RECOVERED"
  fi
  printf 'none' >"$STATE"
  log "OK: all checks pass"
fi

unset TOKEN HOOK secrets_json
