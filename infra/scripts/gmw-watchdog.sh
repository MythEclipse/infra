#!/usr/bin/env bash
# gmw-watchdog — health-check GMW and alert a Discord ops webhook when it breaks.
#
# WHAT THIS CATCHES (and why a plain `is-active` check does not):
#   1. unit down / crash-looping
#   2. Discord gateway down, wedged, or refused at login
#   3. backend HTTP not answering on :4001
#   4. moderation queue not draining (rows piling up past their wait budget)
#
# ## Why there is no longer a `GET /users/@me` token probe
#
# This script used to verify the Discord credential from the OUTSIDE: every five
# minutes it sent an authenticated REST call to discord.com with the account's
# user token, and treated anything but HTTP 200 as "token revoked".
#
# That was wrong twice over.
#
# First, it is the signature of a selfbot. A datacenter IP issuing a bare
# user-token REST call on a fixed timer, holding no gateway session, is exactly
# what Discord's anti-abuse heuristics look for — the watchdog risked getting
# banned the very account it was guarding. An operations check must not be
# indistinguishable from the abuse it is supposed to be watching for.
#
# Second, it could not tell the two failures apart. HTTP 000 is a TRANSPORT
# failure (DNS, TCP, TLS, timeout) — the request never reached Discord, so it
# says nothing whatsoever about the token. The old code reported it as
# "Token revoked or invalid. Fix: bws secret edit gmw_discord_token", which sent
# an operator to rotate a perfectly good credential in response to a network
# blip. The alert stream in the ops channel is full of exactly that.
#
# So the observation moved to where the credential lives. The backend already
# holds an authenticated gateway connection; it publishes what that connection
# is doing at `GET /api/discord/status` on loopback, and this script reads it.
# No outbound request, no credential used, and a strictly better signal: a probe
# tested whether a token *would* authenticate, this reports whether the session
# *is* alive — including the cases a probe could never see, like a socket that
# stays open while Discord has stopped talking to it.
#
# ## Reading a report is not the same as probing
#
# The gateway check therefore treats "I could not read the report" as UNKNOWN,
# not as a fault. A refused connection, a timeout, a non-200, a body that is not
# JSON — all mean this script is blind, and a blind run claims nothing. Only a
# well-formed report describing a broken gateway produces a RED. That is the same
# rule the Bitwarden fix below arrived at, applied to the other fetch in this
# file.
#
# ONE BWS CALL, NOT SIX. This script used to resolve three secret IDs via three
# `bws secret list` calls and then three `bws secret get` calls per run. `bws
# secret list` already returns `.value` for every key, so that was six round
# trips where one suffices — and the extra five were what tripped Bitwarden's
# 500-requests-per-minute limiter. A 429 was then swallowed by `2>/dev/null`,
# leaving an empty variable that was misread as "the token is gone".
#
# The token and guild reads are gone entirely now that the gateway is observed
# from inside, so what is left is the ONE secret bws-exec cannot export (the
# webhook is not gmw_-prefixed) and the ONE call that fetches it. If Bitwarden is
# unreachable the fetch fails as a whole and the run exits WITHOUT alerting — a
# BWS outage can no longer masquerade as a GMW outage.
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
# The backend's own account of its Discord session. Loopback only, always 200.
STATUS_URL="${STATUS_URL:-http://127.0.0.1:4001/api/discord/status}"
BWS_PROJECT="${BWS_PROJECT:-27210268-6134-47b3-9a68-b4980079d1ec}"
BWS="${BWS:-/usr/local/bin/bws}"

# Rows that have been waiting longer than this are a stuck pipeline, not a quiet
# guild. A backlog is the honest liveness signal: a dead worker accumulates rows
# while staying `active` and answering HTTP 200, whereas journal volume is
# dominated by how chatty the Discord server happens to be.
BACKLOG_MINUTES=15

# A restart legitimately spends a minute migrating, binding HTTP and logging in,
# so "not connected yet" is not a fault until this window has passed.
GATEWAY_BOOT_GRACE_SEC="${GATEWAY_BOOT_GRACE_SEC:-180}"
# A reconnect is normal; a session that has been down this long is not.
GATEWAY_DOWN_SEC="${GATEWAY_DOWN_SEC:-300}"
# Discord heartbeats every ~41s and the library re-emits every frame, so a READY
# client that has heard nothing for this long is wedged, not merely quiet.
GATEWAY_SILENT_SEC="${GATEWAY_SILENT_SEC:-600}"
# The guild cache fills in after the READY payload. Only complain about a missing
# guild once the session has had time to settle.
GATEWAY_GUILD_SETTLE_SEC="${GATEWAY_GUILD_SETTLE_SEC:-120}"

WEBHOOK_KEY=pr_agent_discord_webhook_url

log() { printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG"; }

# Milliseconds since epoch, to compare against the report's epoch-ms stamps.
now_ms() { date +%s%3N; }

# --- secrets: ONE fetch, for the only value bws-exec cannot provide --------
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

# Token and guild: the gateway check reads both from the backend's own report, so
# no credential is fetched or transmitted here at all.

# Human-readable duration: "42s", "4m 12s", "3h 07m", "2d 4h".
human_duration() {
  local s="${1:-0}"
  if [[ "$s" -lt 60 ]]; then printf '%ds' "$s"
  elif [[ "$s" -lt 3600 ]]; then printf '%dm %02ds' $((s / 60)) $((s % 60))
  elif [[ "$s" -lt 86400 ]]; then printf '%dh %02dm' $((s / 3600)) $((s % 3600 / 60))
  else printf '%dd %dh' $((s / 86400)) $((s % 86400 / 3600))
  fi
}

send_content() { # send_content <content>
  local payload
  payload=$(jq -n --arg c "$1" '{content:$c, username:"GMW Watchdog"}')
  curl -s -o /dev/null -m 20 -H 'Content-Type: application/json' -d "$payload" "$HOOK" ||
    log "notify failed"
}

# One readable message: a bold headline, a bulleted list, one footer.
#
# The previous version wrapped EVERY problem in its own triple-backtick block,
# which on a phone rendered as a column of grey slabs separated by blank lines —
# the operator had to reassemble the alert by eye. A bullet list reads as what it
# is: a short list of faults.
#
# Discord rejects content over 2000 characters with a 400 and the alert is simply
# lost, so the list is chunked on problem boundaries rather than truncated. An
# error message can be long; a silently dropped alert is worse than two messages.
notify() { # notify <emoji> <title> <problem...>
  local emoji="$1" title="$2"
  shift 2
  local header="**${emoji} ${title}**"
  local footer
  footer="$(hostname) · $(date '+%Y-%m-%d %H:%M %Z')"
  local chunk="$header" line
  for line in "$@"; do
    # A problem is one line by contract; flatten anyway so a multi-line error
    # from Discord cannot break the bullet layout.
    line="${line//$'\n'/ }"
    if ((${#chunk} + ${#line} + 8 > 1800)); then
      send_content "$chunk"
      chunk="$header (continued)"
    fi
    chunk="${chunk}"$'\n'"• ${line}"
  done
  send_content "${chunk}"$'\n\n'"${footer}"
}

# Recovery is prose, not a list. A single bulleted sentence ("• Degraded for
# 4m 12s") reads like a fault that is still present; the all-clear should read
# as a sentence.
notify_plain() { # notify_plain <emoji> <title> <line...>
  local emoji="$1" title="$2"
  shift 2
  local body="**${emoji} ${title}**" line
  for line in "$@"; do body="${body}"$'\n'"${line}"; done
  send_content "${body}"$'\n\n'"$(hostname) · $(date '+%Y-%m-%d %H:%M %Z')"
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

# The gateway's own account of itself, read from loopback.
#
# Every branch below is a distinct, diagnosable fault with a distinct fix, which
# is the point of reading a structured report instead of a status code: a
# revoked token and a wedged socket both look like HTTP 200 from outside, and an
# operator should not have to guess which one they have.
check_gateway() {
  local raw code body
  raw="$(curl -s -m 10 -w '\n%{http_code}' "$STATUS_URL" 2>/dev/null)"
  code="${raw##*$'\n'}"
  body="${raw%$'\n'*}"

  # Blind, not broken. See the header: an unreadable report is UNKNOWN.
  if [[ "$code" != "200" ]]; then
    log "SKIP: ${STATUS_URL} -> HTTP ${code:-000}; gateway unobservable, claiming nothing"
    return
  fi
  if ! printf '%s' "$body" | jq -e 'type == "object"' >/dev/null 2>&1; then
    log "SKIP: ${STATUS_URL} returned no JSON object; gateway unobservable, claiming nothing"
    return
  fi

  # One jq pass, ONE VALUE PER LINE.
  #
  # Not `IFS=$'\t' read`: a tab is IFS *whitespace*, so consecutive tabs collapse
  # and an empty field silently shifts every column after it. `loginError: ""`
  # and `lastDisconnect: null` are both normal and both empty, so that read
  # misparsed healthy reports — it reported `state=""` and the gateway check
  # bailed out as unobservable, which reads exactly like a working SKIP.
  #
  # `mapfile` keeps empty elements, and the free-text fields have their tabs and
  # newlines flattened first so one value can never span two lines.
  local -a f
  mapfile -t f < <(printf '%s' "$body" | jq -r '[
      (.connected // false),
      (.everReady // false),
      (.invalidated // false),
      ((.loginError // "") | tostring | gsub("[\\t\\n\\r]"; " ")),
      (.uptimeMs // 0),
      (.downSince // 0),
      (.lastPacketAgoMs // -1),
      (.readySince // 0),
      (.lastDisconnect.code // 0),
      ((.lastDisconnect.reason // "") | tostring | gsub("[\\t\\n\\r]"; " ")),
      (.state // "unknown"),
      ([.monitoredGuilds[]? | select(.present == false) | .id] | join(","))
    ] | .[]' 2>/dev/null)

  if [[ "${#f[@]}" -lt 12 ]]; then
    log "SKIP: could not parse ${STATUS_URL}; gateway unobservable, claiming nothing"
    return
  fi

  local connected="${f[0]}" ever_ready="${f[1]}" invalidated="${f[2]}"
  local login_error="${f[3]}" uptime_ms="${f[4]}" down_since="${f[5]}"
  local packet_age_ms="${f[6]}" ready_since="${f[7]}" disconnect_code="${f[8]}"
  local disconnect_reason="${f[9]}" state="${f[10]}" missing_guilds="${f[11]}"

  # 1. The credential was rejected at startup. `loginError` is cleared on the
  #    first successful ready, so a non-empty value is conclusive: the process is
  #    up, the dashboard is up, and capture has never once started.
  if [[ -n "$login_error" ]]; then
    problems+=("Discord login FAILED — the stored token was rejected at startup and the gateway never connected (${login_error}). Fix: bws secret edit gmw_discord_token, then systemctl restart ${UNIT}")
    return
  fi

  # 2. The library gave up re-identifying and destroyed its shards. Capture is
  #    dead and only a restart recovers it.
  if [[ "$invalidated" == "true" ]]; then
    problems+=("Discord session INVALIDATED — the gateway could not re-identify and stopped, so nothing is captured. Fix: systemctl restart ${UNIT}")
    return
  fi

  # 3. A close code that names the fault. 4004 is authentication failed; 4013 and
  #    4014 are Discord refusing this client outright. None of these is a network
  #    problem, and each is fatal to capture until something changes.
  case "$disconnect_code" in
    4004 | 4013 | 4014)
      problems+=("Discord closed the gateway with ${disconnect_code} (${disconnect_reason:-no reason given}) — the token is rejected or the account is restricted. Fix: bws secret edit gmw_discord_token, then systemctl restart ${UNIT}")
      return
      ;;
  esac

  if [[ "$connected" != "true" ]]; then
    if [[ "$ever_ready" != "true" ]]; then
      # Never connected. Booting is not a fault; booting forever is.
      if [[ "$uptime_ms" -lt $((GATEWAY_BOOT_GRACE_SEC * 1000)) ]]; then
        log "gateway still starting (up ${uptime_ms}ms, state=${state})"
      else
        problems+=("Discord gateway NEVER connected — still '${state}' after $((uptime_ms / 60000)) min up, with no login error recorded. Check: journalctl -u ${UNIT} | grep -i 'login'")
      fi
    else
      # Was connected, is not now. A short reconnect is normal.
      local down_ms=0
      [[ "$down_since" -gt 0 ]] && down_ms=$(( $(now_ms) - down_since ))
      if [[ "$down_ms" -gt $((GATEWAY_DOWN_SEC * 1000)) ]]; then
        problems+=("Discord gateway disconnected for $((down_ms / 60000)) min (state='${state}') — capture is stopped. Check: journalctl -u ${UNIT} | grep -i 'gateway\\|disconnect'")
      else
        log "gateway reconnecting (${down_ms}ms down, state=${state})"
      fi
    fi
    return
  fi

  # 4. READY but silent. The socket is open and the library says connected, yet
  #    Discord has sent nothing — not even the ~41s heartbeat — for ten minutes.
  #    This is a wedged connection, and it is invisible to every other check here.
  if [[ "$packet_age_ms" -ge 0 && "$packet_age_ms" -gt $((GATEWAY_SILENT_SEC * 1000)) ]]; then
    problems+=("Discord gateway is READY but has received nothing for $((packet_age_ms / 60000)) min — the socket is open and dead, so capture has stopped. Fix: systemctl restart ${UNIT}")
  fi

  # 5. Logged in, but not in the guild it is supposed to moderate. Everything
  #    looks healthy and nothing is captured. Only checked once the session has
  #    settled, because the guild cache fills in after READY.
  if [[ -n "$missing_guilds" && "$ready_since" -gt 0 ]]; then
    local settled_ms=$(( $(now_ms) - ready_since ))
    if [[ "$settled_ms" -gt $((GATEWAY_GUILD_SETTLE_SEC * 1000)) ]]; then
      problems+=("account is not a member of monitored guild(s) ${missing_guilds} — nothing from them is captured")
    fi
  fi
}

# Queue depth, not journal volume. `message captured` lines only appear when the
# server is chatty, so the old grep fired on every genuinely quiet stretch and
# then "recovered" on its own the moment someone typed — six consecutive false
# REDs in one overnight window.
#
# The predicate mirrors `claim_messages()` EXACTLY, and that is the fix for the
# other false alarm this check produced. It was missing `deleted_at IS NULL`, so
# every message the account had deleted in Discord — which the worker correctly
# never claims, because `claim_messages` filters them out — stayed counted as
# backlog forever. Production sat at "33 message(s) queued for more than 15 min"
# for hours with ZERO claimable rows: 34 soft-deleted messages, all unclaimable
# by design, reported as a stuck worker every five minutes.
#
# `ready_for_work_at` is the second half of the same mistake: a row in backoff is
# legitimately not claimable yet, and counting it turns normal retry behaviour
# into an outage.
#
# So the count is now literally "rows `claim_messages` would pick, that nobody
# has picked, for 15 minutes" — the only reading that means the worker is stuck.
check_backlog() {
  local age_ms backlog
  [[ -n "${DATABASE_URL:-}" ]] || return
  command -v psql >/dev/null 2>&1 || return
  age_ms=$((BACKLOG_MINUTES * 60 * 1000))
  backlog="$(psql "$DATABASE_URL" -tAc \
    "SELECT count(*) FROM messages
      WHERE ai_status IN ('pending','retry_wait')
        AND deleted_at IS NULL
        AND ready_for_work_at <= (extract(epoch FROM now()) * 1000)::bigint
        AND created_at < (extract(epoch FROM now()) * 1000 - ${age_ms})::bigint" 2>/dev/null)" || return
  [[ "$backlog" =~ ^[0-9]+$ ]] || return
  [[ "$backlog" -eq 0 ]] ||
    problems+=("${backlog} message(s) queued for more than ${BACKLOG_MINUTES} min — moderation worker is not draining the queue")
}

check_unit
check_http
check_gateway
check_backlog

# --- dedup + dispatch -----------------------------------------------------
# State is two lines: the fingerprint of the current failure set, and the epoch
# second it was FIRST seen. The timestamp is what makes the recovery message
# worth reading — "recovered" with no duration cannot tell a five-minute blip
# from an all-night outage, and duration is the first thing anyone asks.
#
# A single-line state file is a pre-upgrade leftover; it is read as a fingerprint
# with no known start time rather than discarded, so an alert that is currently
# open still closes properly instead of re-firing.
mkdir -p "$STATE_DIR" 2>/dev/null || true
fingerprint="$(printf '%s' "${problems[*]-}" | sha256sum | cut -c1-16)"
previous="none"
previous_since=""
if [[ -f "$STATE" ]]; then
  previous="$(sed -n 1p "$STATE" 2>/dev/null)"
  previous_since="$(sed -n 2p "$STATE" 2>/dev/null)"
  previous="${previous:-none}"
fi

if [[ "${#problems[@]}" -gt 0 ]]; then
  log "ALERT(${problems[*]}): ${#problems[@]} problem(s)"
  if [[ "$fingerprint" != "$previous" ]]; then
    notify "🔴" "GMW DEGRADED — ${#problems[@]} problem(s)" "${problems[@]}"
    printf '%s\n%s\n' "$fingerprint" "$(date +%s)" >"$STATE"
  fi
else
  if [[ "$previous" != "none" ]]; then
    # Say how long it was broken. The duration is measured from the first run
    # that saw this failure, so it is a lower bound, not an exact outage window —
    # the watchdog only observes once per timer tick.
    if [[ "$previous_since" =~ ^[0-9]+$ ]]; then
      notify_plain "🟢" "GMW recovered — all checks pass" \
        "Degraded for **$(human_duration $(( $(date +%s) - previous_since )))** (since $(date -d "@${previous_since}" '+%H:%M %Z'))."
    else
      notify_plain "🟢" "GMW recovered — all checks pass"
    fi
    log "RECOVERED"
  fi
  printf 'none\n' >"$STATE"
  log "OK: all checks pass"
fi

unset HOOK secrets_json
