#!/usr/bin/env bash
# Offline regression tests for gmw-watchdog.sh.
#
# No network, no Bitwarden, no Discord, no real credentials: every external
# command is a stub, so this runs anywhere (including CI) and cannot touch
# production.
#
# The cases are grouped by the two false alarms this script has actually
# produced in production, because those are what it exists to prevent:
#
#   * A Bitwarden 429 reported as "the Discord token is dead".
#   * 34 soft-deleted messages reported as "the moderation worker is stuck",
#     every five minutes, for hours.
#
# plus the structural rule that replaced the token probe: an UNREADABLE gateway
# report is unknown, never a fault. A watchdog that cannot see must say nothing,
# or a backend restart becomes an outage alert.
#
#   bash infra/tests/gmw-watchdog-test.sh
#
# Exit 0 = all cases pass.
set -uo pipefail

SCRIPT="${SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/gmw-watchdog.sh}"
[[ -f "$SCRIPT" ]] || { echo "cannot find gmw-watchdog.sh at $SCRIPT" >&2; exit 2; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK/bin" "$WORK/state"
CAPTURE="$WORK/captured.ndjson"
: >"$CAPTURE"

# --- one local server: captures POSTs (alert sink), serves the two GETs -----
# A real class, not a lambda: BaseHTTPRequestHandler cannot be built from
# lambdas, and a server that silently fails to start makes every "expect no
# alert" case pass for the wrong reason. It prints its port on stdout.
#
# `/status` answers from files so each case can dictate exactly what the backend
# would have reported. Code and body are separate files on purpose: the watchdog
# must treat a non-200 and a garbage body identically (as UNKNOWN), and both
# need to be reproducible.
cat >"$WORK/server.py" <<'PY'
import http.server, sys
capture, status_path, code_path = sys.argv[1], sys.argv[2], sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        with open(capture, 'a') as f:
            f.write(self.rfile.read(n).decode('utf-8', 'replace') + "\n")
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/status'):
            try:
                body = open(status_path, 'rb').read()
            except FileNotFoundError:
                body = b''
            try:
                code = int(open(code_path).read().strip())
            except (FileNotFoundError, ValueError):
                code = 200
        else:
            body = b'{"status":"healthy"}'
            code = 200
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

srv = http.server.HTTPServer(('127.0.0.1', 0), Handler)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY

: >"$CAPTURE"
printf '200' >"$WORK/status.code"
# The port travels over a FIFO so this blocks until the server is genuinely
# listening. A spin loop would race the interpreter's startup instead.
mkfifo "$WORK/port.fifo"
python3 "$WORK/server.py" "$CAPTURE" "$WORK/status.json" "$WORK/status.code" >"$WORK/port.fifo" &
SERVER_PID=$!
read -r PORT <"$WORK/port.fifo"
if [[ -z "${PORT:-}" ]]; then echo "test harness: local server failed to start" >&2; exit 2; fi
HEALTH_URL="http://127.0.0.1:$PORT/health"
STATUS_URL="http://127.0.0.1:$PORT/status"

# --- stub bws: synthetic secrets, optional 429 on chosen call numbers -------
cat >"$WORK/bin/bws" <<BSTUB
#!/usr/bin/env bash
n=\$(( \$(cat "$WORK/bws-calls" 2>/dev/null || echo 0) + 1 ))
echo "\$n" >"$WORK/bws-calls"
for f in \${BWS_STUB_FAIL_ON//,/ }; do
  [[ -n "\$f" && "\$f" == "\$n" ]] && { echo "[429 Too Many Requests]" >&2; exit 1; }
done
cat <<JSON
[{"key":"pr_agent_discord_webhook_url","value":"http://127.0.0.1:$PORT/hook"}]
JSON
BSTUB
chmod +x "$WORK/bin/bws"

# --- stub curl: loopback only; real Discord traffic is refused --------------
# The refusal is the point. The watchdog must make NO outbound request with the
# account's credential, so any attempt to reach discord.com is a test failure,
# not a tolerated side effect.
cat >"$WORK/bin/curl" <<'CSTUB'
#!/usr/bin/env bash
url=""
for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
case "$url" in
  *discord.com*) echo "stub: BLOCKED outbound Discord request ($url)" >&2; exit 7 ;;
  http://127.0.0.1*|http://localhost*|"") ;;
  *) echo "stub: BLOCKED $url" >&2; exit 7 ;;
esac
exec /usr/bin/curl "$@"
CSTUB
chmod +x "$WORK/bin/curl"

# --- stub psql: reports the backlog the case asks for, and records the SQL ---
# The recorded text is asserted on: the false alarm was a PREDICATE bug, so the
# predicate itself has to be covered, not just its result.
printf '#!/usr/bin/env bash\nprintf "%%s" "$*" >"%s/psql-sql"\necho "${PSQL_BACKLOG:-0}"\n' \
  "$WORK" >"$WORK/bin/psql"
chmod +x "$WORK/bin/psql"

# --- stub systemctl: the unit is "active", and no crash loop ----------------
printf '#!/usr/bin/env bash\ncase "$*" in *is-active*) echo active ;; *NRestarts*) echo 0 ;; esac\n' >"$WORK/bin/systemctl"
chmod +x "$WORK/bin/systemctl"

# --- stub journalctl: no boots, so the crash-loop check stays quiet ---------
printf '#!/usr/bin/env bash\necho 0\n' >"$WORK/bin/journalctl"
chmod +x "$WORK/bin/journalctl"

export PATH="$WORK/bin:$PATH"

# A gateway report with every field at its healthy value. Each case overrides
# only what it is about, so a field added to the endpoint later defaults to
# "fine" here instead of silently failing twenty cases.
status_json() { # status_json [jq filter...]
  local expr='{"state":"ready","connected":true,"everReady":true,
    "readySince":null,"downSince":null,"lastPacketAt":null,
    "lastPacketAgoMs":1200,"uptimeMs":600000,"invalidated":false,
    "loginError":null,"lastDisconnect":null,"lastError":null,
    "guildsCached":3,"monitoredGuilds":[{"id":"111111111111111111","present":true}]}'
  local filter
  for filter in "$@"; do expr="$(printf '%s' "$expr" | jq -c "$filter")"; done
  printf '%s' "$expr"
}

invoke() { # invoke <fail_on> <status-json> [backlog] [status_url_override]
  if [[ -n "${2:-}" ]]; then printf '%s' "$2" >"$WORK/status.json"; else : >"$WORK/status.json"; fi
  BWS_STUB_FAIL_ON="${1:-}" \
    DATABASE_URL="postgres://stub/stub" PSQL_BACKLOG="${3:-0}" \
    STATE_DIR="$WORK/state" LOG="$WORK/log" BWS="$WORK/bin/bws" \
    HEALTH_URL="$HEALTH_URL" STATUS_URL="${4:-$STATUS_URL}" UNIT="gmw-backend" \
    bash "$SCRIPT" >/dev/null 2>&1
}
fresh() {
  : >"$CAPTURE"; echo 0 >"$WORK/bws-calls"
  rm -f "$WORK/state/state" "$WORK/log" "$WORK/psql-sql"
  printf '200' >"$WORK/status.code"
}
reds() { grep -c '🔴' "$CAPTURE" 2>/dev/null || true; }
greens() { grep -c '🟢' "$CAPTURE" 2>/dev/null || true; }
calls() { cat "$WORK/bws-calls" 2>/dev/null || echo 0; }
# `grep -c` prints 0 AND exits 1 when nothing matches, so `grep -c ... || echo 0`
# emits "0\n0" — which made the "no code fences" assertion fail while printing a
# matching want=0. Count on one line, always.
count_in() { grep -c -- "$1" "$2" 2>/dev/null | head -1 || true; }
logcount() { count_in "$1" "$WORK/log"; }

PASS=0 FAIL=0
check() {
  if [[ "$2" == "$3" ]]; then printf '  ok    %-52s %s\n' "$1" "$3"; PASS=$((PASS + 1))
  else printf '  FAIL  %-52s want=%s got=%s\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}

# Sanity: the sink must actually be reachable, or every "no alert" case below
# would pass for the wrong reason.
if ! curl -s -o /dev/null -m 2 -X POST "http://127.0.0.1:$PORT/sink-check"; then
  echo "test harness: alert sink unreachable" >&2; exit 2
fi
: >"$CAPTURE"

echo "gmw-watchdog offline tests"

echo "=== healthy system ==="
fresh; invoke "" "$(status_json)"
check "no alert" 0 "$(reds)"
check "Bitwarden called once per run" 1 "$(calls)"

echo "=== no outbound Discord request, ever (the anti-selfbot rule) ==="
# If this fires, the watchdog has gone back to probing Discord with the
# account's credential from a datacenter IP.
fresh; invoke "" "$(status_json)"
check "no request to discord.com" 0 "$(logcount 'BLOCKED')"

echo "=== Bitwarden rate-limits the run (a reported spam trigger) ==="
fresh; invoke "1,2,3,4,5,6" "$(status_json)"
check "NO false alert" 0 "$(reds)"
check "logged SKIP and claimed nothing" 1 "$(logcount 'SKIP')"

echo "=== token rejected at startup ==="
fresh; invoke "" "$(status_json '.connected=false | .everReady=false
  | .state="idle" | .uptimeMs=600000
  | .loginError="An invalid token was provided"')"
check "exactly one RED" 1 "$(reds)"
check "names the login failure" 1 "$(logcount 'login FAILED')"

echo "=== session invalidated (cannot re-identify) ==="
fresh; invoke "" "$(status_json '.connected=false | .invalidated=true | .state="disconnected"')"
check "one RED" 1 "$(reds)"
check "blames the invalidated session" 1 "$(logcount 'INVALIDATED')"

echo "=== gateway closed with 4004 (auth failed) ==="
fresh; invoke "" "$(status_json '.connected=false | .state="disconnected"
  | .lastDisconnect={"code":4004,"reason":"Authentication failed.","at":0}')"
check "one RED" 1 "$(reds)"
check "names the close code" 1 "$(logcount 'closed the gateway with 4004')"

echo "=== still booting: not yet connected, inside the grace window ==="
fresh; invoke "" "$(status_json '.connected=false | .everReady=false | .state="connecting" | .uptimeMs=30000')"
check "NO alert" 0 "$(reds)"

echo "=== never connected, past the grace window ==="
fresh; invoke "" "$(status_json '.connected=false | .everReady=false | .state="identifying" | .uptimeMs=900000')"
check "one RED" 1 "$(reds)"
check "says it never connected" 1 "$(logcount 'NEVER connected')"

echo "=== brief reconnect: normal, not an outage ==="
fresh; invoke "" "$(status_json ".connected=false | .state=\"reconnecting\" | .downSince=$(( $(date +%s%3N) - 20000 ))")"
check "NO alert" 0 "$(reds)"

echo "=== down for 20 minutes: a real outage ==="
fresh; invoke "" "$(status_json ".connected=false | .state=\"reconnecting\" | .downSince=$(( $(date +%s%3N) - 1200000 ))")"
check "one RED" 1 "$(reds)"
check "reports the down duration" 1 "$(logcount 'disconnected for 20 min')"

echo "=== READY but silent: the wedged socket ==="
fresh; invoke "" "$(status_json '.lastPacketAgoMs=900000')"
check "one RED" 1 "$(reds)"
check "names the silent socket" 1 "$(logcount 'received nothing')"

echo "=== READY and chatty: no false silent-socket alert ==="
fresh; invoke "" "$(status_json '.lastPacketAgoMs=40000')"
check "NO alert" 0 "$(reds)"

echo "=== logged in but not in the monitored guild (settled) ==="
fresh; invoke "" "$(status_json ".readySince=$(( $(date +%s%3N) - 600000 ))
  | .monitoredGuilds=[{\"id\":\"111111111111111111\",\"present\":false}]")"
check "one RED" 1 "$(reds)"
check "names the missing guild" 1 "$(logcount 'not a member of monitored guild')"

echo "=== guild list still filling in: not yet an alert ==="
fresh; invoke "" "$(status_json ".readySince=$(( $(date +%s%3N) - 5000 ))
  | .monitoredGuilds=[{\"id\":\"111111111111111111\",\"present\":false}]")"
check "NO alert" 0 "$(reds)"

echo "=== gateway report unreadable (backend down / restarting) ==="
# THE rule this rewrite is built around: blind is not broken. The backend being
# unreachable is already covered by check_http, which reports the real fault;
# guessing at the gateway on top of that is how one restart became two alerts.
fresh; invoke "" "$(status_json)" 0 "http://127.0.0.1:1/status"
check "NO alert" 0 "$(reds)"
check "logged SKIP, claimed nothing" 1 "$(logcount 'gateway unobservable')"

echo "=== gateway report returns non-200 ==="
fresh; printf '500' >"$WORK/status.code"; invoke "" "$(status_json)"
check "NO alert" 0 "$(reds)"

echo "=== gateway report is not JSON ==="
fresh; invoke "" 'this is not json'
check "NO alert" 0 "$(reds)"

echo "=== worker stuck: queue backlog ==="
fresh; invoke "" "$(status_json)" 5
check "one RED" 1 "$(reds)"
check "blames the queue, not journal volume" 1 "$(logcount 'not draining the queue')"

echo "=== backlog predicate mirrors claim_messages() ==="
# The 33-message false alarm was a PREDICATE bug: soft-deleted rows are never
# claimable, so counting them reports a stuck worker that does not exist.
fresh; invoke "" "$(status_json)" 0
check "excludes soft-deleted rows" 1 "$(count_in 'deleted_at IS NULL' "$WORK/psql-sql")"
check "excludes rows still in backoff" 1 "$(count_in 'ready_for_work_at' "$WORK/psql-sql")"

echo "=== quiet guild, empty queue (the old overnight false RED) ==="
fresh; invoke "" "$(status_json)" 0
check "NO alert" 0 "$(reds)"

echo "=== dedup + recovery ==="
fresh
for _ in 1 2 3; do
  invoke "" "$(status_json '.connected=false | .everReady=false | .uptimeMs=900000 | .state="idle"')"
done
check "three degraded runs post ONE alert" 1 "$(reds)"
invoke "" "$(status_json)"
check "recovery posts one GREEN" 1 "$(greens)"
check "recovery says how long it was down" 1 "$(count_in 'Degraded for' "$CAPTURE")"
if [[ "${SHOW_MESSAGES:-0}" == "1" ]]; then
  echo
  echo "--- RECOVERY, as posted ---"
  jq -r '.content' "$CAPTURE"
  echo "--- end ---"
fi

echo "=== message renders as a bullet list, not a wall of code fences ==="
# The old format wrapped each problem in its own triple-backtick block, which on
# a phone was a column of grey slabs. Assert the shape, not just the text.
fresh; invoke "" "$(status_json '.connected=false | .everReady=false | .uptimeMs=900000
  | .state="idle"')" 7
check "bullets, one per problem" 2 "$(grep -o '• ' "$CAPTURE" | wc -l | tr -d ' ')"
check "no code fences" 0 "$(count_in '```' "$CAPTURE")"
check "headline is bold" 1 "$(count_in '**🔴 GMW DEGRADED' "$CAPTURE")"
# SHOW_MESSAGES=1 dumps the exact posted payloads, so the rendered Discord
# message can be eyeballed without sending anything to a real webhook.
if [[ "${SHOW_MESSAGES:-0}" == "1" ]]; then
  echo
  echo "--- DEGRADED alert, as posted ---"
  jq -r '.content' "$CAPTURE"
  echo "--- end ---"
fi

echo "=== a long error message is chunked, not dropped ==="
# Discord rejects >2000 chars with a 400 and the alert vanishes. Two messages
# beat a silently lost one.
fresh; invoke "" "$(status_json ".connected=false | .everReady=false | .uptimeMs=900000
  | .loginError=\"$(printf 'x%.0s' $(seq 1 2500))\"")"
check "split into multiple messages" 1 "$(count_in 'continued' "$CAPTURE")"

echo "=== state file survives a pre-upgrade single-line format ==="
# An open alert written by the old version must still close, not re-fire.
fresh; invoke "" "$(status_json '.connected=false | .everReady=false | .uptimeMs=900000 | .state="idle"')"
printf '%s' "$(head -1 "$WORK/state/state")" >"$WORK/state/state"
: >"$CAPTURE"
invoke "" "$(status_json)"
check "old-format state still recovers" 1 "$(greens)"
check "no duplicate RED" 0 "$(reds)"

# SHOW_MESSAGES=1 prints the exact payloads that were posted, so the rendered
# Discord message can be eyeballed without sending anything to a real webhook.
if [[ "${SHOW_MESSAGES:-0}" == "1" ]]; then
  echo
  echo "=== a DEGRADED alert, as posted ==="
  grep '🔴' "$CAPTURE" | tail -1
  echo
  echo "=== the RECOVERY message, as posted ==="
  grep '🟢' "$CAPTURE" | tail -1
fi

echo
printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
