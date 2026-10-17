#!/usr/bin/env bash
# Offline regression tests for gmw-watchdog.sh.
#
# No network, no Bitwarden, no Discord, no real credentials: every external
# command is a stub, so this runs anywhere (including CI) and cannot touch
# production. It exists because the failure it guards against was invisible —
# Bitwarden's 429 was reported as "the Discord token is dead", a confident and
# completely wrong outage alert.
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

# --- one local server: captures POSTs (alert sink), answers GET 200 (health) -
# A real class, not a lambda: BaseHTTPRequestHandler cannot be built from
# lambdas, and a server that silently fails to start makes every "expect no
# alert" case pass for the wrong reason. It prints its port on stdout.
cat >"$WORK/server.py" <<'PY'
import http.server, sys
capture = sys.argv[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        with open(capture, 'a') as f:
            f.write(self.rfile.read(n).decode('utf-8', 'replace') + "\n")
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        body = b'{"status":"healthy"}'
        self.send_response(200)
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
# The port travels over a FIFO so this blocks until the server is genuinely
# listening. A spin loop would race the interpreter's startup instead.
mkfifo "$WORK/port.fifo"
python3 "$WORK/server.py" "$CAPTURE" >"$WORK/port.fifo" &
SERVER_PID=$!
read -r PORT <"$WORK/port.fifo"
if [[ -z "${PORT:-}" ]]; then echo "test harness: local server failed to start" >&2; exit 2; fi
HEALTH_URL="http://127.0.0.1:$PORT/health"

# --- stub bws: synthetic secrets, optional 429 on chosen call numbers -------
cat >"$WORK/bin/bws" <<BSTUB
#!/usr/bin/env bash
n=\$(( \$(cat "$WORK/bws-calls" 2>/dev/null || echo 0) + 1 ))
echo "\$n" >"$WORK/bws-calls"
for f in \${BWS_STUB_FAIL_ON//,/ }; do
  [[ -n "\$f" && "\$f" == "\$n" ]] && { echo "[429 Too Many Requests]" >&2; exit 1; }
done
cat <<JSON
[{"key":"pr_agent_discord_webhook_url","value":"http://127.0.0.1:$PORT/hook"},
 {"key":"gmw_discord_token","value":"UNIT-TEST-TOKEN"},
 {"key":"gmw_monitor_guild_id","value":"111111111111111111"}]
JSON
BSTUB
chmod +x "$WORK/bin/bws"

# --- stub curl: loopback only; real Discord webhook posts are refused -------
cat >"$WORK/bin/curl" <<'CSTUB'
#!/usr/bin/env bash
url=""
for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
case "$url" in
  *discord.com/api/webhooks*) echo "stub: BLOCKED real webhook" >&2; exit 7 ;;
  http://127.0.0.1*|http://localhost*|"") ;;
  *discord.com/api/v10/users/@me*)
    tok=""
    for a in "$@"; do case "$a" in "Authorization: "*) tok="${a#Authorization: }" ;; esac; done
    if [[ "$tok" == "UNIT-TEST-TOKEN" ]]; then
      printf '%s\n200' '{"id":"42","username":"unit-test"}'
    else
      printf '%s\n401' '{"message":"401: Unauthorized"}'
    fi
    exit 0 ;;
  *discord.com/api/v10/guilds/*) printf '200'; exit 0 ;;
  *) echo "stub: BLOCKED $url" >&2; exit 7 ;;
esac
exec /usr/bin/curl "$@"
CSTUB
chmod +x "$WORK/bin/curl"

# --- stub psql: reports whatever backlog the case asks for ------------------
printf '#!/usr/bin/env bash\necho "${PSQL_BACKLOG:-0}"\n' >"$WORK/bin/psql"
chmod +x "$WORK/bin/psql"

# --- stub systemctl: the unit is "active", and no crash loop ----------------
printf '#!/usr/bin/env bash\ncase "$*" in *is-active*) echo active ;; *NRestarts*) echo 0 ;; esac\n' >"$WORK/bin/systemctl"
chmod +x "$WORK/bin/systemctl"

# --- stub journalctl: no boots, so the crash-loop check stays quiet ---------
printf '#!/usr/bin/env bash\necho 0\n' >"$WORK/bin/journalctl"
chmod +x "$WORK/bin/journalctl"

export PATH="$WORK/bin:$PATH"

invoke() { # invoke <fail_on> <token> [backlog]
  BWS_STUB_FAIL_ON="$1" DISCORD_TOKEN="$2" MONITOR_GUILD_ID="111111111111111111" \
    DATABASE_URL="postgres://stub/stub" PSQL_BACKLOG="${3:-0}" \
    STATE_DIR="$WORK/state" LOG="$WORK/log" BWS="$WORK/bin/bws" \
    HEALTH_URL="$HEALTH_URL" UNIT="gmw-backend" \
    bash "$SCRIPT" >/dev/null 2>&1
}
fresh() { : >"$CAPTURE"; echo 0 >"$WORK/bws-calls"; rm -f "$WORK/state/state" "$WORK/log"; }
reds() { grep -c '🔴' "$CAPTURE" 2>/dev/null || true; }
greens() { grep -c '🟢' "$CAPTURE" 2>/dev/null || true; }
calls() { cat "$WORK/bws-calls" 2>/dev/null || echo 0; }
logcount() { grep -c "$1" "$WORK/log" 2>/dev/null || echo 0; }

PASS=0 FAIL=0
check() {
  if [[ "$2" == "$3" ]]; then printf '  ok    %-50s %s\n' "$1" "$3"; PASS=$((PASS + 1))
  else printf '  FAIL  %-50s want=%s got=%s\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}

# Sanity: the sink must actually be reachable, or every "no alert" case below
# would pass for the wrong reason.
if ! curl -s -o /dev/null -m 2 -X POST "http://127.0.0.1:$PORT/sink-check"; then
  echo "test harness: alert sink unreachable" >&2; exit 2
fi
: >"$CAPTURE"

echo "gmw-watchdog offline tests"
echo "=== healthy system ==="
fresh; invoke "" "UNIT-TEST-TOKEN"
check "no alert" 0 "$(reds)"
check "Bitwarden called once per run" 1 "$(calls)"

echo "=== Bitwarden rate-limits the run (the reported spam trigger) ==="
fresh; invoke "1,2,3,4,5,6" "UNIT-TEST-TOKEN"
check "NO false alert" 0 "$(reds)"
check "logged SKIP and claimed nothing" 1 "$(logcount 'SKIP')"

echo "=== token genuinely revoked ==="
fresh; invoke "" "DEAD-TOKEN"
check "exactly one RED" 1 "$(reds)"
check "names the token as the fault" 1 "$(logcount 'token REJECTED')"

echo "=== worker stuck: queue backlog ==="
fresh; invoke "" "UNIT-TEST-TOKEN" 5
check "one RED" 1 "$(reds)"
check "blames the queue, not journal volume" 1 "$(logcount 'not draining the queue')"

echo "=== quiet guild, empty queue (the old overnight false RED) ==="
fresh; invoke "" "UNIT-TEST-TOKEN" 0
check "NO alert" 0 "$(reds)"

echo "=== dedup + recovery ==="
fresh
for _ in 1 2 3; do invoke "" "DEAD-TOKEN"; done
check "three degraded runs post ONE alert" 1 "$(reds)"
invoke "" "UNIT-TEST-TOKEN"
check "recovery posts one GREEN" 1 "$(greens)"

echo
printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
