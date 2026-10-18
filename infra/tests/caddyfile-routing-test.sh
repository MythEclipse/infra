#!/usr/bin/env bash
# Offline regression tests for the production Caddyfile's routing.
#
# No network, no SSH, no credentials: this reads the Caddyfile as text and
# asserts the routes that have each broken a deployment. It runs in CI BEFORE
# anything is copied to a host.
#
#   bash infra/tests/caddyfile-routing-test.sh
#
# Exit 0 = all cases pass.
set -uo pipefail

CADDYFILE="${CADDYFILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/caddy/Caddyfile.prod}"
[[ -f "$CADDYFILE" ]] || { echo "cannot find Caddyfile at $CADDYFILE" >&2; exit 2; }

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

# Extract one site block, from its opening line to the first line that is just
# "}" — which is how this file closes every block. A block is a site address
# followed by " {", so an anchored pattern keeps `dashboard.asepharyana.my.id`
# out of the `wiki.` results.
block() {
	awk -v host="$1" '
		index($0, host " {") == 1 { inside = 1 }
		inside { print }
		inside && $0 == "}" { exit }
	' "$CADDYFILE"
}

# --- every block we care about must be found, or the cases below pass empty ---
for host in 'wiki.asepharyana.my.id' 'mcpedia.asepharyana.my.id'; do
	if [[ -n "$(block "$host")" ]]; then
		ok "found the $host block"
	else
		no "could not extract the $host block — the cases below would pass for the wrong reason"
	fi
done

# --- /dashboard must NOT be proxied to the API ---
#
# It was, and the page it reached was a self-contained HTML dashboard naming the
# product, the protocol and BullMQ on a site that presents itself as a plain
# wiki. The page lived in apps/api/src — invisible to every guard over
# apps/web/src — and its inline script did not even parse, so it looked live and
# rendered nothing.
#
# The SPA owns /dashboard now, and it is reached by falling through to
# `import proxy 4016`. Re-adding a handle here silently shadows the SPA again,
# and the failure is a 200 with the wrong page: no error, no log line.
for host in 'wiki.asepharyana.my.id' 'mcpedia.asepharyana.my.id'; do
	if block "$host" | grep -qE '^[[:space:]]*handle[[:space:]]+/dashboard'; then
		no "$host still proxies /dashboard — the SPA's own /dashboard route is shadowed by the API"
	else
		ok "$host does not proxy /dashboard (the SPA serves it)"
	fi
done

# --- both sites still need the routes that ARE the API ---
#
# The inverse assertion. Removing /dashboard must not take the API surface with
# it: /trpc/* carries every read the SPA makes, /api/auth/* is better-auth, and
# /hooks/* is the git-sync webhook. Each of these has been missing at least once,
# and /api/auth/* failed as a 200 (the SPA catch-all answered with index.html and
# a correct password read as "wrong password").
for route in '/metrics' '/trpc/' '/hooks/' '/health' '/api/auth/'; do
	for host in 'wiki.asepharyana.my.id' 'mcpedia.asepharyana.my.id'; do
		if block "$host" | grep -qE "^[[:space:]]*handle[[:space:]]+${route}"; then
			ok "$host handles $route"
		else
			no "$host lost its $route handle — that route now falls through to the SPA"
		fi
	done
done

# --- the SPA origin is what the fall-through reaches ---
for host in 'wiki.asepharyana.my.id' 'mcpedia.asepharyana.my.id'; do
	if block "$host" | grep -qE '^[[:space:]]*import[[:space:]]+proxy[[:space:]]+4016'; then
		ok "$host falls through to the SPA on :4016"
	else
		no "$host does not import proxy 4016 — nothing serves the wiki frontend"
	fi
done

# --- the API must still be reachable for a write, i.e. :4020 is proxied ---
if block 'wiki.asepharyana.my.id' | grep -qE 'reverse_proxy[[:space:]]+127\.0\.0\.1:4020'; then
	ok "the wiki block proxies the API on :4020"
else
	no "the wiki block never proxies :4020 — every API route is unreachable"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
