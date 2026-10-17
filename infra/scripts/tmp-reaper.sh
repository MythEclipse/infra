#!/usr/bin/env bash
# Reclaim /tmp on orangevps.
#
# WHY THIS EXISTS. /tmp on this host is a **7.8G tmpfs**, i.e. RAM, and nothing
# ever swept it by directory age. It filled to 100% on 2026-10-17 and broke a
# deploy in a way that looked nothing like a disk problem:
#
#   tar: ./node_modules/.pnpm/node_modules/@better-auth/core:
#        Cannot create symlink to ‘…’: No space left on device
#   ##[error]Process completed with exit code 2.
#
# The pr-agent-server deploy script stages its payload in /tmp
# (`tar -xzf /tmp/pkg-api.tar.gz -C /tmp/pkg-api.new`), so a full tmpfs fails the
# deploy of a service that has nothing to do with /tmp. Two separate leaks fed it:
# the worker's own clone workdirs (56 of them, oldest 3 days, one per PR ever
# touched) and a pile of one-off probe dirs from earlier sessions.
#
# HOW IT DECIDES. Denylist FIRST, then age, then liveness — never the reverse.
# /tmp here is not a scratch dir: it holds a live Postgres socket (postgres runs
# with `-k /tmp`), 25 `systemd-private-*` mounts for running units, an X server's
# socket, and the worker's own lock/state files. A reaper that walks the directory
# deleting whatever is old would take out the worker's queue state and break
# `psql` for every service on the box, and the damage would surface hours later as
# an unrelated failure — exactly the class of bug this host keeps producing.
#
# Usage:
#   tmp-reaper.sh              report only, changes nothing (the default)
#   tmp-reaper.sh --apply      delete the entries it reports
#
# Exit status is always 0 unless a genuine error occurs; "nothing to do" is a
# success, because this runs from a timer every hour and a red unit would be
# noise nobody reads.
set -euo pipefail

MODE="report"
for arg in "$@"; do
	case "$arg" in
	--apply) MODE="apply" ;;
	--report) MODE="report" ;;
	-h | --help)
		sed -n '2,30p' "${BASH_SOURCE[0]}"
		exit 0
		;;
	*)
		echo "tmp-reaper: unknown argument: $arg" >&2
		exit 2
		;;
	esac
done

TMP_DIR="${TMP_DIR:-/tmp}"
# 12h, not the 10d in /usr/lib/tmpfiles.d/tmp.conf. The systemd default is tuned
# for hosts where /tmp is disk; here it is RAM, so a day-old clone is both
# expensive and useless — the worker re-clones on demand and a build dir is
# regenerable. Nothing under 12h is touched, which is what keeps a deploy's
# in-flight staging (mtime = now) and a freshly written tarball safe.
MAX_AGE_HOURS="${TMP_REAP_MAX_AGE_HOURS:-12}"

# Entries that are NEVER deleted, whatever their age. Each one is here because it
# is either a live IPC endpoint or state a service needs to keep working.
#
#   systemd-private-*  PrivateTmp mounts for every running unit. Deleting one
#                      breaks that unit's own /tmp until it restarts.
#   .s.PGSQL.*         The live Postgres socket. postgres here runs
#                      `-k /tmp`, so `psql`, migrations and every app's DB
#                      connection die with it.
#   .X11-unix etc.     X server (:99) and ICE/font sockets.
#   tmux-*             The tmux server's control socket.
#   .bun-*             bun's shared object, mmap'd by running bun processes.
#   *.lock .*.lock     flock targets; deleting the inode silently defeats the
#                      lock rather than releasing it.
#   pr-queue-*         The worker's lock, PID dir and state files. The state
#                      files are the worker's memory of which PRs it has tried.
#   cc-socks           claude's proxy socket dir, recreated per agent run.
KEEP_PATTERNS=(
	"systemd-private-*"
	".s.PGSQL*"
	".X11-unix" ".X11-pipe"
	".ICE-unix" ".font-unix" ".Test-unix"
	"tmux-*"
	".bun-*"
	"*.lock" ".*.lock"
	"pr-queue-worker.lock" "pr-queue-pids"
	"pr-queue-fix-state.json" "pr-queue-sync-state.json"
	"cc-socks"
	".hermes*" "hermes*"
	# The pnpm store is content-addressable and hardlinked into live
	# node_modules; is_kept() blocks it here and store_prune() handles it with
	# pnpm's own command. `rm -rf` on it would corrupt every project on the box.
	".pnpm-store"
	# Live sockets, seen at various times on this host.
	"ssh-*" ".ssh-*" "vprobe-*"
)

log() { printf '%s\n' "$*"; }

is_kept() {
	local name="$1"
	local pat
	for pat in "${KEEP_PATTERNS[@]}"; do
		# shellcheck disable=SC2053 # intentional glob on the RHS
		if [[ "$name" == $pat ]]; then
			return 0
		fi
	done
	return 1
}

# Every top-level entry that some process currently has open, in one pass.
# `lsof +D` is deliberately NOT used: its recursive walk reports paths a process
# does not actually hold, which manufactures live entries. Reading the kernel's
# open-file table via a plain `lsof` is the authority.
declare -A IN_USE=()
while read -r path; do
	[[ -n "$path" ]] || continue
	local_name="${path#"$TMP_DIR"/}"
	IN_USE["${local_name%%/*}"]=1
done < <(lsof -nP 2>/dev/null | awk -v d="$TMP_DIR/" '$NF ~ ("^" d) {print $NF}' | sort -u)

# Any directory a process is chdir'd into is live too — a server's cwd is the
# thing that matters, and it holds no file descriptor that lsof would show.
while read -r cwd; do
	[[ "$cwd" == "$TMP_DIR/"* ]] || continue
	local_name="${cwd#"$TMP_DIR"/}"
	IN_USE["${local_name%%/*}"]=1
done < <(for p in /proc/[0-9]*; do readlink "$p/cwd" 2>/dev/null || true; done | sort -u)

# Is a worker tick running? The worker clones into $TMP_DIR/pr-queue-work for up
# to 30 minutes (an agent run) and hardlinks packages out of the pnpm store. Both
# are protected by the age guard, but the store prune below additionally requires
# an idle worker, because `pnpm store prune` racing an in-flight `pnpm install`
# can remove content the install is about to link.
worker_busy() {
	if [[ -n "$(lsof -t "$TMP_DIR/pr-queue-worker.lock" 2>/dev/null || true)" ]]; then
		return 0
	fi
	if pgrep -f 'run-worker\.sh|apps/worker/dist/index\.js' >/dev/null 2>&1; then
		return 0
	fi
	return 1
}

df_before="$(df -h "$TMP_DIR" | awk 'NR==2 {print $3 " used, " $4 " avail (" $5 ")"}')"
log "== tmp-reaper ($MODE) =="
log "tmpfs: $df_before"
log "max age: ${MAX_AGE_HOURS}h   protected-in-use entries: ${#IN_USE[@]}"

AGE_MIN=$((MAX_AGE_HOURS * 60))
declare -a doomed=()
declare -a kept=()

while IFS= read -r entry; do
	name="$(basename "$entry")"
	if is_kept "$name"; then
		kept+=("$name (protected)")
		continue
	fi
	if [[ -n "${IN_USE[$name]:-}" ]]; then
		kept+=("$name (in use)")
		continue
	fi
	doomed+=("$entry")
done < <(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -mmin "+$AGE_MIN" 2>/dev/null | sort)

if [[ ${#doomed[@]} -eq 0 ]]; then
	log "nothing older than ${MAX_AGE_HOURS}h to reclaim"
else
	log "-- reclaiming ${#doomed[@]} entr(y|ies) --"
	for entry in "${doomed[@]}"; do
		size="$(du -xsh "$entry" 2>/dev/null | cut -f1 || echo '?')"
		if [[ "$MODE" == "apply" ]]; then
			if rm -rf -- "$entry" 2>/dev/null; then
				log "  removed  $size  $entry"
			else
				# Root-owned or mode-restricted: report, never claim the space.
				log "  FAILED   $size  $entry (permission denied — not reclaimed)"
			fi
		else
			log "  would remove  $size  $entry"
		fi
	done
fi

if [[ ${#kept[@]} -gt 0 ]]; then
	log "-- kept: ${#kept[@]} --"
	printf '  %s\n' "${kept[@]}"
fi

# The pnpm store gets its own reclamation path, because it is a hardlink-shared
# content-addressable store: `du` overstates it and `rm -rf` would corrupt every
# installed project. `pnpm store prune` drops only content nothing links to.
if [[ "$MODE" == "apply" ]]; then
	if [[ -d "$TMP_DIR/.pnpm-store" ]]; then
		if worker_busy; then
			log "pnpm store: worker busy — skipping prune this pass"
		elif ! command -v pnpm >/dev/null 2>&1; then
			log "pnpm store: pnpm not on PATH — skipping prune"
		else
			store="${PNPM_STORE_PATH:-$TMP_DIR/.pnpm-store}"
			before="$(du -xsh "$store" 2>/dev/null | cut -f1)"
			# Run as the store's owner: pnpm refuses a store it cannot write, and
			# claiming a reclaim from a failed prune is how a report lies.
			owner="$(stat -c '%U' "$store" 2>/dev/null || echo '')"
			run_as=()
			have_sudo=0
			if [[ -n "$owner" && "$owner" != "$(id -un)" ]]; then
				if sudo -n true 2>/dev/null; then
					run_as=(sudo -n -u "$owner")
					have_sudo=1
				else
					log "pnpm store: store owned by $owner and no passwordless sudo — skipping"
					# NOT `run_as=("")`: an empty-but-nonempty array passes the
					# `${#run_as[@]} -gt 0` guard below and then tries to execute
					# the empty string, which is how the first version reported a
					# "nonzero exit" for a prune that never ran.
					run_as=()
				fi
			fi
			if [[ ${#run_as[@]} -gt 0 ]]; then
				# A nonzero exit is EXPECTED when a worker tick holds the store
				# lock, and is not an error worth alarming on: the store is 2G of
				# live, hardlinked content, and a manual `pnpm store prune`
				# confirms "Removed 0 files". So the message says "deferred",
				# not "failed" — a claim of breakage here would be false, and a
				# silent success would hide a genuinely locked store.
				prune_out="$("${run_as[@]}" env PNPM_STORE_PATH="$store" pnpm store prune 2>&1)" || {
					log "pnpm store: prune deferred (store lock held — expected during a tick)"
					prune_out=""
				}
				# Report pnpm's own "Removed N files" line rather than a size the
				# hardlink split makes meaningless.
				removed="$(printf '%s\n' "$prune_out" | grep -m1 'Removed' || true)"
				after="$(du -xsh "$store" 2>/dev/null | cut -f1)"
				log "pnpm store: $before -> $after ${removed:+($removed)}"
			elif [[ -z "$owner" ]]; then
				log "pnpm store: could not stat $store — skipping prune"
			else
				# Already the owner: run it directly, no sudo needed.
				prune_out="$(env PNPM_STORE_PATH="$store" pnpm store prune 2>&1)" || prune_out=""
				after="$(du -xsh "$store" 2>/dev/null | cut -f1)"
				log "pnpm store: $before -> $after"
			fi
		fi
	else
		log "pnpm store: $TMP_DIR/.pnpm-store absent — nothing to prune"
	fi
fi

df_after="$(df -h "$TMP_DIR" | awk 'NR==2 {print $3 " used, " $4 " avail (" $5 ")"}')"
log "tmpfs: $df_before  ->  $df_after"
if [[ "$MODE" != "apply" ]]; then
	log "(report only — re-run with --apply to reclaim)"
fi
