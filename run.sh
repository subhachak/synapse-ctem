#!/usr/bin/env bash
# Start/stop the Mphasis Synapse CTEM demo (FastAPI backend + Next.js frontend) together.
#
# Usage:
#   ./run.sh start   # start both servers in the background, open Chrome
#   ./run.sh stop    # stop both servers
#   ./run.sh restart
#   ./run.sh status

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
RUN_DIR="$ROOT_DIR/.run"
BACKEND_PID_FILE="$RUN_DIR/backend.pid"
FRONTEND_PID_FILE="$RUN_DIR/frontend.pid"
BACKEND_LOG="$RUN_DIR/backend.log"
FRONTEND_LOG="$RUN_DIR/frontend.log"
BACKEND_ENV="$BACKEND_DIR/.env"
BACKEND_PORT=8000
FRONTEND_PORT=3000
DEMO_URL="http://localhost:${FRONTEND_PORT}"
# Default target repo name used by `setup` when backend/.env doesn't already pin one.
TARGET_REPO_NAME="ctem-node-payments-api"
TARGET_SNAPSHOT="$BACKEND_DIR/app/remediation_targets/node-payments-api"
# Same, for the log4j (Maven, GitHub-Actions-verified) scenario -- a separate
# repo/env var so the two live targets never clobber each other (see
# github_pr.resolve_repo).
TARGET_REPO_NAME_LOG4J="ctem-log4j-demo"
TARGET_SNAPSHOT_LOG4J="$BACKEND_DIR/app/remediation_targets/log4j-vulnerable-app"

mkdir -p "$RUN_DIR"

# Read a single key's value from backend/.env (empty if absent). Used for the
# GitHub token + target repo so the demo lifecycle is driven by the same file
# the backend reads at startup.
env_val() {
  [[ -f "$BACKEND_ENV" ]] || return 0
  grep -E "^$1=" "$BACKEND_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true
}

is_running() {
  local pid_file="$1"
  [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

wait_for_http() {
  local url="$1" tries=60
  while (( tries > 0 )); do
    if curl -sf -o /dev/null "$url"; then
      return 0
    fi
    sleep 1
    (( tries-- ))
  done
  return 1
}

free_port() {
  local port="$1"
  local pids
  pids="$(lsof -ti "tcp:${port}" 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    echo "Port ${port} is already in use (pid(s) ${pids//$'\n'/, }) — stopping it to take over."
    kill $pids 2>/dev/null || true
    sleep 1
    pids="$(lsof -ti "tcp:${port}" 2>/dev/null || true)"
    [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null || true
  fi
}

start() {
  if is_running "$BACKEND_PID_FILE" || is_running "$FRONTEND_PID_FILE"; then
    echo "CTEM demo already running (use ./run.sh restart to restart it)."
    exit 0
  fi

  free_port "$BACKEND_PORT"
  free_port "$FRONTEND_PORT"

  echo "Starting backend on :${BACKEND_PORT}..."
  (
    cd "$BACKEND_DIR"
    source venv/bin/activate
    exec uvicorn app.main:app --port "$BACKEND_PORT"
  ) > "$BACKEND_LOG" 2>&1 &
  echo $! > "$BACKEND_PID_FILE"

  if ! wait_for_http "http://localhost:${BACKEND_PORT}/api/health"; then
    echo "Backend failed to start — see $BACKEND_LOG"
    stop
    exit 1
  fi
  echo "Backend is up."

  echo "Starting frontend on :${FRONTEND_PORT}..."
  (
    cd "$FRONTEND_DIR"
    exec npm run dev -- --port "$FRONTEND_PORT"
  ) > "$FRONTEND_LOG" 2>&1 &
  echo $! > "$FRONTEND_PID_FILE"

  if ! wait_for_http "$DEMO_URL"; then
    echo "Frontend failed to start — see $FRONTEND_LOG"
    stop
    exit 1
  fi
  echo "Frontend is up."

  echo "Opening $DEMO_URL in Chrome..."
  open -a "Google Chrome" "$DEMO_URL"

  echo "CTEM demo is running. Use ./run.sh stop to shut it down."
}

kill_tree() {
  local pid="$1"
  local child
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    kill_tree "$child"
  done
  kill "$pid" 2>/dev/null || true
}

stop_pid_tree() {
  local pid_file="$1" name="$2"
  if is_running "$pid_file"; then
    local pid
    pid="$(cat "$pid_file")"
    echo "Stopping $name (pid $pid)..."
    kill_tree "$pid"
  fi
  rm -f "$pid_file"
}

stop() {
  stop_pid_tree "$FRONTEND_PID_FILE" "frontend"
  stop_pid_tree "$BACKEND_PID_FILE" "backend"
  echo "CTEM demo stopped."
}

status() {
  if is_running "$BACKEND_PID_FILE"; then
    echo "backend:  running (pid $(cat "$BACKEND_PID_FILE"))"
  else
    echo "backend:  stopped"
  fi
  if is_running "$FRONTEND_PID_FILE"; then
    echo "frontend: running (pid $(cat "$FRONTEND_PID_FILE"))"
  else
    echo "frontend: stopped"
  fi
}

# Inject the live code-remediation scenario (a real scan->fix->test->PR->closure
# against the node-payments-api target) and open its review page in Chrome, the
# same way `start` opens the dashboard.
inject_code() {
  local variant="${1:-live}" payload_file
  case "$variant" in
    live)    payload_file="$ROOT_DIR/demo-data/code-remediation.json" ;;          # SCA: deterministic dependency bump
    agentic) payload_file="$ROOT_DIR/demo-data/code-remediation-agentic.json" ;;  # SAST: AI coding agent fixes a code vuln
    dast)    payload_file="$ROOT_DIR/demo-data/code-remediation-dast.json" ;;      # DAST: AI agent fixes a reflected XSS found by a live HTTP probe
    blocked) payload_file="$ROOT_DIR/demo-data/code-remediation-blocked.json" ;;  # safe-failure (blocked)
    log4j)   payload_file="$ROOT_DIR/demo-data/code-remediation-log4j.json" ;;    # SCA (Maven): Log4Shell, GitHub-Actions-verified
    *) echo "Usage: $0 inject-code [live|agentic|dast|blocked|log4j]"; exit 2 ;;
  esac

  if ! is_running "$BACKEND_PID_FILE"; then
    echo "Backend isn't running — start it first with ./run.sh start"
    exit 1
  fi

  echo "Injecting code-remediation scenario ($variant)..."
  local response run_id
  if ! response="$(curl -sf -X POST "http://localhost:${BACKEND_PORT}/api/_control/incidents" \
        -H 'Content-Type: application/json' --data-binary @"$payload_file")"; then
    echo "Injection failed — is the backend healthy? (see $BACKEND_LOG)"
    exit 1
  fi
  run_id="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')"

  echo "Run: $run_id"
  echo "Opening ${DEMO_URL}/review/${run_id} in Chrome..."
  open -a "Google Chrome" "${DEMO_URL}/review/${run_id}"
}

# One-time (idempotent) provisioning of the GitHub target repo for the live
# code-remediation demo: create it if missing, push the vulnerable baseline to
# `main`, and pin CTEM_REMEDIATION_REPO in backend/.env. Reads GITHUB_TOKEN from
# backend/.env.
setup() {
  local tok repo login name
  tok="$(env_val GITHUB_TOKEN)"
  if [[ -z "$tok" ]]; then
    echo "No GITHUB_TOKEN in $BACKEND_ENV — add a PAT with 'repo' scope, then re-run ./run.sh setup." >&2
    exit 1
  fi
  login="$(curl -sf -H "Authorization: Bearer $tok" https://api.github.com/user \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["login"])')" \
    || { echo "GitHub token was rejected (check it isn't expired/revoked)." >&2; exit 1; }
  echo "Authenticated as $login."

  repo="$(env_val CTEM_REMEDIATION_REPO)"
  [[ -z "$repo" ]] && repo="$login/$TARGET_REPO_NAME"
  name="${repo#*/}"

  echo "Ensuring GitHub target repo $repo exists (private)..."
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $tok" -H "Accept: application/vnd.github+json" \
    https://api.github.com/user/repos \
    -d "{\"name\":\"$name\",\"private\":true,\"description\":\"Mphasis Synapse CTEM demo target — intentionally vulnerable (lodash 4.17.4). Do not deploy.\"}")
  case "$code" in
    201) echo "  created $repo" ;;
    422) echo "  $repo already exists — reusing" ;;
    *)   echo "  repo create returned HTTP $code (continuing)" ;;
  esac

  echo "Seeding $repo@main with the vulnerable baseline..."
  push_npm_snapshot "$tok" "$repo" || { echo "  seed push failed." >&2; exit 1; }
  echo "  seeded $repo@main."

  if ! grep -q '^CTEM_REMEDIATION_REPO=' "$BACKEND_ENV" 2>/dev/null; then
    echo "CTEM_REMEDIATION_REPO=$repo" >> "$BACKEND_ENV"
    echo "  wrote CTEM_REMEDIATION_REPO=$repo to backend/.env"
  fi
  echo "Setup complete. Run ./run.sh restart to load it, then ./run.sh inject-code live."
}

# Same idempotent provisioning, for the log4j (Maven, GitHub-Actions-verified)
# scenario: separate repo, separate env var (CTEM_LOG4J_REMEDIATION_REPO) so
# it never collides with the npm target above. The pushed baseline already
# includes .github/workflows/ctem-verify.yml -- that's the real build/test/
# JNDI-probe machine (this demo host has no local JDK/Maven), and it works
# as soon as it lands on the repo's default branch, no extra step needed.
setup_log4j() {
  local tok repo login name
  tok="$(env_val GITHUB_TOKEN)"
  if [[ -z "$tok" ]]; then
    echo "No GITHUB_TOKEN in $BACKEND_ENV — add a PAT with 'repo' + 'workflow' scope, then re-run ./run.sh setup-log4j." >&2
    exit 1
  fi
  login="$(curl -sf -H "Authorization: Bearer $tok" https://api.github.com/user \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["login"])')" \
    || { echo "GitHub token was rejected (check it isn't expired/revoked)." >&2; exit 1; }
  echo "Authenticated as $login."

  repo="$(env_val CTEM_LOG4J_REMEDIATION_REPO)"
  [[ -z "$repo" ]] && repo="$login/$TARGET_REPO_NAME_LOG4J"
  name="${repo#*/}"

  echo "Ensuring GitHub target repo $repo exists (private)..."
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $tok" -H "Accept: application/vnd.github+json" \
    https://api.github.com/user/repos \
    -d "{\"name\":\"$name\",\"private\":true,\"description\":\"Mphasis Synapse CTEM demo target — intentionally vulnerable to Log4Shell (CVE-2021-44228, log4j-core 2.14.1). Do not deploy.\"}")
  case "$code" in
    201) echo "  created $repo" ;;
    422) echo "  $repo already exists — reusing" ;;
    *)   echo "  repo create returned HTTP $code (continuing)" ;;
  esac

  echo "Seeding $repo@main with the vulnerable baseline (log4j-core 2.14.1)..."
  local tmp; tmp="$(mktemp -d)"
  cp -R "$TARGET_SNAPSHOT_LOG4J/." "$tmp/"
  (
    cd "$tmp" && rm -rf target .git
    git init -b main -q
    git -c user.email=ctem-agent@mphasis.demo -c user.name="CTEM Implementation Agent" add -A
    git -c user.email=ctem-agent@mphasis.demo -c user.name="CTEM Implementation Agent" commit -qm "vulnerable baseline (log4j-core 2.14.1, CVE-2021-44228)"
    git remote add origin "https://x-access-token:${tok}@github.com/${repo}.git"
    git push -u origin main --force -q
  ) || { rm -rf "$tmp"; echo "  seed push failed." >&2; exit 1; }
  rm -rf "$tmp"
  echo "  seeded $repo@main (ctem-verify.yml is live as of this push)."

  if ! grep -q '^CTEM_LOG4J_REMEDIATION_REPO=' "$BACKEND_ENV" 2>/dev/null; then
    echo "CTEM_LOG4J_REMEDIATION_REPO=$repo" >> "$BACKEND_ENV"
    echo "  wrote CTEM_LOG4J_REMEDIATION_REPO=$repo to backend/.env"
  fi
  echo "Setup complete. Run ./run.sh restart to load it, then ./run.sh inject-code log4j."
}

# Close any open ctem/fix-* PRs and delete those branches on ONE repo so
# repeated demo runs start clean. No-op when the repo/token aren't configured.
reset_github_repo() {
  local tok="$1" repo="$2"
  if [[ -z "$tok" || -z "$repo" ]]; then
    return 0
  fi
  echo "Cleaning ctem/fix-* branches and PRs on $repo..."
  CTEM_REPO="$repo" GH_TOK="$tok" python3 <<'PY' || echo "  (github cleanup skipped after an error)"
import json, os, urllib.request, urllib.error, urllib.parse
repo, tok = os.environ["CTEM_REPO"], os.environ["GH_TOK"]
def api(method, path, data=None):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        data=(json.dumps(data).encode() if data is not None else None), method=method,
        headers={"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json", "User-Agent": "ctem-demo"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        return e.code, None
_, prs = api("GET", f"/repos/{repo}/pulls?state=open&per_page=100")
closed = 0
for pr in prs or []:
    if pr["head"]["ref"].startswith("ctem/fix-"):
        api("PATCH", f"/repos/{repo}/pulls/{pr['number']}", {"state": "closed"}); closed += 1
_, branches = api("GET", f"/repos/{repo}/branches?per_page=100")
deleted = 0
for b in branches or []:
    if b["name"].startswith("ctem/fix-"):
        api("DELETE", f"/repos/{repo}/git/refs/heads/{urllib.parse.quote(b['name'], safe='')}"); deleted += 1
print(f"  closed {closed} PR(s), deleted {deleted} branch(es)")
PY
}

# Cleans BOTH live-remediation target repos (npm + log4j/maven), whichever
# are configured. No-op per-repo when that repo/token aren't set up yet.
reset_github() {
  local tok; tok="$(env_val GITHUB_TOKEN)"
  local repo; repo="$(env_val CTEM_REMEDIATION_REPO)"
  local log4j_repo; log4j_repo="$(env_val CTEM_LOG4J_REMEDIATION_REPO)"
  if [[ -z "$tok" ]]; then
    echo "  (GITHUB_TOKEN not configured in backend/.env; skipping repo cleanup)"
    return 0
  fi
  if [[ -z "$repo" && -z "$log4j_repo" ]]; then
    echo "  (no remediation target repos configured in backend/.env; skipping repo cleanup)"
    return 0
  fi
  reset_github_repo "$tok" "$repo"
  reset_github_repo "$tok" "$log4j_repo"
}

# Force-push the current node-payments-api snapshot (which carries all three
# independent vulns — lodash SCA, command-injection SAST, reflected-XSS DAST) to
# a repo's main. Shared by `setup` and the `reset` preflight's self-healing.
push_npm_snapshot() {
  local tok="$1" repo="$2"
  local tmp; tmp="$(mktemp -d)"
  cp -R "$TARGET_SNAPSHOT/." "$tmp/"
  (
    cd "$tmp" && rm -rf node_modules .git
    git init -b main -q
    git -c user.email=ctem-agent@mphasis.demo -c user.name="CTEM Implementation Agent" add -A
    git -c user.email=ctem-agent@mphasis.demo -c user.name="CTEM Implementation Agent" \
        commit -qm "vulnerable baseline (lodash 4.17.4 SCA, command-injection SAST, reflected-XSS DAST)"
    git remote add origin "https://x-access-token:${tok}@github.com/${repo}.git"
    git push -u origin main --force -q
  ) || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
}

# Return 0 iff the remote repo's main carries all three expected vulns.
verify_npm_baseline() {
  local tok="$1" repo="$2"
  CTEM_REPO="$repo" GH_TOK="$tok" python3 - <<'PY'
import os, sys, base64, json, urllib.request
repo, tok = os.environ["CTEM_REPO"], os.environ["GH_TOK"]
def get(path):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/contents/{path}?ref=main",
        headers={"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json", "User-Agent": "ctem"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return base64.b64decode(json.load(r)["content"]).decode()
try:
    srv, pkg = get("src/server.js"), get("package.json")
except Exception:
    sys.exit(1)
sca = '"lodash": "4.17.4"' in pkg
sast = "cp.exec('echo resolving ' + host" in srv
dast = "function renderGreeting" in srv and "Hello, ${name}!" in srv
sys.exit(0 if (sca and sast and dast) else 1)
PY
}

# Make sure the npm baseline repo carries all three vulns; refresh it if stale.
# No-op (local-snapshot mode) when no remote repo is configured.
ensure_npm_baseline() {
  local tok repo
  tok="$(env_val GITHUB_TOKEN)"; repo="$(env_val CTEM_REMEDIATION_REPO)"
  if [[ -z "$tok" || -z "$repo" ]]; then
    echo "  baseline: local-snapshot mode (no CTEM_REMEDIATION_REPO) — snapshot carries SCA+SAST+DAST."
    return 0
  fi
  if verify_npm_baseline "$tok" "$repo"; then
    echo "  baseline: OK — $repo carries SCA+SAST+DAST vulns."
  else
    echo "  baseline: $repo missing/stale vulns — refreshing from snapshot..."
    if push_npm_snapshot "$tok" "$repo"; then echo "    refreshed."; else echo "    ❌ refresh FAILED (check GITHUB_TOKEN)."; fi
  fi
}

# Print a clear pre-demo readiness checklist.
double_check() {
  echo ""
  echo "=== Pre-demo readiness ==="
  local ok=1
  if curl -sf -o /dev/null "http://localhost:${BACKEND_PORT}/api/health"; then
    echo "  ✅ backend  :${BACKEND_PORT} up — $(curl -s "http://localhost:${BACKEND_PORT}/api/health")"
  else
    echo "  ❌ backend  :${BACKEND_PORT} DOWN"; ok=0
  fi
  if curl -sf -o /dev/null "$DEMO_URL"; then
    echo "  ✅ frontend :${FRONTEND_PORT} up"
  else
    echo "  ❌ frontend :${FRONTEND_PORT} DOWN"; ok=0
  fi
  if [[ "$ok" == "1" ]]; then
    echo ""
    echo "  READY. Inject a scenario:"
    echo "    ./run.sh inject-code live      # SCA  — lodash CVE, deterministic bump"
    echo "    ./run.sh inject-code agentic   # SAST — command injection, agentic code fix"
    echo "    ./run.sh inject-code dast      # DAST — reflected XSS, black-box HTTP probe + agentic fix"
    echo "    ./run.sh demo-scenarios        # all three, back-to-back"
  else
    echo ""
    echo "  NOT READY — run ./run.sh restart, then ./run.sh reset."
  fi
}

# Reset the whole demo to a clean slate AND leave it demo-ready:
#   1) make sure both servers are up (start them if not),
#   2) reset backend runs/queues/graph (control API) + clean GitHub branches/PRs,
#   3) ensure the live-remediation baseline repo carries all three vulns,
#   4) print a pre-demo readiness checklist.
reset() {
  local mode="${1:-presentation}"
  [[ "$mode" == "presentation" || "$mode" == "technical" ]] || { echo "mode must be presentation or technical" >&2; exit 2; }

  # Ensure servers are up. Only (re)start when something is down — start() calls
  # `exit 0` when it's already running, which would abort this script mid-reset.
  if ! curl -sf -o /dev/null "http://localhost:${BACKEND_PORT}/api/health" || ! is_running "$FRONTEND_PID_FILE"; then
    echo "Servers not fully up — starting them first..."
    stop >/dev/null 2>&1 || true
    start
  fi

  echo "Resetting backend demo state ($mode)..."
  if curl -sf -X POST "http://localhost:${BACKEND_PORT}/api/_control/reset?mode=$mode" \
       -H 'Content-Type: application/json' -d '{}' >/dev/null; then
    echo "  backend reset."
  else
    echo "  backend reset failed (is it healthy? see $BACKEND_LOG)."
  fi
  reset_github
  ensure_npm_baseline
  double_check
}

case "${1:-}" in
  start)       start ;;
  stop)        stop ;;
  restart)     stop; start ;;
  status)      status ;;
  setup)       setup ;;
  setup-log4j) setup_log4j ;;
  reset)       reset "${2:-presentation}" ;;
  inject-code) inject_code "${2:-live}" ;;
  demo-scenarios) inject_code live; inject_code agentic; inject_code dast ;;  # inject SCA + SAST + DAST back to back
  *)
    echo "Usage: $0 {start|stop|restart|status|setup|setup-log4j|reset [presentation|technical]|inject-code [live|agentic|dast|blocked|log4j]|demo-scenarios}"
    exit 1
    ;;
esac
