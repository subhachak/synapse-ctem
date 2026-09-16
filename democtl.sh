#!/usr/bin/env bash
# Command-line control plane for the local CTEM demo backend.

set -euo pipefail

API_BASE="${CTEM_API_BASE:-http://localhost:8000}"

pretty() {
  if command -v jq >/dev/null 2>&1; then jq .; else python3 -m json.tool; fi
}

post_json() {
  local url="$1" body="$2"
  curl --fail-with-body --silent --show-error \
    -X POST -H "Content-Type: application/json" -d "$body" "$url"
}

extract_run_id() {
  if command -v jq >/dev/null 2>&1; then jq -r .run_id; else python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])'; fi
}

usage() {
  cat <<'USAGE'
Usage:
  ./democtl.sh health
  ./democtl.sh reset [presentation|technical]
  ./democtl.sh inject-preset <find-1..find-7>
  ./democtl.sh inject-example [normal|failure]
  ./democtl.sh inject-json <payload.json|->
  ./democtl.sh status <run-id>
  ./democtl.sh watch <run-id>
  ./democtl.sh open <run-id>
  ./democtl.sh suppressions
  ./democtl.sh reopen <run-id> [trigger]
  ./democtl.sh outcome <run-id> <observed|not-observed|unknown> <successful|failed|rolled-back|not-applicable|unknown> [reason-code]
  ./democtl.sh learning

Environment:
  CTEM_API_BASE=http://localhost:8000
  CTEM_UI_BASE=http://localhost:3000
USAGE
}

command="${1:-}"
case "$command" in
  health)
    curl --fail-with-body --silent --show-error "$API_BASE/api/health" | pretty
    ;;
  reset)
    mode="${2:-presentation}"
    [[ "$mode" == "presentation" || "$mode" == "technical" ]] || { echo "mode must be presentation or technical" >&2; exit 2; }
    post_json "$API_BASE/api/_control/reset?mode=$mode" '{}' | pretty
    ;;
  inject-preset)
    finding="${2:?provide a preset id such as find-1}"
    response="$(post_json "$API_BASE/api/_control/incidents" "{\"preset\":\"$finding\"}")"
    run_id="$(printf '%s' "$response" | extract_run_id)"
    echo "$run_id"
    echo "UI: ${CTEM_UI_BASE:-http://localhost:3000}/review/$run_id" >&2
    ;;
  inject-example)
    scenario="${2:-normal}"
    failure=false
    [[ "$scenario" == "normal" || "$scenario" == "failure" ]] || { echo "scenario must be normal or failure" >&2; exit 2; }
    [[ "$scenario" == "failure" ]] && failure=true
    body="{\"custom\":{\"component\":\"GnuPG\",\"name\":\"CLI-injected GnuPG memory safety case\",\"cve\":\"CVE-DEMO-CLI\",\"severity\":\"High\",\"cvssBase\":8.2,\"epss\":0.72,\"cisaKev\":false,\"runtimeReachable\":true,\"affectedServiceIds\":[\"svc-1\"],\"source\":\"Command-line demo adapter\",\"simulateSandboxFailure\":$failure}}"
    response="$(post_json "$API_BASE/api/_control/incidents" "$body")"
    run_id="$(printf '%s' "$response" | extract_run_id)"
    echo "$run_id"
    echo "UI: ${CTEM_UI_BASE:-http://localhost:3000}/review/$run_id" >&2
    ;;
  inject-json)
    source="${2:?provide a JSON file or - for stdin}"
    if [[ "$source" == "-" ]]; then body="$(cat)"; else body="$(<"$source")"; fi
    response="$(post_json "$API_BASE/api/_control/incidents" "$body")"
    run_id="$(printf '%s' "$response" | extract_run_id)"
    echo "$run_id"
    echo "UI: ${CTEM_UI_BASE:-http://localhost:3000}/review/$run_id" >&2
    ;;
  status)
    run_id="${2:?provide a run id}"
    curl --fail-with-body --silent --show-error "$API_BASE/api/incidents/$run_id" | pretty
    ;;
  watch)
    run_id="${2:?provide a run id}"
    echo "Streaming persisted node events and run status. Ctrl-C stops watching." >&2
    curl --fail-with-body --no-buffer --silent --show-error "$API_BASE/api/incidents/$run_id/stream"
    ;;
  open)
    run_id="${2:?provide a run id}"
    open "${CTEM_UI_BASE:-http://localhost:3000}/review/$run_id"
    ;;
  suppressions)
    curl --fail-with-body --silent --show-error "$API_BASE/api/suppressions" | pretty
    ;;
  reopen)
    run_id="${2:?provide a suppressed run id}"
    trigger="${3:-demo-context-change}"
    post_json "$API_BASE/api/suppressions/$run_id/reopen" "{\"trigger\":\"$trigger\"}" | pretty
    ;;
  outcome)
    run_id="${2:?provide a run id}"
    exploitation="${3:?provide observed, not-observed, or unknown}"
    remediation="${4:?provide successful, failed, rolled-back, not-applicable, or unknown}"
    reason="${5:-demo-review}"
    post_json "$API_BASE/api/incidents/$run_id/outcome" "{\"exploitation_outcome\":\"$exploitation\",\"remediation_outcome\":\"$remediation\",\"reviewer_reason_code\":\"$reason\"}" | pretty
    ;;
  learning)
    curl --fail-with-body --silent --show-error "$API_BASE/api/learning/summary" | pretty
    ;;
  *) usage; [[ -z "$command" ]] || exit 2 ;;
esac
