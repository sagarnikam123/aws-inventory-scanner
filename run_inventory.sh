#!/usr/bin/env bash
#
# Run all inventory scanners for one AWS account, N at a time.
# Config comes from .env (see .env.example). Failures are warned but never
# stop the run — a broken scanner won't block the rest.
#
# Usage:
#   cp .env.example .env    # edit AWS_PROFILE, PARALLEL, etc.
#   ./run_inventory.sh
#
# Override .env inline:
#   AWS_PROFILE=myprofile PARALLEL=4 ./run_inventory.sh
#
set -uo pipefail   # NOT -e: one failing scanner must not abort the whole run

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INV_DIR="$HERE/inventory"
LOG_DIR="$HERE/output/_run_logs"

# --- load .env (without clobbering already-exported env vars) ---
if [[ -f "$HERE/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$HERE/.env"
  set +a
fi

: "${AWS_PROFILE:?Set AWS_PROFILE in .env (see .env.example)}"
PARALLEL="${PARALLEL:-2}"
AWS_REGION="${AWS_REGION:-}"
ONLY="${ONLY:-}"
SKIP="${SKIP:-}"

# --- build the script list ---
if [[ -n "$ONLY" ]]; then
  # explicit list from ONLY (comma-separated)
  IFS=',' read -r -a scripts <<< "$ONLY"
else
  scripts=()
  while IFS= read -r line; do scripts+=("$(basename "$line")"); done \
    < <(find "$INV_DIR" -maxdepth 1 -name 'get_*.py' | sort)
fi

# apply SKIP filter
if [[ -n "$SKIP" ]]; then
  IFS=',' read -r -a skiplist <<< "$SKIP"
  filtered=()
  for s in "${scripts[@]}"; do
    drop=0
    for sk in "${skiplist[@]}"; do [[ "$s" == "$(echo "$sk" | xargs)" ]] && drop=1; done
    [[ $drop -eq 0 ]] && filtered+=("$s")
  done
  scripts=("${filtered[@]}")
fi

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.status   # clear prior run's outcomes

echo "============================================================"
echo "  AWS Inventory Runner"
echo "  Profile:   $AWS_PROFILE"
echo "  Region:    ${AWS_REGION:-<all>}"
echo "  Parallel:  $PARALLEL"
echo "  Scripts:   ${#scripts[@]}"
echo "  Logs:      $LOG_DIR"
echo "============================================================"

# --- worker: runs one script, logs output, reports pass/fail (never exits nonzero) ---
run_one() {
  local script="$1" profile="$2" region="$3" invdir="$4" logdir="$5"
  local name="${script%.py}"
  local log="$logdir/${name}.log"
  local ra=(); [[ -n "$region" ]] && ra=(-r "$region")

  if python3 "$invdir/$script" -p "$profile" "${ra[@]}" > "$log" 2>&1; then
    echo "ok" > "$log.status"
    echo "✅ $script"
  else
    local code=$?
    echo "fail:$code" > "$log.status"
    echo "⚠️  $script FAILED (exit $code) — see $log" >&2
    tail -n 3 "$log" | sed 's/^/       /' >&2
  fi
}
export -f run_one

# --- run PARALLEL at a time via xargs; failures don't stop the batch ---
printf '%s\n' "${scripts[@]}" \
  | xargs -P "$PARALLEL" -I {} bash -c \
      'run_one "$@"' _ {} "$AWS_PROFILE" "$AWS_REGION" "$INV_DIR" "$LOG_DIR"

echo "============================================================"
# --- summary from logs ---
pass=0; fail=0; failed_names=()
for s in "${scripts[@]}"; do
  status_file="$LOG_DIR/${s%.py}.log.status"
  if [[ -f "$status_file" && "$(cat "$status_file")" == "ok" ]]; then
    ((pass++))
  else
    ((fail++)); failed_names+=("$s")
  fi
done
echo "  Done: $pass ok, $fail with errors"
if [[ $fail -gt 0 ]]; then
  echo "  Failed scripts:"
  printf '    %s\n' "${failed_names[@]}"
fi
echo "============================================================"
