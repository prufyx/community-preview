#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 || ! -f $1 || ! -x $1 ]]; then
  echo "usage: $0 /absolute/path/to/prufyx-community" >&2
  exit 2
fi

for command in jq mktemp chmod cmp awk grep rm dirname stat; do
  command -v "$command" >/dev/null 2>&1 || { echo "required command missing: $command" >&2; exit 2; }
done
if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "required command missing: sha256sum or shasum" >&2
  exit 2
fi

file_mode() {
  local value
  if value=$(stat -f '%Lp' "$1" 2>/dev/null) && [[ $value =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$value"
  elif value=$(stat -c '%a' "$1" 2>/dev/null) && [[ $value =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$value"
  else
    return 1
  fi
}

binary=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cli_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-synthetic-etcd.XXXXXXXX")
cleanup_needed=true
cleanup() {
  local command_exit=$?
  trap - EXIT HUP INT TERM
  if [[ $cleanup_needed == true ]]; then
    if ! rm -rf -- "$work" || [[ -e $work ]]; then
      echo "synthetic etcd example cleanup failed" >&2
      exit 1
    fi
  fi
  exit "$command_exit"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

binary_digest_before=$(sha256_file "$binary")
raw="$work/PRIVATE-ETCD-EFFECTIVE-ARGV-7b1f.json"
prepared="$work/etcd-prepared.json"
report="$work/etcd-report.json"
unknown_raw="$work/PRIVATE-ETCD-AMBIGUOUS-ARGV-7b1f.json"
unknown_prepared="$work/etcd-unknown-prepared.json"
unknown_report="$work/etcd-unknown-report.json"

cat >"$raw" <<'JSON'
{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=synthetic-private-node","--enable-v2=false"]}
JSON
chmod 0600 "$raw"
raw_digest="sha256:$(sha256_file "$raw")"

set +e
"$binary" prepare cncf --project etcd --input "$raw" --from 3.5.17 --to 3.6.0 \
  --input-digest "$raw_digest" --format input >"$prepared"
prepare_status=$?
set -e
[[ $prepare_status -eq 0 ]] || { echo "etcd witness preparation expected exit 0, got $prepare_status" >&2; exit 1; }
chmod 0600 "$prepared"
jq -e '
  .schema == "prufyx.io/operator-declared-constraint-input/v1alpha1" and
  .current.components[0].component == "pkg:github/etcd-io/etcd" and
  .current.components[0].version == "3.5.17" and
  .proposed.components[0].version == "3.6.0" and
  .proposed.components[0].facts[0].id == "component.etcd.removed_v2_proxy_flags_present" and
  .proposed.components[0].facts[0].state == "declared" and
  .proposed.components[0].facts[0].boolValue == true
' "$prepared" >/dev/null

prepared_digest="sha256:$(sha256_file "$prepared")"
set +e
"$binary" check cncf --project etcd --input "$prepared" --input-digest "$prepared_digest" \
  --now 2026-09-10T00:00:00Z --format json >"$report"
check_status=$?
set -e
[[ $check_status -eq 10 ]] || { echo "etcd witness check expected exit 10, got $check_status" >&2; exit 1; }
chmod 0600 "$report"
jq -e '
  .project == "etcd" and .assessment == "UNKNOWN" and .runtimeReproduced == 0 and .networkUsed == false and
  .check.claims[0].ruleId == "etcd.v2-proxy-flags-removed.3-6" and
  .check.claims[0].status == "BLOCKED" and
  .check.claims[0].reasonCode == "REVIEWED_SOURCE_CONSTRAINT"
' "$report" >/dev/null

cat >"$unknown_raw" <<'JSON'
{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--initial-cluster","--enable-v2=true"]}
JSON
chmod 0600 "$unknown_raw"
unknown_raw_digest="sha256:$(sha256_file "$unknown_raw")"
set +e
"$binary" prepare cncf --project etcd --input "$unknown_raw" --from 3.5.17 --to 3.6.0 \
  --input-digest "$unknown_raw_digest" --format input >"$unknown_prepared"
unknown_prepare_status=$?
set -e
[[ $unknown_prepare_status -eq 11 ]] || { echo "etcd ambiguous preparation expected exit 11, got $unknown_prepare_status" >&2; exit 1; }
chmod 0600 "$unknown_prepared"
jq -e '
  .proposed.components[0].facts[0].id == "component.etcd.removed_v2_proxy_flags_present" and
  .proposed.components[0].facts[0].state == "missing" and
  (.proposed.components[0].facts[0] | has("boolValue") | not)
' "$unknown_prepared" >/dev/null

unknown_prepared_digest="sha256:$(sha256_file "$unknown_prepared")"
set +e
"$binary" check cncf --project etcd --input "$unknown_prepared" --input-digest "$unknown_prepared_digest" \
  --now 2026-09-10T00:00:00Z --format json >"$unknown_report"
unknown_check_status=$?
set -e
[[ $unknown_check_status -eq 11 ]] || { echo "etcd ambiguous check expected exit 11, got $unknown_check_status" >&2; exit 1; }
chmod 0600 "$unknown_report"
jq -e '
  .assessment == "UNKNOWN" and .runtimeReproduced == 0 and .networkUsed == false and
  .check.claims[0].ruleId == "etcd.v2-proxy-flags-removed.3-6" and
  .check.claims[0].status == "UNKNOWN" and .check.claims[0].reasonCode == "RULE_FACT_UNAVAILABLE"
' "$unknown_report" >/dev/null

for file in "$raw" "$prepared" "$report" "$unknown_raw" "$unknown_prepared" "$unknown_report"; do
  [[ $(file_mode "$file") == 600 ]] || { echo "private etcd example file mode is not 0600: $file" >&2; exit 1; }
done
if grep -Fq 'synthetic-private-node' "$prepared" "$report" "$unknown_prepared" "$unknown_report"; then
  echo "private etcd argv crossed the minimized output boundary" >&2
  exit 1
fi
binary_digest_after=$(sha256_file "$binary")
[[ $binary_digest_after == "$binary_digest_before" ]] || { echo "candidate binary changed during the example" >&2; exit 1; }

if ! rm -rf -- "$work" || [[ -e $work ]]; then
  echo "synthetic etcd example cleanup failed" >&2
  exit 1
fi
cleanup_needed=false
trap - EXIT HUP INT TERM
jq -cn \
  --arg binaryDigest "sha256:$binary_digest_before" \
  '{apiVersion:"prufyx.io/synthetic-etcd-example-result/v1",status:"PASS",purpose:"synthetic_test_only",binaryDigest:$binaryDigest,witness:{from:"3.5.17",to:"3.6.0",flag:"--enable-v2=false",prepareExit:0,checkExit:10,claimStatus:"BLOCKED",aggregateAssessment:"UNKNOWN"},ambiguous:{prepareExit:11,checkExit:11,claimStatus:"UNKNOWN"},networkUsed:false,clusterUsed:false,privateInputsRetained:false}'
