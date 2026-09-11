#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 || ! -f $1 || ! -x $1 ]]; then
  echo "usage: $0 /absolute/path/to/prufyx-community" >&2
  exit 2
fi
for command in jq mktemp chmod cp rm dirname stat awk grep; do
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
example=$script_dir/input.json
work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-synthetic-otelcol.XXXXXXXX")
cleanup_needed=true
cleanup() {
  local command_exit=$?
  trap - EXIT HUP INT TERM
  if [[ $cleanup_needed == true ]]; then
    if ! rm -rf -- "$work" || [[ -e $work ]]; then
      echo "synthetic OpenTelemetry Collector example cleanup failed" >&2
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
example_digest=$(sha256_file "$example")
blocked_input="$work/PRIVATE-OTELCOL-BLOCKED.json"
pass_input="$work/PRIVATE-OTELCOL-PASS.json"
unknown_input="$work/PRIVATE-OTELCOL-UNKNOWN.json"
unsupported_input="$work/PRIVATE-OTELCOL-UNSUPPORTED.json"
blocked_report="$work/blocked-report.json"
pass_report="$work/pass-report.json"
unknown_report="$work/unknown-report.json"
unsupported_report="$work/unsupported-report.json"
cp -- "$example" "$blocked_input"
chmod 0600 "$blocked_input"
jq -e '.proposed.components[0].facts[0].enumValue == "official" and .proposed.components[0].facts[1].boolValue == true' "$blocked_input" >/dev/null
[[ $(file_mode "$blocked_input") == 600 ]] || { echo "blocked input is not private" >&2; exit 1; }

set +e
"$binary" check cncf --project opentelemetry --input "$blocked_input" \
  --input-digest "sha256:$(sha256_file "$blocked_input")" \
  --now 2026-09-10T00:00:00Z --format json >"$blocked_report"
blocked_status=$?
set -e
[[ $blocked_status -eq 10 ]] || { echo "blocked Collector check expected exit 10, got $blocked_status" >&2; exit 1; }
chmod 0600 "$blocked_report"
jq -e '
  .project == "opentelemetry" and .assessment == "UNKNOWN" and .runtimeReproduced == 0 and .networkUsed == false and
  .check.claims[0].ruleId == "opentelemetry.logging-exporter-removed.0-111" and
  .check.claims[0].status == "BLOCKED"
' "$blocked_report" >/dev/null

jq ' .proposed.components[0].facts[1].boolValue = false ' "$blocked_input" >"$pass_input"
chmod 0600 "$pass_input"
set +e
"$binary" check cncf --project opentelemetry --input "$pass_input" \
  --input-digest "sha256:$(sha256_file "$pass_input")" \
  --now 2026-09-10T00:00:00Z --format json >"$pass_report"
pass_status=$?
set -e
[[ $pass_status -eq 0 ]] || { echo "clean Collector check expected exit 0, got $pass_status" >&2; exit 1; }
chmod 0600 "$pass_report"
jq -e '
  .project == "opentelemetry" and .assessment == "UNKNOWN" and .runtimeReproduced == 0 and .networkUsed == false and
  .check.claims[0].ruleId == "opentelemetry.logging-exporter-removed.0-111" and
  .check.claims[0].status == "PASS"
' "$pass_report" >/dev/null

jq ' .proposed.components[0].facts |= map(select(.id != "component.opentelemetry.logging_exporter_present")) ' "$blocked_input" >"$unknown_input"
chmod 0600 "$unknown_input"
set +e
"$binary" check cncf --project opentelemetry --input "$unknown_input" \
  --input-digest "sha256:$(sha256_file "$unknown_input")" \
  --now 2026-09-10T00:00:00Z --format json >"$unknown_report"
unknown_status=$?
set -e
[[ $unknown_status -eq 11 ]] || { echo "missing Collector fact expected exit 11, got $unknown_status" >&2; exit 1; }
chmod 0600 "$unknown_report"
jq -e '
  .project == "opentelemetry" and .assessment == "UNKNOWN" and .runtimeReproduced == 0 and .networkUsed == false and
  .check.claims[0].ruleId == "opentelemetry.logging-exporter-removed.0-111" and
  .check.claims[0].status == "UNKNOWN" and .check.claims[0].reasonCode == "RULE_FACT_UNAVAILABLE"
' "$unknown_report" >/dev/null

jq ' .current.components[0].version = "0.111.0" | .proposed.components[0].version = "0.112.0" ' "$blocked_input" >"$unsupported_input"
chmod 0600 "$unsupported_input"
set +e
"$binary" check cncf --project opentelemetry --input "$unsupported_input" \
  --input-digest "sha256:$(sha256_file "$unsupported_input")" \
  --now 2026-09-10T00:00:00Z --format json >"$unsupported_report"
unsupported_status=$?
set -e
[[ $unsupported_status -eq 11 ]] || { echo "unsupported Collector pair expected exit 11, got $unsupported_status" >&2; exit 1; }
chmod 0600 "$unsupported_report"
jq -e '
  .project == "opentelemetry" and .assessment == "UNKNOWN" and .runtimeReproduced == 0 and .networkUsed == false and
  .check.claims[0].ruleId == "opentelemetry.logging-exporter-removed.0-111" and
  .check.claims[0].status == "UNKNOWN" and .check.claims[0].reasonCode == "RULE_TRANSITION_NOT_REVIEWED"
' "$unsupported_report" >/dev/null

for file in "$blocked_input" "$pass_input" "$unknown_input" "$unsupported_input" "$blocked_report" "$pass_report" "$unknown_report" "$unsupported_report"; do
  [[ $(file_mode "$file") == 600 ]] || { echo "private Collector file mode is not 0600: $file" >&2; exit 1; }
done
if grep -Fq 'synthetic' "$blocked_report" "$pass_report" "$unknown_report"; then
  echo "private Collector marker crossed minimized output boundary" >&2
  exit 1
fi
[[ $(sha256_file "$example") == "$example_digest" ]] || { echo "canonical Collector example changed" >&2; exit 1; }
binary_digest_after=$(sha256_file "$binary")
[[ $binary_digest_after == "$binary_digest_before" ]] || { echo "candidate binary changed during Collector example" >&2; exit 1; }

if ! rm -rf -- "$work" || [[ -e $work ]]; then
  echo "synthetic OpenTelemetry Collector example cleanup failed" >&2
  exit 1
fi
cleanup_needed=false
trap - EXIT HUP INT TERM
jq -cn --arg binaryDigest "sha256:$binary_digest_before" --arg exampleDigest "sha256:$example_digest" \
  '{apiVersion:"prufyx.io/synthetic-opentelemetry-collector-example-result/v1",status:"PASS",purpose:"synthetic_test_only",binaryDigest:$binaryDigest,exampleDigest:$exampleDigest,transition:{from:"0.110.0",to:"0.111.0"},blocked:{checkExit:10,claimStatus:"BLOCKED"},clean:{checkExit:0,claimStatus:"PASS"},missing:{checkExit:11,claimStatus:"UNKNOWN"},aggregateAssessment:"UNKNOWN",networkUsed:false,clusterUsed:false,privateInputsRetained:false,unsupportedPair:{checkExit:11,claimStatus:"UNKNOWN",reasonCode:"RULE_TRANSITION_NOT_REVIEWED"}}'
