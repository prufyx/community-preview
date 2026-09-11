#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -f $1 || ! -x $1 ]]; then
  echo "usage: $0 /path/to/prufyx" >&2
  exit 2
fi

for command in go jq mktemp chmod cmp awk grep rm dirname; do
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

binary=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cli_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-synthetic-knowledge.XXXXXXXX")
cleanup_needed=true
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ $cleanup_needed == true ]]; then
    if ! rm -rf -- "$work" || [[ -e $work ]]; then
      echo "synthetic knowledge example cleanup failed" >&2
      exit 1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

binary_digest_before=$(sha256_file "$binary")
packages="$work/packages"
store="$work/store"
values="$work/values.json"
manifest="$packages/synthetic-manifest.json"

(
  cd "$cli_root"
  env GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
    go run ./examples/community/knowledge/generate-synthetic-packages.go --output "$packages" > "$work/generator.json"
)
printf '%s\n' '{"syntheticCanary":"PUBLIC-SYNTHETIC-CANARY-7bd198","prometheus":{"servicemonitor":{"path":"PUBLIC-SYNTHETIC-CANARY-7bd198"}}}' > "$values"
chmod 0600 "$values"

root_digest=$(jq -er '.bootstrapRoot.digest' "$manifest")
bundle1=$(jq -er '.revisions[] | select(.revision == "1") | .bundleDigest' "$manifest")
bundle2=$(jq -er '.revisions[] | select(.revision == "2") | .bundleDigest' "$manifest")

"$binary" db import "$packages/synthetic-revision-1.tar" \
  --db-root "$store" --bootstrap-root "$packages/synthetic-root.json" --bootstrap-root-digest "$root_digest" \
  --expected-revision 1 --expected-bundle-digest "$bundle1" --format json > "$work/import-1.json"
receipt1=$(jq -er '.trustReceiptDigest' "$work/import-1.json")

set +e
"$binary" check cert-manager-values --from 1.20.3 --to 1.21.1 --values "$values" \
  --knowledge-db "$store" --knowledge-revision 1 --knowledge-bundle-digest "$bundle1" \
  --knowledge-trust-receipt-digest "$receipt1" --format json > "$work/report-1.json"
check1=$?
set -e
[[ $check1 -eq 11 ]] || { echo "revision 1 expected UNKNOWN/11, got $check1" >&2; exit 1; }
jq -e '.check.claim.status == "UNKNOWN" and .knowledge.revision == "1" and .knowledge.purpose == "synthetic_test_only"' "$work/report-1.json" >/dev/null

"$binary" db import "$packages/synthetic-revision-2.tar" --db-root "$store" \
  --expected-revision 2 --expected-bundle-digest "$bundle2" --format json > "$work/import-2.json"
receipt2=$(jq -er '.trustReceiptDigest' "$work/import-2.json")

set +e
"$binary" check cert-manager-values --from 1.20.3 --to 1.21.1 --values "$values" \
  --knowledge-db "$store" --knowledge-revision 2 --knowledge-bundle-digest "$bundle2" \
  --knowledge-trust-receipt-digest "$receipt2" --format json > "$work/report-2.json"
check2=$?
set -e
[[ $check2 -eq 10 ]] || { echo "revision 2 expected BLOCKED/10, got $check2" >&2; exit 1; }
jq -e '.check.claim.status == "BLOCKED" and .knowledge.revision == "2" and .knowledge.purpose == "synthetic_test_only"' "$work/report-2.json" >/dev/null

values_digest="sha256:$(sha256_file "$values")"
set +e
"$binary" check cert-manager-values --from 1.20.3 --to 1.21.1 --values "$values" --values-digest "$values_digest" \
  --knowledge-db "$store" --knowledge-revision 1 --knowledge-bundle-digest "$bundle1" \
  --knowledge-trust-receipt-digest "$receipt1" --replay-receipt "$work/report-1.json" --format json > "$work/replay-1.json"
replay1=$?
set -e
[[ $replay1 -eq 11 ]] || { echo "revision 1 historical replay expected UNKNOWN/11, got $replay1" >&2; exit 1; }
jq -e '.mode == "historical" and .status == "MATCH" and .currentNonRevocation == "not_checked_offline"' "$work/replay-1.json" >/dev/null
jq -c '.originalReport' "$work/replay-1.json" > "$work/replayed-original.json"
cmp "$work/report-1.json" "$work/replayed-original.json"

"$binary" db status --db-root "$store" --format json > "$work/status.json"
jq -e '.state == "READY" and .currentEligible == true and .selectedRevision == "2" and .purpose == "synthetic_test_only" and .networkChecked == false' "$work/status.json" >/dev/null
if grep -Fq 'PUBLIC-SYNTHETIC-CANARY-7bd198' "$work/report-1.json" "$work/report-2.json" "$work/replay-1.json" "$work/status.json"; then
  echo "synthetic private value crossed the retained report boundary" >&2
  exit 1
fi

binary_digest_after=$(sha256_file "$binary")
[[ $binary_digest_after == "$binary_digest_before" ]] || { echo "candidate binary changed during the example" >&2; exit 1; }

if ! rm -rf -- "$work" || [[ -e $work ]]; then
  echo "synthetic knowledge example cleanup failed" >&2
  exit 1
fi
cleanup_needed=false
trap - EXIT HUP INT TERM
jq -cn \
  --arg binaryDigest "sha256:$binary_digest_before" \
  --arg revision1Bundle "$bundle1" --arg revision2Bundle "$bundle2" \
  '{apiVersion:"prufyx.io/synthetic-knowledge-example-result/v1",status:"PASS",purpose:"synthetic_test_only",binaryDigest:$binaryDigest,revision1:{claim:"UNKNOWN",exit:11,bundleDigest:$revision1Bundle},revision2:{claim:"BLOCKED",exit:10,bundleDigest:$revision2Bundle},historicalReplay:{status:"MATCH",exit:11,currentNonRevocation:"not_checked_offline"},networkUsed:false,privateKeysPersisted:false,temporaryStoreRetained:false}'
