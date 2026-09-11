#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

# This is an integration gate for the Linux runner, not a production network
# control. macOS developers keep the ordinary cross-platform test path; the
# mandatory Linux job must have both namespace isolation and syscall tracing.
if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' 'offline CLI boundary: SKIP (Linux integration gate only)' >&2
  exit 0
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'offline CLI boundary: required command is unavailable: %s\n' "$1" >&2
    exit 1
  }
}

for command in go jq python3 strace unshare sudo setpriv mktemp chmod cp mkdir awk grep stat; do
  need "$command"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  printf '%s\n' 'offline CLI boundary: required command is unavailable: sha256sum or shasum' >&2
  exit 1
fi

if [[ "$(id -u)" == 0 ]]; then
  printf '%s\n' 'offline CLI boundary: refusing to run as root; use the hosted non-root runner' >&2
  exit 1
fi

test_uid=$(id -u)
test_gid=$(id -g)

# sudo is used only to create the isolated network namespace. setpriv drops
# immediately to the original fixture-owning identity before the observer,
# positive control, or any CLI process starts. No CLI command is run by sudo.
namespace_launcher=(sudo -n unshare --net -- setpriv "--reuid=$test_uid" "--regid=$test_gid" --clear-groups --)

if ! "${namespace_launcher[@]}" true >/dev/null 2>&1; then
  printf '%s\n' 'offline CLI boundary: sudo-created network namespace or credential drop is unavailable' >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
else
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

assert_owned() {
  local path owner
  for path in "$@"; do
    owner=$(stat -c '%u' "$path")
    [[ "$owner" == "$test_uid" ]] || {
      printf 'offline CLI boundary: fixture is not owned by test UID %s: %s\n' "$test_uid" "$path" >&2
      exit 1
    }
  done
}

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cli_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/prufyx-offline-boundary.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir -m 0700 "$work/traces" "$work/output" "$work/store"

: > "$work/namespace-identity-fixture"
chmod 0600 "$work/namespace-identity-fixture"
assert_owned "$work/namespace-identity-fixture"
if ! "${namespace_launcher[@]}" python3 - "$work/namespace-identity-fixture" <<'PY'
import os
import sys

fixture = os.stat(sys.argv[1])
if os.geteuid() == 0 or fixture.st_uid != os.geteuid():
    raise SystemExit(f"namespace UID is {os.geteuid()}, fixture owner is {fixture.st_uid}")
PY
then
  printf '%s\n' 'offline CLI boundary: namespace identity is not a non-root fixture owner' >&2
  exit 1
fi

trace_has_network() {
  local trace=$1
  # trace=%network emits only network syscalls. Treat every emitted line as an
  # attempt so new syscall names cannot silently evade this gate.
  grep -Eq '(^|[[:space:]])[[:alnum:]_]+\(' "$trace"
}

join_traces() {
  local base=$1 joined=$2 path
  : > "$joined"
  for path in "${base}".*; do
    [[ "$path" != "$joined" ]] || continue
    [[ "$path" =~ \.([0-9]+)$ ]] || continue
    [[ -f "$path" ]] || continue
    cat "$path" >> "$joined"
  done
}

trace_files_exist() {
  local base=$1 path
  for path in "${base}".*; do
    [[ "$path" =~ \.([0-9]+)$ ]] || continue
    [[ -f "$path" ]] && return 0
  done
  return 1
}

namespace_runner="$work/run-in-namespace.sh"
cat >"$namespace_runner" <<'RUNNER'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

trace_base=$1
positive_base=$2
stdout=$3
stderr=$4
fixture=$5
shift 5
[[ "${1:-}" == -- ]] || { printf '%s\n' 'offline CLI boundary: runner argument separator missing' >&2; exit 125; }
shift

python3 - "$fixture" <<'PY'
import os
import sys

fixture = os.stat(sys.argv[1])
uid = os.geteuid()
if uid == 0 or fixture.st_uid != uid:
    raise SystemExit(f"namespace UID is {uid}, fixture owner is {fixture.st_uid}")
PY

set +e
strace -ff -qq -e trace=%network -o "$positive_base" \
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.close()' \
  >/dev/null 2>"${stderr}.positive"
positive_status=$?
set -e
if [[ "$positive_status" -ne 0 ]]; then
  printf 'offline CLI boundary: socket positive control exited %s\n' "$positive_status" >&2
  exit 125
fi

set +e
strace -ff -qq -e trace=%network -o "$trace_base" "$@" >"$stdout" 2>"$stderr"
status=$?
set -e
exit "$status"
RUNNER
chmod 0700 "$namespace_runner"
assert_owned "$namespace_runner"

run_isolated() {
  local label=$1 expected=$2
  shift 2
  local trace_dir="$work/traces/$label"
  local cli_trace_base="$trace_dir/command"
  local positive_trace_base="$trace_dir/control"
  local trace="$trace_dir/command.joined"
  local positive_trace="$trace_dir/control.joined"
  local stdout="$work/output/$label.stdout"
  local stderr="$work/output/$label.stderr"
  local status

  mkdir -m 0700 "$trace_dir"
  : > "$stdout"
  : > "$stderr"

  set +e
  "${namespace_launcher[@]}" "$namespace_runner" "$cli_trace_base" "$positive_trace_base" "$stdout" "$stderr" \
    "$work/namespace-identity-fixture" -- "$@"
  status=$?
  set -e
  join_traces "$cli_trace_base" "$trace"
  join_traces "$positive_trace_base" "$positive_trace"
  if ! trace_files_exist "$positive_trace_base" || ! trace_files_exist "$cli_trace_base"; then
    printf 'offline CLI boundary: %s did not produce both positive-control and CLI trace files\n' "$label" >&2
    exit 1
  fi
  if [[ "$status" -ne "$expected" ]]; then
    printf 'offline CLI boundary: %s returned %s, expected %s\n' "$label" "$status" "$expected" >&2
    cat "$stderr" >&2
    exit 1
  fi
  if ! trace_has_network "$positive_trace"; then
    printf 'offline CLI boundary: %s socket positive control did not prove the observer\n' "$label" >&2
    cat "$positive_trace" >&2
    exit 1
  fi
  if trace_has_network "$trace"; then
    printf 'offline CLI boundary: %s attempted an IP/network syscall\n' "$label" >&2
    cat "$trace" >&2
    exit 1
  fi
  chmod 0600 "$stdout" "$stderr" "${stderr}.positive" "$positive_trace" "$trace"
  assert_owned "$stdout" "$stderr" "${stderr}.positive" "$positive_trace" "$trace"
}

binary="$work/prufyx"
(
  cd "$cli_root"
  CGO_ENABLED=0 GOEXPERIMENT= GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
    GOFLAGS='-mod=vendor -buildvcs=false' \
    go build -trimpath -buildvcs=false -o "$binary" ./cmd/prufyx-community
)
chmod 0755 "$binary"

# The generator uses only vendored code and ephemeral test keys. Its output is
# prepared before the traced CLI matrix; the matrix observes every CLI process
# that consumes the resulting local package and reports.
(
  cd "$cli_root"
  GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
    GOFLAGS='-mod=vendor -buildvcs=false' \
    go run ./examples/community/knowledge/generate-synthetic-packages.go \
    --profile cncf --output "$work/packages" >"$work/generator.json"
)
chmod 0600 "$work/packages/synthetic-manifest.json" \
  "$work/packages/synthetic-root.json" "$work/packages/synthetic-revision-1.tar"
assert_owned "$work/packages/synthetic-manifest.json" "$work/packages/synthetic-root.json" "$work/packages/synthetic-revision-1.tar"

cp "$cli_root/examples/cncf/karmada-input.json" "$work/karmada-input.json"
cp "$cli_root/examples/cncf/proposed-karmada-propagation-policy.json" "$work/karmada-policy.json"
chmod 0600 "$work/karmada-input.json" "$work/karmada-policy.json"
cat >"$work/OFFLINE-BOUNDARY-CILIUM-CANARY-policy.json" <<'JSON'
{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"OFFLINE-BOUNDARY-CILIUM-CANARY"},"spec":{"ingress":[{"fromRequires":[{"matchLabels":{"prufyx.io/offline-boundary":"OFFLINE-BOUNDARY-CILIUM-CANARY"}}]}]}}
JSON
cat >"$work/OFFLINE-BOUNDARY-SYNTHETIC-TEST-ONLY-input.json" <<'JSON'
{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":true}]}]}}
JSON
input="$work/OFFLINE-BOUNDARY-SYNTHETIC-TEST-ONLY-input.json"
cilium_policy="$work/OFFLINE-BOUNDARY-CILIUM-CANARY-policy.json"
chmod 0600 "$input" "$cilium_policy"
assert_owned "$work/karmada-input.json" "$work/karmada-policy.json" "$input" "$cilium_policy"

run_isolated help 0 "$binary" --help
grep -Fq 'prufyx Community' "$work/output/help.stdout"

run_isolated version 0 "$binary" version
jq -e '.result.status == "OK" and .command == "version"' "$work/output/version.stdout" >/dev/null

karmada_digest="sha256:$(sha256_file "$work/karmada-input.json")"
run_isolated check 10 "$binary" check cncf --project karmada --input "$work/karmada-input.json" \
  --input-digest "$karmada_digest" --now 2026-09-09T06:00:00Z --format json
jq -e '.assessment == "UNKNOWN" and .networkUsed == false and .check.claims[0].status == "BLOCKED"' \
  "$work/output/check.stdout" >/dev/null

policy_digest="sha256:$(sha256_file "$work/karmada-policy.json")"
run_isolated prepare 0 "$binary" prepare cncf --project karmada --input "$work/karmada-policy.json" \
  --from 1.18.3 --to 1.19.0 --distribution official_upstream \
  --target-policy-crd-admission required --input-digest "$policy_digest" --format input
cp "$work/output/prepare.stdout" "$work/prepared-input.json"
chmod 0600 "$work/prepared-input.json"
jq -e '.schema == "prufyx.io/operator-declared-constraint-input/v1alpha1"' \
  "$work/prepared-input.json" >/dev/null

cilium_requires_filter='.proposed.components | any((.component == "pkg:github/cilium/cilium") and (.facts | any(.id == "component.cilium.nonempty_requires_fields" and .state == "declared" and .boolValue == true)))'
assert_cilium_requires_filter() {
  jq -e "$cilium_requires_filter" "$1" >/dev/null
}
assert_cilium_requires_filter_rejects() {
  local fixture=$1 stderr_file=$2
  if assert_cilium_requires_filter "$fixture" 2>"$stderr_file"; then
    printf 'offline CLI boundary: Cilium witness filter accepted a negative fixture\n' >&2
    exit 1
  fi
  if [[ -s "$stderr_file" ]]; then
    printf 'offline CLI boundary: Cilium witness filter raised a jq runtime error\n' >&2
    cat "$stderr_file" >&2
    exit 1
  fi
}
cat >"$work/cilium-filter-true.json" <<'JSON'
{"proposed":{"components":[{"component":"pkg:github/cilium/cilium","facts":[{"id":"component.cilium.nonempty_requires_fields","state":"declared","boolValue":true}]}]}}
JSON
cat >"$work/cilium-filter-wrong-component.json" <<'JSON'
{"proposed":{"components":[{"component":"pkg:example/wrong","facts":[{"id":"component.cilium.nonempty_requires_fields","state":"declared","boolValue":true}]}]}}
JSON
cat >"$work/cilium-filter-false.json" <<'JSON'
{"proposed":{"components":[{"component":"pkg:github/cilium/cilium","facts":[{"id":"component.cilium.nonempty_requires_fields","state":"declared","boolValue":false}]}]}}
JSON
cat >"$work/cilium-filter-missing.json" <<'JSON'
{"proposed":{"components":[{"component":"pkg:github/cilium/cilium","facts":[]}]}}
JSON
assert_cilium_requires_filter "$work/cilium-filter-true.json"
for cilium_filter_negative in wrong-component false missing; do
  assert_cilium_requires_filter_rejects "$work/cilium-filter-${cilium_filter_negative}.json" "$work/cilium-filter-${cilium_filter_negative}.stderr"
done

cilium_digest="sha256:$(sha256_file "$cilium_policy")"
run_isolated cilium-prepare 0 "$binary" prepare cncf --project cilium --input "$cilium_policy" \
  --from 1.18.6 --to 1.19.0 --input-digest "$cilium_digest" --format input
cp "$work/output/cilium-prepare.stdout" "$work/cilium-prepared-input.json"
chmod 0600 "$work/cilium-prepared-input.json"
assert_owned "$work/cilium-prepared-input.json"
assert_cilium_requires_filter "$work/cilium-prepared-input.json"

cilium_input_digest="sha256:$(sha256_file "$work/cilium-prepared-input.json")"
run_isolated cilium-check 10 "$binary" check cncf --project cilium --input "$work/cilium-prepared-input.json" \
  --input-digest "$cilium_input_digest" --now 2026-09-09T06:00:00Z --format json
jq -e '.assessment == "UNKNOWN" and .networkUsed == false and any(.check.claims[]; .ruleId == "cilium.nonempty-requires-rejected.1-19" and .status == "BLOCKED")' \
  "$work/output/cilium-check.stdout" >/dev/null

manifest="$work/packages/synthetic-manifest.json"
root_digest=$(jq -er '.bootstrapRoot.digest' "$manifest")
bundle=$(jq -er '.revisions[] | select(.revision == "1") | .bundleDigest' "$manifest")
package_digest=$(jq -er '.revisions[] | select(.revision == "1") | .packageDigest' "$manifest")
chmod 0600 "$manifest" "$work/packages/synthetic-root.json" "$work/packages/synthetic-revision-1.tar"
run_isolated verify 0 "$binary" db verify "$work/packages/synthetic-revision-1.tar" \
  --profile cncf --bootstrap-root "$work/packages/synthetic-root.json" \
  --bootstrap-root-digest "$root_digest" --expected-package-digest "$package_digest" \
  --expected-revision 1 --expected-bundle-digest "$bundle" --format json
jq -e '.status == "VERIFIED" and .purpose == "synthetic_test_only" and .networkUsed == false and .storeUsed == false and .storeChanged == false and .rollbackAgainstStoreChecked == false and .importEligibility == "NOT_EVALUATED"' \
  "$work/output/verify.stdout" >/dev/null
run_isolated import 0 "$binary" db import "$work/packages/synthetic-revision-1.tar" \
  --profile cncf --db-root "$work/store" --bootstrap-root "$work/packages/synthetic-root.json" \
  --bootstrap-root-digest "$root_digest" --expected-revision 1 \
  --expected-bundle-digest "$bundle" --format json
receipt=$(jq -er '.trustReceiptDigest' "$work/output/import.stdout")
jq -e '.status == "IMPORTED" and .trustReceipt.purpose == "synthetic_test_only"' \
  "$work/output/import.stdout" >/dev/null

input_digest="sha256:$(sha256_file "$input")"
run_isolated external-check 11 "$binary" check cncf --project kyverno --input "$input" \
  --input-digest "$input_digest" --knowledge-db "$work/store" \
  --knowledge-revision 1 --knowledge-bundle-digest "$bundle" \
  --knowledge-trust-receipt-digest "$receipt" --format json
jq -e '.status == "CANDIDATE_ONLY" and .assessment == "UNKNOWN" and .knowledge.origin == "external_signed_local"' \
  "$work/output/external-check.stdout" >/dev/null

run_isolated status 0 "$binary" db status --profile cncf --db-root "$work/store" --format json
jq -e '.state == "READY" and .currentEligible == true and .selectedRevision == "1" and .networkChecked == false' \
  "$work/output/status.stdout" >/dev/null

run_isolated replay 11 "$binary" check cncf --project kyverno --input "$input" \
  --input-digest "$input_digest" --knowledge-db "$work/store" \
  --knowledge-revision 1 --knowledge-bundle-digest "$bundle" \
  --knowledge-trust-receipt-digest "$receipt" \
  --replay-report "$work/output/external-check.stdout" --format json
jq -e '.mode == "historical" and .status == "MATCH" and .currentNonRevocation == "not_checked_offline"' \
  "$work/output/replay.stdout" >/dev/null

if grep -R -Fq -e 'OFFLINE-BOUNDARY-SYNTHETIC-TEST-ONLY' -e 'OFFLINE-BOUNDARY-CILIUM-CANARY' \
  "$work/output" "$work/cilium-prepared-input.json"; then
  printf '%s\n' 'offline CLI boundary: synthetic private fixture name crossed the output boundary' >&2
  exit 1
fi

jq -cn \
  --arg binaryDigest "sha256:$(sha256_file "$binary")" \
  --arg namespaceUID "$test_uid" \
  --arg namespaceGID "$test_gid" \
  '{apiVersion:"prufyx.io/offline-cli-boundary-receipt/v1",status:"PASS",platform:"linux",observer:"strace -f trace=%network",isolation:"fresh sudo -n unshare --net per command then setpriv to original fixture owner",sudoUsedForNamespaceOnly:true,namespaceUIDNonRoot:true,namespaceUID:$namespaceUID,namespaceGID:$namespaceGID,fixtureMode:"0600",socketPositiveControl:true,positiveControlPerNamespace:true,commands:["help","version","check","prepare","cilium-prepare","cilium-check","db verify","db import","check --knowledge-db","db status","historical replay"],networkSyscallsObserved:false,explicitUpdateExcluded:true,binaryDigest:$binaryDigest}' >"$work/receipt.json"
if grep -Fq 'OFFLINE-BOUNDARY-CILIUM-CANARY' "$work/receipt.json"; then
  printf '%s\n' 'offline CLI boundary: Cilium canary crossed the receipt boundary' >&2
  exit 1
fi
cat "$work/receipt.json"
