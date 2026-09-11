#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  printf '%s\n' 'Usage: run.sh /absolute/path/to/prufyx /absolute/new/evidence-directory' >&2
}

if (( $# != 2 )); then
  usage
  exit 2
fi
prufyx_binary=$1
evidence_dir=$2
if [[ $prufyx_binary != /* || ! -f $prufyx_binary || ! -x $prufyx_binary || -L $prufyx_binary ]]; then
  printf '%s\n' 'The prufyx binary must be an absolute executable regular file, not a symlink.' >&2
  exit 2
fi
if [[ $evidence_dir != /* || -e $evidence_dir || -L $evidence_dir ]]; then
  printf '%s\n' 'The evidence directory must be an absolute path that does not exist.' >&2
  exit 2
fi

for dependency in kind kubectl jq python3 shasum mktemp find chmod cp grep env sed sort awk date rm cmp mkdir dirname; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$dependency" >&2
    exit 2
  fi
done
jq_version=$(jq --version)
if [[ ! $jq_version =~ ^jq-([0-9]+)\.([0-9]+) ]] || (( BASH_REMATCH[1] < 1 || (BASH_REMATCH[1] == 1 && BASH_REMATCH[2] < 7) )); then
  printf '%s\n' 'jq 1.7 or newer is required.' >&2
  exit 2
fi

ambient_names=$(env | sed 's/=.*//' | LC_ALL=C sort -u)
for proxy_name in HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; do
  if printf '%s\n' "$ambient_names" | grep -Fx "$proxy_name" >/dev/null 2>&1; then
    printf 'Ambient proxy variable %s is present. Review the local routing policy and deliberately unset it or run the collector separately with an explicit --exec-env choice.\n' "$proxy_name" >&2
    exit 2
  fi
done

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cli_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
node_image='kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'
random_suffix=$(python3 -I -S -c 'import secrets; print(secrets.token_hex(8))')
if [[ ! $random_suffix =~ ^[0-9a-f]{16}$ ]]; then
  printf '%s\n' 'Failed to create a unique local proof identity.' >&2
  exit 2
fi
cluster_name="prufyx-proof-$random_suffix"
work=$(mktemp -d /tmp/prufyx-local-kind.XXXXXX)
kubeconfig="$work/kubeconfig"
cluster_owned=false
evidence_owned=false
proof_complete=false

run_kind() {
  KIND_EXPERIMENTAL_PROVIDER=docker kind "$@"
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  cleanup_failed=false
  if [[ $cluster_owned == true ]]; then
    if ! run_kind delete cluster --name "$cluster_name" --kubeconfig "$kubeconfig" >/dev/null 2>&1; then
      cleanup_failed=true
    fi
    if ! cluster_inventory=$(run_kind get clusters 2>/dev/null); then
      cleanup_failed=true
    elif printf '%s\n' "$cluster_inventory" | grep -Fx "$cluster_name" >/dev/null 2>&1; then
      cleanup_failed=true
    fi
  fi
  if [[ $evidence_owned == true && $proof_complete != true ]]; then
    if [[ $evidence_dir == /* && -d $evidence_dir && ! -L $evidence_dir ]]; then
      if ! rm -rf -- "$evidence_dir" || [[ -e $evidence_dir ]]; then
        cleanup_failed=true
      fi
    else
      cleanup_failed=true
    fi
  fi
  if [[ -n $work ]]; then
    if [[ $work == /tmp/prufyx-local-kind.* && -d $work && ! -L $work ]]; then
      if ! rm -rf -- "$work" || [[ -e $work ]]; then
        cleanup_failed=true
      fi
    else
      cleanup_failed=true
    fi
  fi
  if [[ $cleanup_failed == true ]]; then
    printf 'Cleanup failed for the run-owned kind cluster %s; inspect it before continuing.\n' "$cluster_name" >&2
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cluster_inventory=$(run_kind get clusters)
if printf '%s\n' "$cluster_inventory" | grep -Fx "$cluster_name" >/dev/null 2>&1; then
  printf '%s\n' 'Generated kind cluster name already exists; refusing to assume ownership.' >&2
  exit 2
fi
# The name was generated for this run and proved absent. Mark it owned before
# create so the trap also removes a partially-created cluster on create error.
cluster_owned=true
run_kind create cluster --name "$cluster_name" --image "$node_image" --kubeconfig "$kubeconfig" --wait 120s
chmod 600 "$kubeconfig"
test "$(kubectl --kubeconfig "$kubeconfig" config current-context)" = "kind-$cluster_name"
server=$(kubectl --kubeconfig "$kubeconfig" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
case "$server" in
  https://127.0.0.1:*) ;;
  *) printf '%s\n' 'The task kubeconfig did not select a loopback API endpoint.' >&2; exit 1 ;;
esac

kubectl --kubeconfig "$kubeconfig" create namespace prufyx-local-proof >/dev/null
kubectl --kubeconfig "$kubeconfig" apply -f "$script_dir/current-prometheus-agent.yaml" >/dev/null
test "$(kubectl --kubeconfig "$kubeconfig" get deployment prometheus-declaration -n prufyx-local-proof -o jsonpath='{.spec.replicas}')" = 0

mkdir -m 700 "$work/observations"
bash "$cli_root/scripts/kubeconfig-api-snapshot.sh" \
  "$work/observations" --kubeconfig "$kubeconfig" \
  --acknowledge-kubeconfig-exec-risk \
  --include-component-configuration \
  --component-configuration-profile v3 \
  "kind-$cluster_name"
observation_root=$(find "$work/observations" -mindepth 1 -maxdepth 1 -type d -print -quit)
test -n "$observation_root"
captured_at=$(jq -er '.generatedAt' "$observation_root/index.json")
evaluation_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mkdir -m 700 "$evidence_dir"
evidence_owned=true
initial_binary_digest="sha256:$(shasum -a 256 "$prufyx_binary" | awk '{print $1}')"
if ! "$prufyx_binary" version > "$work/prufyx-version.json" 2> "$work/prufyx-version.stderr" || [[ -s $work/prufyx-version.stderr ]]; then
  printf '%s\n' 'The prufyx binary did not emit a clean build-identity envelope.' >&2
  exit 1
fi
if ! jq -e '
  .result.status == "OK" and .result.reasonCode == "build_identity_reported" and
  (.data | type) == "object" and
  (.data.version | type) == "string" and (.data.version | length) <= 128 and
  (.data.sourceRevision | type) == "string" and (.data.sourceRevision | length) <= 128 and
  (.data.sourceTreeDigest | type) == "string" and (.data.sourceTreeDigest | length) <= 128 and
  (.data.allowlistDigest | type) == "string" and (.data.allowlistDigest | length) <= 128 and
  (.data.buildProfile | type) == "string" and (.data.buildProfile | length) <= 128 and
  (.data.goVersion | type) == "string" and (.data.goVersion | test("^go[0-9]+\\.[0-9]+(?:\\.[0-9]+)?(?:[ A-Za-z0-9:._+-]*)?$")) and
  .data.candidateOnly == true and
  (.data | [.version,.sourceRevision,.sourceTreeDigest,.allowlistDigest,.buildProfile,.goVersion] | all(test("[/\\\\]") | not)) and
  ((.data.releaseState == "development" and .data.version == "dev" and .data.sourceRevision == "unbound" and .data.sourceTreeDigest == "unbound" and .data.allowlistDigest == "unbound" and .data.buildProfile == "development") or
   (.data.releaseState == "release" and (.data.version | test("^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")) and (.data.sourceRevision | test("^[0-9a-f]{7,64}$")) and (.data.sourceTreeDigest | test("^sha256:[0-9a-f]{64}$")) and (.data.allowlistDigest | test("^sha256:[0-9a-f]{64}$")) and (.data.buildProfile | test("^linux-(amd64|arm64)$"))))
' "$work/prufyx-version.json" >/dev/null; then
  printf '%s\n' 'The prufyx build-identity envelope is malformed or contains a path.' >&2
  exit 1
fi
jq -S '.data | {version,releaseState,sourceRevision,sourceTreeDigest,allowlistDigest,buildProfile,goVersion,candidateOnly}' "$work/prufyx-version.json" > "$work/prufyx-identity.json"
run_evaluation() {
  proposal_name=$1
  report_name=$2
  expected_exit=$3
  expected_status=$4
  proposal="$work/$proposal_name"
  cp -- "$script_dir/$proposal_name" "$proposal"
  chmod 600 "$proposal"
  proposal_digest="sha256:$(shasum -a 256 "$proposal" | awk '{print $1}')"
  set +e
  "$prufyx_binary" check prometheus-mode \
    --observation-root "$observation_root" \
    --proposed-workload "$proposal" --proposed-digest "$proposal_digest" \
    --captured-at "$captured_at" --now "$evaluation_now" --max-age 2h --format json \
    > "$evidence_dir/$report_name" 2> "$work/$report_name.stderr"
  actual_exit=$?
  set -e
  test "$actual_exit" -eq "$expected_exit"
  test ! -s "$work/$report_name.stderr"
  jq -e --arg status "$expected_status" '.assessment == "UNKNOWN" and .claim.status == $status' "$evidence_dir/$report_name" >/dev/null
}

run_evaluation proposed-preserve-agent.json pass-report.json 0 PASS
run_evaluation proposed-preserve-agent.json pass-replay-report.json 0 PASS
cmp -s "$evidence_dir/pass-report.json" "$evidence_dir/pass-replay-report.json"
run_evaluation proposed-change-to-server.json attention-report.json 11 ATTENTION
run_evaluation proposed-ambiguous.json ambiguous-report.json 11 UNKNOWN

final_binary_digest="sha256:$(shasum -a 256 "$prufyx_binary" | awk '{print $1}')"
if [[ $final_binary_digest != "$initial_binary_digest" ]]; then
  printf '%s\n' 'The prufyx binary changed during the proof.' >&2
  exit 1
fi

replay_digest="sha256:$(shasum -a 256 "$evidence_dir/pass-report.json" | awk '{print $1}')"
jq -n -S \
  --arg schema 'prufyx.io/local-kind-prometheus-proof/v1alpha1' \
  --arg nodeImage "$node_image" --arg capturedAt "$captured_at" --arg evaluatedAt "$evaluation_now" --arg replayDigest "$replay_digest" --arg binaryDigest "$initial_binary_digest" \
  --slurpfile binaryIdentity "$work/prufyx-identity.json" \
  '{schema:$schema,fixture:{classification:"PUBLIC_SYNTHETIC_DECLARATION_ONLY",replicas:0,runtimeClaim:false},cluster:{nodeImage:$nodeImage,taskKubeconfig:true,ambientContextUsed:false},collector:{profile:"producer-v3",capturedAt:$capturedAt},evaluator:{binaryDigest:$binaryDigest,identity:$binaryIdentity[0],unchangedDuringEvaluation:true},evaluation:{evaluatedAt:$evaluatedAt,aggregate:"UNKNOWN",preserveAgent:"PASS",changeToServer:"ATTENTION",multipleContainers:"UNKNOWN",sameInputReplayByteEqual:true,replayDigest:$replayDigest},claimsExcluded:["process startup","applied runtime mode","data and remote-write safety","whole-upgrade compatibility"]}' \
  > "$evidence_dir/receipt.json"

run_kind delete cluster --name "$cluster_name" --kubeconfig "$kubeconfig" >/dev/null
cluster_inventory=$(run_kind get clusters)
if printf '%s\n' "$cluster_inventory" | grep -Fx "$cluster_name" >/dev/null 2>&1; then
  printf '%s\n' 'The run-owned kind cluster remained after deletion.' >&2
  exit 1
fi
cluster_owned=false
if [[ $work != /tmp/prufyx-local-kind.* || ! -d $work || -L $work ]]; then
  printf '%s\n' 'The task directory failed its cleanup boundary check.' >&2
  exit 1
fi
rm -rf -- "$work"
if [[ -e $work || -e $kubeconfig ]]; then
  printf '%s\n' 'The task directory or kubeconfig remained after cleanup.' >&2
  exit 1
fi
work=''
jq -n -S --arg schema 'prufyx.io/local-kind-cleanup-receipt/v1alpha1' '{schema:$schema,clusterAbsent:true,kubeconfigRetained:false}' > "$evidence_dir/cleanup-receipt.json"
(cd "$evidence_dir" && find . -type f ! -name MANIFEST.sha256 -print | LC_ALL=C sort | while IFS= read -r file; do shasum -a 256 "$file"; done > MANIFEST.sha256)
chmod 600 "$evidence_dir"/*
proof_complete=true
printf 'Local declaration proof passed; evidence: %s\n' "$evidence_dir"
