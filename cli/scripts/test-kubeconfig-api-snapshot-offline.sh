#!/usr/bin/env bash
set -Eeuo pipefail

# Offline collector contract tests. A synthetic kubectl shim is used; this
# script never contacts a cluster, invokes a real kubectl, or uses a network.
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
snapshot_script="$script_dir/kubeconfig-api-snapshot.sh"
fake_source="$script_dir/testdata/fake-kubectl.sh"
classifier_source="$script_dir/classify-kubectl-stderr.py"
bounded_runner_source="$script_dir/run-kubectl-bounded.py"

# jq 1.8 accepts optional chaining directly into a field, but jq 1.7 rejects
# that syntax. Keep the documented minimum executable even on newer test hosts.
if grep -Eq '\)\?\.[A-Za-z_]' \
  "$script_dir/component-configuration-adapter.jq" \
  "$script_dir/component-configuration-adapter-v3.jq" \
  "$snapshot_script"; then
  printf '%s\n' 'collector jq contains syntax unavailable in jq 1.7' >&2
  exit 1
fi
bash -n "$snapshot_script"
bash -n "${BASH_SOURCE[0]}"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

fake_bin="$tmp/bin"
mkdir -p "$fake_bin"
cp -- "$fake_source" "$fake_bin/kubectl"
chmod 700 "$fake_bin/kubectl"
export FAKE_KUBECTL_CALL_LOG=''
snapshot_exec_env_args=(--exec-env FAKE_KUBECTL_MODE --exec-env FAKE_KUBECTL_CALL_LOG)
synthetic_config_file="$tmp/kubeconfig"
python3 - "$synthetic_config_file" <<'PY'
import os
import sys

path = sys.argv[1]
with open(path, "w", encoding="utf-8") as handle:
    handle.write("synthetic kubeconfig\n")
os.chmod(path, 0o600)
PY

assert_contains() {
  local pattern=$1
  local file=$2
  grep -F "$pattern" "$file" >/dev/null || {
    printf 'offline snapshot test missing expected fixed value: %s\n' "$pattern" >&2
    exit 1
  }
}

assert_no_sensitive_output() {
  local root=$1
  local stdout_file=$2
  local stderr_file=$3
  if grep -F 'SENSITIVE_FAKE_KUBECTL_STDERR' "$stdout_file" "$stderr_file" >/dev/null 2>&1 || \
    grep -R 'SENSITIVE_FAKE_KUBECTL_STDERR' "$root" >/dev/null 2>&1; then
    printf '%s\n' 'offline snapshot test found fake sensitive stderr in an output' >&2
    exit 1
  fi
}

assert_no_hidden_fragments() {
  local root=$1
  if find "$root" -type f \( -name '.*.tmp*' -o -name '.*.page.*' -o -name '.*.items.*' -o -name '.*.stderr-class*' -o -name '.component-configuration.ndjson' -o -name '.component-configuration-omissions.ndjson' \) -print | grep . >/dev/null 2>&1; then
    printf '%s\n' 'offline snapshot test found a hidden temporary/component fragment' >&2
    exit 1
  fi
}

component_code_for() {
  case "$1" in
    kubernetes_api_read_failed) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED' ;;
    kubernetes_api_read_failed_authentication_exec_plugin_failure) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHENTICATION_EXEC_PLUGIN_FAILURE' ;;
    kubernetes_api_read_failed_unauthorized) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNAUTHORIZED' ;;
    kubernetes_api_read_failed_authorization_rbac_forbidden) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN' ;;
    kubernetes_api_read_failed_invalid_kubeconfig_context) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_INVALID_KUBECONFIG_CONTEXT' ;;
    kubernetes_api_read_failed_tls_certificate) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TLS_CERTIFICATE' ;;
    kubernetes_api_read_failed_dns) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_DNS' ;;
    kubernetes_api_read_failed_transport_timeout_unreachable) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TRANSPORT_TIMEOUT_UNREACHABLE' ;;
    kubernetes_api_read_failed_unsupported_not_found_api) printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNSUPPORTED_NOT_FOUND_API' ;;
    *) return 1 ;;
  esac
}

# The explicit safe-output negotiation must remove raw image references before
# the adapter payload can be written to the collector's temporary file. The
# default/false path is covered byte-for-byte by the focused adapter test.
safe_adapter_input="$tmp/safe-component-input.json"
safe_adapter_output="$tmp/.safe-component-payload.tmp"
jq -n '{items: [{kind: "Deployment", spec: {template: {spec: {containers: [{image: "quay.io/prometheus/prometheus:v3.14.0", args: ["--log.level=info"]}, {image: "registry.private.invalid/customer/secret:9.9.9", args: ["--password=must-not-retain"]}]}}}}]}' > "$safe_adapter_input"
jq -S \
  --argjson registry "$(jq -c . "$script_dir/component-configuration-adapters.json")" \
  --arg safeOutput true \
  -f "$script_dir/component-configuration-adapter.jq" "$safe_adapter_input" > "$safe_adapter_output"
jq -e '.images == [] and (.publicImages | any(.componentId == "pkg:oci/prometheus/prometheus")) and (.configuration | length == 1)' "$safe_adapter_output" >/dev/null
if grep -E 'registry\.private\.invalid|must-not-retain|password' "$safe_adapter_output" >/dev/null 2>&1; then
  printf '%s\n' 'offline safe-output payload retained a raw private image or token' >&2
  exit 1
fi
rm -f -- "$safe_adapter_output"
test ! -e "$safe_adapter_output"

run_snapshot() {
  local mode=$1
  local output_root=$2
  local stdout_file=$3
  local stderr_file=$4
  set +e
  PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE="$mode" \
    "$snapshot_script" "$output_root" --kubeconfig "$synthetic_config_file" \
      --acknowledge-kubeconfig-exec-risk --include-component-configuration \
      --allow-partial "${snapshot_exec_env_args[@]}" synthetic-context >"$stdout_file" 2>"$stderr_file"
  local status=$?
  set -e
  if (( status != 0 )); then
    printf 'offline snapshot command failed: mode=%s status=%s\n' "$mode" "$status" >&2
    if [[ -s $stderr_file ]]; then
      printf '%s\n' '--- captured stderr ---' >&2
      sed -n '1,160p' "$stderr_file" >&2
      printf '%s\n' '--- end captured stderr ---' >&2
    else
      printf '%s\n' '(captured stderr was empty)' >&2
    fi
    return "$status"
  fi
}

run_case() {
  local mode=$1
  local expected_code=$2
  local expected_count=$3
  local output_root="$tmp/out-$mode"
  local stdout_file="$tmp/$mode.stdout"
  local stderr_file="$tmp/$mode.stderr"
  mkdir -p "$output_root"

  run_snapshot "$mode" "$output_root" "$stdout_file" "$stderr_file"

  local run_dir
  run_dir=$(printf '%s\n' "$output_root"/kubeconfig-api-snapshot-* | tail -1)
  local context_dir="$run_dir/000"
  test -d "$context_dir"
  test "$(jq -r '.crdPaginationPolicy.version' "$context_dir/snapshot-metadata.json")" = crd-pagination-policy-v1
  test "$(jq -r '.crdPaginationPolicy.endpoint' "$context_dir/snapshot-metadata.json")" = /apis/apiextensions.k8s.io/v1/customresourcedefinitions
  test "$(jq -r '.crdPaginationPolicy.profile' "$context_dir/snapshot-metadata.json")" = raw-v1-continue
  test "$(jq -r '.crdPaginationPolicy.pageLimit' "$context_dir/snapshot-metadata.json")" -eq 50
  test "$(jq -r '.crdPaginationPolicy.maxPages' "$context_dir/snapshot-metadata.json")" -eq 64
  test "$(jq -r '.crdPaginationPolicy.maxItems' "$context_dir/snapshot-metadata.json")" -eq 10000
  test "$(jq -r '.crdPaginationPolicy.maxVersions' "$context_dir/snapshot-metadata.json")" -eq 100000
  test "$(jq -r '.crdPaginationPolicy.maxProjectedBytes' "$context_dir/snapshot-metadata.json")" -eq $((4 * 1024 * 1024))
  test "$(jq -r '.crdPaginationPolicy.overallTimeoutSeconds' "$context_dir/snapshot-metadata.json")" -eq 120
  test "$(jq -r '.crdPaginationPolicy.localJsonStageDigest' "$context_dir/snapshot-metadata.json")" = sha256:b99c2719f934d8a07d5f8785817bc1ee8bc85712187d0b38d5c4c3db75123127
  test "$(jq -r '.crdPaginationPolicy.pageProjectionDigest' "$context_dir/snapshot-metadata.json")" = sha256:7ab5c4ae22b27786195261bf3d28c9d1707d1c1d577a7c9a27b6e0509825b664
  test "$(jq -r '.crdPaginationPolicy.finalMergeDigest' "$context_dir/snapshot-metadata.json")" = sha256:026a6a98d5a3dd748bbcb8ca5540739715d2191ff5e1203182267bd7d0ed0b32
  local actual_count
  actual_count=$(wc -l < "$context_dir/omissions.tsv" | tr -d ' ')
  if [[ $actual_count -ne $expected_count ]]; then
    printf 'offline snapshot omission count mismatch: mode=%s expected=%s actual=%s\n' "$mode" "$expected_count" "$actual_count" >&2
    sed -n '1,120p' "$context_dir/omissions.tsv" >&2
    return 1
  fi
  if [[ $expected_count -eq 0 ]]; then
    if [[ ! -f $context_dir/server-version.json || ! -f $context_dir/core-api-versions.json ]]; then
      printf 'offline snapshot success artifacts missing: mode=%s server=%s core=%s\n' "$mode" "$(test -f "$context_dir/server-version.json"; echo $?)" "$(test -f "$context_dir/core-api-versions.json"; echo $?)" >&2
      return 1
    fi
  else
    assert_contains "${expected_code}" "$context_dir/omissions.tsv"
    local component_code=''
    if component_code=$(component_code_for "$expected_code"); then
      assert_contains "$component_code" "$context_dir/component-configuration-surface.json"
    fi
    assert_contains "Failure histogram:" "$stderr_file"
    assert_contains '"kubectlStderrClassifierAuthority": "heuristic_local_diagnostic_not_proof"' "$context_dir/snapshot-metadata.json"
    assert_contains '"evaluationEligible": false' "$context_dir/snapshot-metadata.json"
    if grep -F '"componentId"' "$context_dir/component-configuration-surface.json" >/dev/null 2>&1; then
      printf '%s\n' 'offline snapshot test found a component identity on a failed read' >&2
      exit 1
    fi
  fi
  if [[ $mode == kubernetes-api-read-failed ]]; then
    assert_contains 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED' "$context_dir/component-configuration-surface.json"
    assert_contains 'all declared API reads failed at kubernetes_api_read_failed' "$stderr_file"
  elif [[ $mode == auth-no-stdout || $mode == timeout-no-stdout ]]; then
    # These fake kubectl modes emit only canonical stderr and a nonzero status.
    # The empty stdout path must retain the sanitized API class rather than
    # being relabeled strict_json_rejected by the downstream validator.
    test ! -f "$context_dir/server-version.json"
    test ! -f "$context_dir/core-api-versions.json"
    assert_contains "server-version.json" "$context_dir/omissions.tsv"
  elif [[ $mode == workload-filter-rejected ]]; then
    assert_contains 'COMPONENT_CONFIGURATION_PROJECTION_FILTER_REJECTED' "$context_dir/component-configuration-surface.json"
  fi
  assert_no_sensitive_output "$run_dir" "$stdout_file" "$stderr_file"
  assert_no_hidden_fragments "$context_dir"
}

# Context identities are stable only inside one observation run. The run key
# is random and discarded, so a known context cannot be recovered by comparing
# the output to an ordinary SHA-256 dictionary and separate runs cannot join.
context_identity_root="$tmp/context-identity"
context_identity_repeat_root="$tmp/context-identity-repeat"
mkdir -p "$context_identity_root" "$context_identity_repeat_root"
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=success \
  "$snapshot_script" "$context_identity_root" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --allow-partial "${snapshot_exec_env_args[@]}" \
  dictionary-context dictionary-context >"$tmp/context-identity.stdout" 2>"$tmp/context-identity.stderr"
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=success \
  "$snapshot_script" "$context_identity_repeat_root" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --allow-partial "${snapshot_exec_env_args[@]}" \
  dictionary-context >"$tmp/context-identity-repeat.stdout" 2>"$tmp/context-identity-repeat.stderr"
context_identity_run=$(printf '%s\n' "$context_identity_root"/kubeconfig-api-snapshot-* | tail -1)
context_identity_repeat_run=$(printf '%s\n' "$context_identity_repeat_root"/kubeconfig-api-snapshot-* | tail -1)
first_context_hash=$(jq -r '.contexts[0].contextHash' "$context_identity_run/index.json")
same_run_context_hash=$(jq -r '.contexts[1].contextHash' "$context_identity_run/index.json")
different_run_context_hash=$(jq -r '.contexts[0].contextHash' "$context_identity_repeat_run/index.json")
ordinary_context_hash=$(printf '%s' dictionary-context | shasum -a 256 | awk '{print "sha256:" $1}')
[[ $first_context_hash =~ ^sha256:[0-9a-f]{64}$ ]]
test "$first_context_hash" = "$same_run_context_hash"
test "$first_context_hash" != "$different_run_context_hash"
test "$first_context_hash" != "$ordinary_context_hash"
jq -e '.disclosure | any(.[]; contains("randomized per-run pseudonym") and contains("match only within this observation run") and contains("cross-run replay is intentionally unavailable"))' "$context_identity_run/000/snapshot-metadata.json" >/dev/null

# Pod status collection retains exact public identities only. A private image,
# a private runtime imageID attached to a public image, and unrelated raw Pod
# fields must not cross the jq projection boundary.
pod_privacy_root="$tmp/pod-privacy"
mkdir -p "$pod_privacy_root"
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=pod-private-images \
  "$snapshot_script" "$pod_privacy_root" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --include-pod-status-images --allow-partial \
  "${snapshot_exec_env_args[@]}" synthetic-context >"$tmp/pod-privacy.stdout" 2>"$tmp/pod-privacy.stderr"
pod_privacy_run=$(printf '%s\n' "$pod_privacy_root"/kubeconfig-api-snapshot-* | tail -1)
jq -e '. == [{componentId:"pkg:oci/prometheus/prometheus",observationCount:1,observationState:"active",observedVersion:"v2.55.1",versionConflict:false,versionScheme:"tag"}]' "$pod_privacy_run/000/deployment-images.json" >/dev/null
jq -e '
  any(.[]; .imageIdentity == "PRIVATE_IMAGE_IDENTITY_OMITTED" and .observedVersion == null and .versionScheme == "unknown" and .publicImageIDBound == false) and
  any(.[]; .imageIdentity == "pkg:oci/prometheus/prometheus" and .observedVersion == "v2.55.1" and .versionScheme == "tag" and .publicImageIDBound == true) and
  any(.[]; .imageIdentity == "pkg:oci/prometheus/prometheus" and .observedVersion == "v2.55.1" and .versionScheme == "tag" and .publicImageIDBound == false) and
  all(.[]; .imageIdentity == "PRIVATE_IMAGE_IDENTITY_OMITTED" or .imageIdentity == "pkg:oci/prometheus/prometheus")
' "$pod_privacy_run/000/pod-status-images.json" >/dev/null
if grep -R -E 'private\.invalid|PRIVATE_(OBJECT_NAME|COMMAND|ENV|TAG|CONTROL)_NEVER_RETAIN|PRIVATE_(TAG|CONTROL)_CANARY|docker\.io/prom/prometheus' "$pod_privacy_run" "$tmp/pod-privacy.stdout" "$tmp/pod-privacy.stderr" >/dev/null 2>&1; then
  printf '%s\n' 'pod privacy projection retained a private image, object, command, or environment canary' >&2
  exit 1
fi

# Kubectl and its exec plugin receive a closed environment. Baseline execution
# variables and explicitly selected plugin/proxy variables remain available;
# unrelated ambient variables and Kubernetes service injection do not.
environment_root="$tmp/environment"
environment_home="$tmp/environment-home"
environment_tmpdir="$tmp/environment-tmp"
mkdir -p "$environment_root" "$environment_home" "$environment_tmpdir"
(
  readonly AMBIENT_READONLY_SENTINEL=readonly-must-not-flow
  export AMBIENT_READONLY_SENTINEL
  SYNTHETIC_AMBIENT_FUNCTION() { :; }
  export -f SYNTHETIC_AMBIENT_FUNCTION
  PATH="$fake_bin:$PATH" HOME="$environment_home" USER=synthetic-user TMPDIR="$environment_tmpdir" \
    FAKE_KUBECTL_MODE=environment-probe \
    AMBIENT_PRIVATE_SENTINEL=must-not-flow KUBERNETES_SERVICE_HOST=192.0.2.10 \
    AWS_PROFILE=synthetic-profile HTTPS_PROXY=http://proxy.invalid:8443 \
    "$snapshot_script" "$environment_root" --kubeconfig "$synthetic_config_file" \
    --acknowledge-kubeconfig-exec-risk --allow-partial "${snapshot_exec_env_args[@]}" \
    --exec-env AWS_PROFILE --exec-env HTTPS_PROXY synthetic-context \
    >"$tmp/environment.stdout" 2>"$tmp/environment.stderr"
)
jq -e '.ambientPrivate == "absent" and .ambientReadonly == "absent" and .exportedFunction == "absent" and .kubernetesService == "absent" and .explicitPlugin == "present" and .explicitProxy == "present" and .baseline == "present" and .kubeconfig == "exact"' "$synthetic_config_file.environment-probe.json" >/dev/null
if grep -R -E 'must-not-flow|readonly-must-not-flow|synthetic-profile|proxy\.invalid|192\.0\.2\.10' "$environment_root" "$tmp/environment.stdout" "$tmp/environment.stderr" >/dev/null 2>&1; then
  printf '%s\n' 'environment hardening test retained an environment value' >&2
  exit 1
fi

set +e
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=success HTTPS_PROXY=http://proxy.invalid:8443 \
  "$snapshot_script" "$tmp/proxy-refusal" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk "${snapshot_exec_env_args[@]}" synthetic-context \
  >"$tmp/proxy-refusal.stdout" 2>"$tmp/proxy-refusal.stderr"
proxy_refusal_status=$?
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=success \
  "$snapshot_script" "$tmp/missing-env-refusal" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk "${snapshot_exec_env_args[@]}" --exec-env ABSENT_SYNTHETIC_VARIABLE synthetic-context \
  >"$tmp/missing-env-refusal.stdout" 2>"$tmp/missing-env-refusal.stderr"
missing_env_status=$?
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=success BASH_ENV=/dev/null \
  "$snapshot_script" "$tmp/loader-env-refusal" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk "${snapshot_exec_env_args[@]}" --exec-env BASH_ENV synthetic-context \
  >"$tmp/loader-env-refusal.stdout" 2>"$tmp/loader-env-refusal.stderr"
loader_env_status=$?
set -e
test "$proxy_refusal_status" -eq 2
test "$missing_env_status" -eq 2
test "$loader_env_status" -eq 2
test ! -e "$tmp/proxy-refusal"
test ! -e "$tmp/missing-env-refusal"
test ! -e "$tmp/loader-env-refusal"
assert_contains 'requires explicit --exec-env HTTPS_PROXY' "$tmp/proxy-refusal.stderr"
assert_contains 'was not present in the invoking environment' "$tmp/missing-env-refusal.stderr"
assert_contains 'can alter executable loading' "$tmp/loader-env-refusal.stderr"
if grep -F 'proxy.invalid' "$tmp/proxy-refusal.stdout" "$tmp/proxy-refusal.stderr" >/dev/null 2>&1; then
  printf '%s\n' 'proxy refusal printed a discarded proxy value' >&2
  exit 1
fi

run_case success success 0
run_case kubernetes-api-read-failed kubernetes_api_read_failed 20
run_case auth-exec-plugin kubernetes_api_read_failed_authentication_exec_plugin_failure 20
run_case auth-no-stdout kubernetes_api_read_failed_authentication_exec_plugin_failure 20
run_case unauthorized kubernetes_api_read_failed_unauthorized 20
run_case rbac-forbidden kubernetes_api_read_failed_authorization_rbac_forbidden 20
run_case invalid-kubeconfig-context kubernetes_api_read_failed_invalid_kubeconfig_context 20
run_case tls-certificate kubernetes_api_read_failed_tls_certificate 20
run_case dns kubernetes_api_read_failed_dns 20
run_case transport-timeout-unreachable kubernetes_api_read_failed_transport_timeout_unreachable 20
run_case timeout-no-stdout kubernetes_api_read_failed_transport_timeout_unreachable 20
run_case unsupported-not-found-api kubernetes_api_read_failed_unsupported_not_found_api 20
run_case invalid-json strict_json_rejected 1
run_case oversized-json strict_json_rejected 1
run_case projection-filter-rejected projection_filter_rejected 1
run_case workload-filter-rejected projection_filter_rejected 1

# Keep the server-version fixtures byte-exact at the fake collector boundary;
# importer acceptance/rejection is covered by the Go current-bundle E2E test.
run_server_version_case() {
  local mode=$1
  local expression=$2
  local output_root="$tmp/out-$mode"
  local stdout_file="$tmp/$mode.stdout"
  local stderr_file="$tmp/$mode.stderr"
  mkdir -p "$output_root"
  run_snapshot "$mode" "$output_root" "$stdout_file" "$stderr_file"
  local run_dir
  run_dir=$(printf '%s\n' "$output_root"/kubeconfig-api-snapshot-* | tail -1)
  local context_dir="$run_dir/000"
  jq -e "$expression" "$context_dir/server-version.json" >/dev/null
  assert_no_sensitive_output "$run_dir" "$stdout_file" "$stderr_file"
  assert_no_hidden_fragments "$context_dir"
}

run_server_version_case server-version-boringcrypto '.goVersion == "go1.25.11 X:boringcrypto"'
run_server_version_case server-version-clean '.goVersion == "go1.25.11"'
run_server_version_case server-version-malicious-suffix '.goVersion == "go1.25.11 X:evil"'
run_server_version_case server-version-malicious-core-suffix '.goVersion == "go1.25.11evil"'
run_server_version_case server-version-malicious-core-suffix-boringcrypto '.goVersion == "go1.25.11evil X:boringcrypto"'
run_server_version_case server-version-malicious-build-suffix '.goVersion == "go1.25.11+evil"'
run_server_version_case server-version-malicious-fourth-segment '.goVersion == "go1.25.11.4"'
run_server_version_case server-version-malicious-boringcrypto-suffix '.goVersion == "go1.25.11 X:boringcrypto:evil"'
run_server_version_case server-version-newline '.goVersion == "go1.25.11\nX:boringcrypto"'
run_server_version_case server-version-nul '(.goVersion | index("\u0000")) != null'
run_server_version_case server-version-long '.goVersion | length > 4096'

run_component_identity_case() {
  local mode=$1
  local expected_omissions=$2
  local output_root="$tmp/out-$mode"
  local stdout_file="$tmp/$mode.stdout"
  local stderr_file="$tmp/$mode.stderr"
  mkdir -p "$output_root"
  run_snapshot "$mode" "$output_root" "$stdout_file" "$stderr_file"
  local run_dir
  run_dir=$(printf '%s\n' "$output_root"/kubeconfig-api-snapshot-* | tail -1)
  local context_dir="$run_dir/000"
  test "$(wc -l < "$context_dir/omissions.tsv" | tr -d ' ')" -eq "$expected_omissions"
  if [[ $mode == component-rbac-* ]]; then
    jq -e '.components[] | select(.componentId == "pkg:oci/cert-manager/cert-manager") | (.predicates["component.cert_manager.rbac_acme_api_group"] == false and .predicates["component.cert_manager.rbac_cert_manager_api_groups"] == false and .predicates["component.cert_manager.rbac_serviceaccounts_token_create"] == false)' "$context_dir/component-configuration-surface.json" >/dev/null
  fi
  if [[ $mode == component-monitor-* ]]; then
    jq -e '((.components | map(select(.componentId == "pkg:oci/cert-manager/cert-manager")) | length) == 1) and (.components[] | select(.componentId == "pkg:oci/cert-manager/cert-manager") | (.predicates | keys | all(test("^component\\.cert_manager\\.metrics_") | not))) and any(.omissions[]?; .code == "COMPONENT_CONFIGURATION_API_UNAVAILABLE" and (.reason | test("target workload identity")))' "$context_dir/component-configuration-surface.json" >/dev/null
  fi
}

# Exact roleRef/subject/resource joins reject an unrelated namespace, a
# same-name Role of the wrong kind, an unrelated ServiceAccount, and unrelated
# resources. Monitor labels/path alone are also insufficient.
run_component_identity_case component-rbac-unrelated-namespace 0
run_component_identity_case component-rbac-same-name-role 0
run_component_identity_case component-rbac-unrelated-sa 0
run_component_identity_case component-rbac-unrelated-resource 0
run_component_identity_case component-monitor-label-collision 0
run_component_identity_case component-monitor-unrelated-target 0

# Producer v3 changes only the local projection contract. It must issue the
# exact same Kubernetes reads as v2, retain only the two closed Prometheus
# predicates/public platform digest, and discard workload names and raw args.
run_profile_snapshot() {
  local profile=$1
  local output_root=$2
  local call_log=$3
  local stdout_file="$tmp/profile-$profile.stdout"
  local stderr_file="$tmp/profile-$profile.stderr"
  mkdir -p "$output_root"
  PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=component-v3-prom FAKE_KUBECTL_CALL_LOG="$call_log" \
    "$snapshot_script" "$output_root" --kubeconfig "$synthetic_config_file" \
      --acknowledge-kubeconfig-exec-risk --include-component-configuration \
      --component-configuration-profile "$profile" --allow-partial "${snapshot_exec_env_args[@]}" synthetic-context \
    >"$stdout_file" 2>"$stderr_file"
}

v2_profile_root="$tmp/out-profile-v2"
v3_profile_root="$tmp/out-profile-v3"
v2_call_log="$tmp/profile-v2.calls"
v3_call_log="$tmp/profile-v3.calls"
run_profile_snapshot v2 "$v2_profile_root" "$v2_call_log"
run_profile_snapshot v3 "$v3_profile_root" "$v3_call_log"
cmp -s "$v2_call_log" "$v3_call_log"
v3_profile_run=$(printf '%s\n' "$v3_profile_root"/kubeconfig-api-snapshot-* | tail -1)
v3_profile_context="$v3_profile_run/000"
jq -e '
  .metadata.schemaVersion == "1.1.0" and
  .metadata.adapterVersion == "component-configuration-adapter-v3" and
  .metadata.registryVersion == "v3" and
  .metadata.registryDigest == "sha256:c2631adc13f82d35f20518736a1816d1a1e8155c69b2d0d805f4dd275678d186" and
  .metadata.filterDigest == "sha256:cf9fbb75cdb9a3ec95b8b79e4ffda7d3d905e07f0de707569a16dc827f65bd2e" and
  .metadata.aggregateDigest == "sha256:37e08d478632074dff7930898bc1c1831f4a18e34d2f45eee3516c2b5b5b679c" and
  (.components | map(select(.componentId == "pkg:oci/prometheus/prometheus")) == [{
    componentId:"pkg:oci/prometheus/prometheus",
    observationCount:1,
    observationState:"observed",
    observedVersion:"2.55.1",
    predicateEvidence:[
      {evidenceClass:"declared_container_context_v1",predicateId:"component.prometheus.agent_mode",sourceRole:"server",state:"observed"},
      {evidenceClass:"declared_container_context_v1",predicateId:"component.prometheus.image_digest",sourceRole:"server",state:"observed"}
    ],
    predicates:{"component.prometheus.agent_mode":true,"component.prometheus.image_digest":"sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"},
    roles:["server"],versionConflict:false,versionScheme:"tag"
  }])' "$v3_profile_context/component-configuration-surface.json" >/dev/null
test "$(jq -r '.componentConfigurationAdapterVersion' "$v3_profile_context/snapshot-metadata.json")" = component-configuration-adapter-v3
test "$(jq -r '.componentConfigurationRegistryVersion' "$v3_profile_context/snapshot-metadata.json")" = v3
if grep -R -E 'PRUFYX_SYNTHETIC_(PRIVATE_WORKLOAD|SECRET)_NEVER_RETAIN|synthetic-private-token' "$v3_profile_run" "$tmp/profile-v3.stdout" "$tmp/profile-v3.stderr" >/dev/null 2>&1; then
  printf '%s\n' 'v3 offline collector retained a workload name or raw argument canary' >&2
  exit 1
fi
assert_no_hidden_fragments "$v3_profile_context"

cross_kind_root="$tmp/out-profile-v3-cross-kind"
cross_kind_stdout="$tmp/profile-v3-cross-kind.stdout"
cross_kind_stderr="$tmp/profile-v3-cross-kind.stderr"
mkdir -p "$cross_kind_root"
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=component-v3-prom-cross-kind \
  "$snapshot_script" "$cross_kind_root" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --include-component-configuration \
  --component-configuration-profile v3 --allow-partial "${snapshot_exec_env_args[@]}" synthetic-context \
  >"$cross_kind_stdout" 2>"$cross_kind_stderr"
cross_kind_run=$(printf '%s\n' "$cross_kind_root"/kubeconfig-api-snapshot-* | tail -1)
cross_kind_context="$cross_kind_run/000"
jq -e '(.components | all(.componentId != "pkg:oci/prometheus/prometheus")) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS") and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE") and (tostring | test("internalParticipationState|PRUFYX_SYNTHETIC") | not)' "$cross_kind_context/component-configuration-surface.json" >/dev/null
if grep -R -E 'PRUFYX_SYNTHETIC_(PRIVATE_WORKLOAD|SECRET)_NEVER_RETAIN|internalParticipationState' "$cross_kind_run" "$cross_kind_stdout" "$cross_kind_stderr" >/dev/null 2>&1; then
  printf '%s\n' 'v3 cross-kind aggregate exposed an internal marker or private canary' >&2
  exit 1
fi
assert_no_hidden_fragments "$cross_kind_context"

read_failed_root="$tmp/out-profile-v3-statefulset-forbidden"
read_failed_stdout="$tmp/profile-v3-statefulset-forbidden.stdout"
read_failed_stderr="$tmp/profile-v3-statefulset-forbidden.stderr"
mkdir -p "$read_failed_root"
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=component-v3-prom-statefulset-forbidden \
  "$snapshot_script" "$read_failed_root" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --include-component-configuration \
  --component-configuration-profile v3 --allow-partial "${snapshot_exec_env_args[@]}" synthetic-context \
  >"$read_failed_stdout" 2>"$read_failed_stderr"
read_failed_run=$(printf '%s\n' "$read_failed_root"/kubeconfig-api-snapshot-* | tail -1)
read_failed_context="$read_failed_run/000"
jq -e '(.components | all(.componentId != "pkg:oci/prometheus/prometheus")) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN") and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS") and (tostring | test("internalParticipationState|PRUFYX_SYNTHETIC") | not)' "$read_failed_context/component-configuration-surface.json" >/dev/null
if grep -R -E 'PRUFYX_SYNTHETIC_(PRIVATE_WORKLOAD|SECRET)_NEVER_RETAIN|internalParticipationState' "$read_failed_run" "$read_failed_stdout" "$read_failed_stderr" >/dev/null 2>&1; then
  printf '%s\n' 'v3 read-failure aggregate exposed an internal marker or private canary' >&2
  exit 1
fi
assert_no_hidden_fragments "$read_failed_context"

for profile_case in missing-include unsupported duplicate; do
  profile_root="$tmp/profile-rejected-$profile_case"
  profile_stdout="$tmp/profile-rejected-$profile_case.stdout"
  profile_stderr="$tmp/profile-rejected-$profile_case.stderr"
  profile_args=(--kubeconfig "$synthetic_config_file" --acknowledge-kubeconfig-exec-risk)
  if [[ $profile_case == missing-include ]]; then
    profile_args+=(--component-configuration-profile v3 synthetic-context)
  elif [[ $profile_case == unsupported ]]; then
    profile_args+=(--include-component-configuration --component-configuration-profile v4 synthetic-context)
  else
    profile_args+=(--include-component-configuration --component-configuration-profile v3 --component-configuration-profile v3 synthetic-context)
  fi
  set +e
  PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=component-v3-prom "$snapshot_script" "$profile_root" "${snapshot_exec_env_args[@]}" "${profile_args[@]}" >"$profile_stdout" 2>"$profile_stderr"
  profile_status=$?
  set -e
  test "$profile_status" -eq 2
  test ! -e "$profile_root"
done

run_crd_case() {
  local mode=$1
  local expected_code=$2
  local expected_items=$3
  local output_root="$tmp/out-$mode"
  local stdout_file="$tmp/$mode.stdout"
  local stderr_file="$tmp/$mode.stderr"
  mkdir -p "$output_root"
  run_snapshot "$mode" "$output_root" "$stdout_file" "$stderr_file"
  local run_dir
  run_dir=$(printf '%s\n' "$output_root"/kubeconfig-api-snapshot-* | tail -1)
  local context_dir="$run_dir/000"
  test -d "$context_dir"
  if [[ $expected_code == success ]]; then
    test "$(wc -l < "$context_dir/omissions.tsv" | tr -d ' ')" -eq 0
    test -f "$context_dir/crd-api-surface.json"
    test "$(jq 'length' "$context_dir/crd-api-surface.json")" -eq "$expected_items"
    test "$(jq -c 'map([.group, .plural])' "$context_dir/crd-api-surface.json")" = "$(jq -c 'map([.group, .plural]) | sort' "$context_dir/crd-api-surface.json")"
    test "$(jq -c 'map(.versions | map(.name))' "$context_dir/crd-api-surface.json")" = "$(jq -c 'map(.versions | map(.name) | sort)' "$context_dir/crd-api-surface.json")"
  else
    test "$(wc -l < "$context_dir/omissions.tsv" | tr -d ' ')" -eq 1
    assert_contains "$expected_code" "$context_dir/omissions.tsv"
    test ! -f "$context_dir/crd-api-surface.json"
    assert_contains 'Failure histogram:' "$stderr_file"
  fi
  assert_no_sensitive_output "$run_dir" "$stdout_file" "$stderr_file"
  assert_no_hidden_fragments "$context_dir"
}

run_crd_case crd-multipage success 4
run_crd_case crd-large-pages success 20
run_crd_case crd-empty-page success 1
run_crd_case crd-duplicate-key strict_json_rejected 0
run_crd_case crd-malformed-page strict_json_rejected 0
run_crd_case crd-duplicate-version projection_filter_rejected 0
run_crd_case crd-invalid-nested-shape projection_filter_rejected 0
run_crd_case crd-page-oversized strict_json_rejected 0
run_crd_case crd-resource-version-mismatch pipeline_failed 0
run_crd_case crd-aggregate-bytes projection_filter_rejected 0
run_crd_case crd-repeated-continue pipeline_failed 0
run_crd_case crd-malformed-token projection_filter_rejected 0
run_crd_case crd-oversized-token projection_filter_rejected 0
run_crd_case crd-max-items projection_filter_rejected 0
run_crd_case crd-max-pages pipeline_failed 0
run_crd_case crd-api-failure kubernetes_api_read_failed_unauthorized 0

crd_status_function=$(awk '/^classify_crd_pipeline_status\(\)/{inside=1} inside{print} inside && /^}/{exit}' "$snapshot_script")
eval "$crd_status_function"
test "$(classify_crd_pipeline_status 124 125)" = kubernetes_api_read_failed
test "$(classify_crd_pipeline_status 42 125)" = kubernetes_api_read_failed
test "$(classify_crd_pipeline_status 125 0)" = pipeline_failed
test "$(classify_crd_pipeline_status 0 125)" = pipeline_failed

local_stage_success="$tmp/local-stage-success.json"
FAKE_KUBECTL_MODE=success bash "$fake_source" --raw=/apis/apiextensions.k8s.io/v1/customresourcedefinitions \
  | python3 "$script_dir/run-local-json-stage-bounded.py" --timeout-seconds 5 --strict-json "$script_dir/reject-duplicate-json.py" --jq-filter "$script_dir/crd-page-projection.jq" --page-limit 50 >"$local_stage_success"
test "$(jq '.items | length' "$local_stage_success")" -eq 1

# The supervisor must produce identical bytes when stdout is a regular file
# (the collector path) or a pipe, while preserving its fixed exit contract.
local_identity_filter="$tmp/local-identity.jq"
local_stage_regular="$tmp/local-stage-regular.json"
local_stage_pipe="$tmp/local-stage-pipe.json"
printf '%s\n' '.' > "$local_identity_filter"
set +e
printf '%s\n' '{"synthetic":true}' \
  | python3 "$script_dir/run-local-json-stage-bounded.py" --timeout-seconds 5 --jq-only --jq-filter "$local_identity_filter" >"$local_stage_regular"
local_stage_regular_status=( "${PIPESTATUS[@]}" )
printf '%s\n' '{"synthetic":true}' \
  | python3 "$script_dir/run-local-json-stage-bounded.py" --timeout-seconds 5 --jq-only --jq-filter "$local_identity_filter" \
  | cat >"$local_stage_pipe"
local_stage_pipe_status=( "${PIPESTATUS[@]}" )
set -e
test "${local_stage_regular_status[0]}" -eq 0
test "${local_stage_regular_status[1]}" -eq 0
test "${local_stage_pipe_status[0]}" -eq 0
test "${local_stage_pipe_status[1]}" -eq 0
test "${local_stage_pipe_status[2]}" -eq 0
cmp "$local_stage_regular" "$local_stage_pipe"

local_overflow_filter="$tmp/local-overflow.jq"
printf '%s\n' '"x" * 4194305' > "$local_overflow_filter"
set +e
python3 "$script_dir/run-local-json-stage-bounded.py" --timeout-seconds 5 --jq-only --jq-filter "$local_overflow_filter" \
  >"$tmp/local-stage-overflow.out" 2>"$tmp/local-stage-overflow.err" <<< 'null'
local_stage_overflow_status=$?
set -e
test "$local_stage_overflow_status" -eq 2
test "$(wc -c < "$tmp/local-stage-overflow.out")" -le 4194304
test ! -s "$tmp/local-stage-overflow.err"

local_slow_filter="$tmp/local-slow.jq"
printf '%s\n' 'reduce range(0;100000000) as $n (0; . + $n)' > "$local_slow_filter"
local_stage_started=$(date +%s)
set +e
python3 "$script_dir/run-local-json-stage-bounded.py" --timeout-seconds 0.2 --jq-only --jq-filter "$local_slow_filter" >"$tmp/local-stage-timeout.out" 2>"$tmp/local-stage-timeout.err" <<< '[]' &
local_stage_pid=$!
wait "$local_stage_pid"
local_stage_status=$?
set -e
local_stage_elapsed=$(( $(date +%s) - local_stage_started ))
test "$local_stage_status" -eq 125
test "$local_stage_elapsed" -lt 5
test ! -s "$tmp/local-stage-timeout.out"
test ! -s "$tmp/local-stage-timeout.err"
if ps -p "$local_stage_pid" -o command= >/dev/null 2>&1; then
  printf 'offline snapshot test found unreaped local-stage PID: %s\n' "$local_stage_pid" >&2
  exit 1
fi

first_crd_hash=$(shasum -a 256 "$tmp/out-crd-multipage"/kubeconfig-api-snapshot-*/000/crd-api-surface.json | awk '{print $1}' | tail -1)
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=crd-multipage \
  "$snapshot_script" "$tmp/out-crd-multipage-repeat" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --include-component-configuration \
  --allow-partial "${snapshot_exec_env_args[@]}" synthetic-context >"$tmp/crd-multipage-repeat.stdout" 2>"$tmp/crd-multipage-repeat.stderr"
second_crd_hash=$(shasum -a 256 "$tmp/out-crd-multipage-repeat"/kubeconfig-api-snapshot-*/000/crd-api-surface.json | awk '{print $1}' | tail -1)
test "$first_crd_hash" = "$second_crd_hash"
assert_no_sensitive_output "$tmp/out-crd-multipage-repeat" "$tmp/crd-multipage-repeat.stdout" "$tmp/crd-multipage-repeat.stderr"

inherited_output="$tmp/out-inherited-writer"
inherited_stdout="$tmp/inherited-writer.stdout"
inherited_stderr="$tmp/inherited-writer.stderr"
inherited_supervisor_pids="$tmp/inherited-writer.supervisor-pids"
: > "$inherited_supervisor_pids"
record_snapshot_supervisors() {
  ps -axo pid=,ppid=,command= | awk -v root="$inherited_snapshot_pid" '
    {
      pid = $1
      parent[pid] = $2
      command[pid] = $0
    }
    END {
      for (pid in command) {
        current = pid
        for (depth = 0; depth < 64; depth++) {
          if (current == root) {
            if (command[pid] ~ /\/run-kubectl-bounded\.py/) print pid
            break
          }
          if (!(current in parent) || parent[current] == current) break
          current = parent[current]
        }
      }
    }
  ' >> "$inherited_supervisor_pids"
}
inherited_started=$(date +%s)
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=inherited-writer \
  "$snapshot_script" "$inherited_output" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --include-component-configuration \
  --allow-partial "${snapshot_exec_env_args[@]}" synthetic-context >"$inherited_stdout" 2>"$inherited_stderr" &
inherited_snapshot_pid=$!
while kill -0 "$inherited_snapshot_pid" 2>/dev/null; do
  record_snapshot_supervisors
  sleep 0.02
done
wait "$inherited_snapshot_pid"
inherited_elapsed=$(( $(date +%s) - inherited_started ))
test "$inherited_elapsed" -lt 8
inherited_run_dir=$(printf '%s\n' "$inherited_output"/kubeconfig-api-snapshot-* | tail -1)
assert_no_sensitive_output "$inherited_run_dir" "$inherited_stdout" "$inherited_stderr"
assert_no_hidden_fragments "$inherited_run_dir/000"
sort -u "$inherited_supervisor_pids" -o "$inherited_supervisor_pids"
test -s "$inherited_supervisor_pids"
while IFS= read -r supervisor_pid; do
  if [[ $supervisor_pid =~ ^[0-9]+$ ]] && ps -p "$supervisor_pid" -o command= 2>/dev/null | grep '/run-kubectl-bounded.py' >/dev/null 2>&1; then
    printf 'offline snapshot test found unreaped supervisor PID: %s\n' "$supervisor_pid" >&2
    exit 1
  fi
done < "$inherited_supervisor_pids"

for bounded_mode in endless-stderr ignore-term silent-hang-ignore-term setsid-descendant; do
  bounded_stdout="$tmp/$bounded_mode.stdout"
  bounded_stderr="$tmp/$bounded_mode.stderr"
  bounded_class="$tmp/$bounded_mode.class"
  bounded_started=$(date +%s)
  set +e
  PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE="$bounded_mode" \
    python3 "$bounded_runner_source" --timeout-seconds 1 --classification-fd 9 -- \
    "$fake_bin/kubectl" 9>"$bounded_class" >"$bounded_stdout" 2>"$bounded_stderr"
  bounded_status=$?
  set -e
  bounded_elapsed=$(( $(date +%s) - bounded_started ))
  test "$bounded_status" -eq 124
  test "$bounded_elapsed" -lt 5
  assert_contains 'transport_timeout_unreachable' "$bounded_class"
  assert_no_sensitive_output "$bounded_stdout" "$bounded_stdout" "$bounded_stderr"
done

broken_pipe_class="$tmp/broken-pipe.class"
broken_pipe_stderr="$tmp/broken-pipe.stderr"
broken_pipe_head="$tmp/broken-pipe.head"
set +e
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=oversized-json \
  python3 "$bounded_runner_source" --timeout-seconds 5 --classification-fd 9 -- \
  "$fake_bin/kubectl" get --raw=/version 9>"$broken_pipe_class" 2>"$broken_pipe_stderr" \
  | head -c 1 >"$broken_pipe_head"
broken_pipe_status=( "${PIPESTATUS[@]}" )
set -e
test "${broken_pipe_status[0]}" -eq 141
test "${broken_pipe_status[1]}" -eq 0
test ! -s "$broken_pipe_stderr"
assert_contains 'generic_api_read_failure' "$broken_pipe_class"

assert_classifier() {
  local expected=$1
  local actual
  shift
  actual=$("$@" | python3 "$classifier_source")
  test "$actual" = "$expected"
}

assert_classifier generic_api_read_failure printf '%s' ''
assert_classifier authentication_exec_plugin_failure printf '%s' 'error: exec plugin: executable /sensitive/plugin failed; endpoint=https://sensitive.example token=canary'
assert_classifier unauthorized printf '%s' 'Error from server (Unauthorized): endpoint=https://sensitive.example token=canary'
assert_classifier authorization_rbac_forbidden printf '%s' 'Error from server (Forbidden): endpoint=https://sensitive.example token=canary'
assert_classifier invalid_kubeconfig_context printf '%s' 'error: context "sensitive-context" does not exist in kubeconfig'
assert_classifier invalid_kubeconfig_context printf '%s' 'error: no context exists with the name: "sensitive-context"'
assert_classifier tls_certificate printf '%s' 'Unable to connect to the server: x509: certificate signed by unknown authority'
assert_classifier dns printf '%s' 'Unable to connect to the server: dial tcp: lookup sensitive.example: no such host'
assert_classifier transport_timeout_unreachable printf '%s' 'Unable to connect to the server: context deadline exceeded'
assert_classifier unsupported_not_found_api printf '%s' 'the server could not find the requested resource'
assert_classifier generic_api_read_failure printf '%s' 'forbidden.example and dns-certificate resource were mentioned'
assert_classifier generic_api_read_failure printf '%s' 'not found in arbitrary application text'
assert_classifier generic_api_read_failure printf '%s' $'\033[31mError from server (Forbidden):\033[0m\000 token=canary'
assert_classifier generic_api_read_failure python3 -c 'import sys; sys.stdout.buffer.write(b"x" * (64 * 1024 + 1) + b" endpoint=https://sensitive.example token=canary")'
assert_classifier generic_api_read_failure python3 -c 'import sys; sys.stdout.buffer.write(b"\\xff\\xfe\\x00")'

classifier_pids=()
for classifier_index in $(seq 1 16); do
  printf '%s' 'Error from server (Forbidden): endpoint=https://sensitive.example token=canary' \
    | python3 "$classifier_source" > "$tmp/classifier-$classifier_index" &
  classifier_pids+=("$!")
done
for classifier_pid in "${classifier_pids[@]}"; do
  wait "$classifier_pid"
done
test "$(find "$tmp" -name 'classifier-*' -type f -exec grep -L '^authorization_rbac_forbidden$' {} + | wc -l | tr -d ' ')" -eq 0

partial_output="$tmp/out-no-allow-partial"
partial_stdout="$tmp/no-allow-partial.stdout"
partial_stderr="$tmp/no-allow-partial.stderr"
mkdir -p "$partial_output"
set +e
PATH="$fake_bin:$PATH" FAKE_KUBECTL_MODE=kubernetes-api-read-failed \
  "$snapshot_script" "$partial_output" --kubeconfig "$synthetic_config_file" \
  --acknowledge-kubeconfig-exec-risk --include-component-configuration \
  "${snapshot_exec_env_args[@]}" synthetic-context >"$partial_stdout" 2>"$partial_stderr"
partial_status=$?
set -e
test "$partial_status" -eq 6
partial_run_dir=$(printf '%s\n' "$partial_output"/kubeconfig-api-snapshot-* | tail -1)
partial_context_dir="$partial_run_dir/000"
test "$(wc -l < "$partial_context_dir/omissions.tsv" | tr -d ' ')" -eq 20
assert_no_sensitive_output "$partial_run_dir" "$partial_stdout" "$partial_stderr"
assert_no_hidden_fragments "$partial_context_dir"

printf '%s\n' 'offline kubeconfig API snapshot tests: PASS'
