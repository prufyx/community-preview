#!/usr/bin/env bash

# A small, one-shot Kubernetes observation tool. It deliberately uses kubectl
# only for read requests and jq only for local extraction. No object returned
# by the API is written to disk before jq has reduced it to an allow-listed
# compatibility signal.
set -Eeuo pipefail
umask 077

# Remember only names that arrived through the process environment. This lets
# --exec-env distinguish operator-supplied values from shell locals created by
# this script without ever serializing an environment value.
ambient_environment_names=()
while IFS= read -r environment_name; do
  ambient_environment_names+=("$environment_name")
done < <(compgen -e)

usage() {
  cat >&2 <<'USAGE'
Usage: kubeconfig-api-snapshot.sh OUTPUT_DIR --kubeconfig FILE [OPTIONS] CONTEXT...

Read-only API observation through explicitly named kubeconfig contexts.

Options:
  --include-pod-status-images  Also collect filtered image/imageID status aggregates.
  --include-component-configuration
                               Opt in to the bounded public component configuration surface.
                               Disabled by default; workloads with registered public component
                               identities add filtered command projections. An exact cert-manager
                               workload match also enables documented RBAC, health, Services/Pods,
                               and monitor reads.
  --component-configuration-profile v3
                               With configuration enabled, use the source-bound v3 declared
                               entrypoint/command profile for registered v3 adapters. Omit to
                               preserve v2 flag-projection semantics.
  --allow-partial              Exit 0 when one or more declared API reads fail.
  --acknowledge-kubeconfig-exec-risk
                               Acknowledge reviewed kubeconfig auth helpers.
  --exec-env NAME              Forward one explicitly named ambient variable to
                               kubectl and its exec plugin. Repeat as needed.
                               PATH, HOME, USER, and TMPDIR are forwarded when
                               present; a fixed C locale and the exact
                               kubeconfig are supplied automatically.
                               Standard plugin examples: CLOUDSDK_CONFIG,
                               GOOGLE_APPLICATION_CREDENTIALS, AWS_PROFILE,
                               AWS_CONFIG_FILE, AWS_SHARED_CREDENTIALS_FILE,
                               AZURE_CONFIG_DIR. Proxy variables must be named
                               explicitly when they are present.

The script creates one numbered directory per context, filtered JSON files,
omissions.tsv, and SHA-256 MANIFEST.sha256 files. It never installs or changes
resources in a cluster.
USAGE
}

if (( $# < 2 )); then
  usage
  exit 2
fi

output_root=$1
shift
kubeconfig_file=''
kubeconfig_option_seen=false
include_pod_status_images=false
include_component_configuration=false
component_configuration_profile='v2'
component_configuration_profile_seen=false
allow_partial=false
exec_risk_acknowledged=false
exec_env_names=()

while (( $# > 0 )); do
  case $1 in
    --kubeconfig)
      if (( $# < 2 )); then
        usage
        exit 2
      fi
      if [[ $kubeconfig_option_seen == true ]]; then
        printf '%s\n' 'Duplicate --kubeconfig options are ambiguous.' >&2
        exit 2
      fi
      kubeconfig_option_seen=true
      kubeconfig_file=$2
      shift 2
      ;;
    --include-pod-status-images)
      include_pod_status_images=true
      shift
      ;;
    --include-component-configuration)
      include_component_configuration=true
      shift
      ;;
    --component-configuration-profile)
      if (( $# < 2 )) || [[ $component_configuration_profile_seen == true ]]; then
        printf '%s\n' 'The component configuration profile must be supplied exactly once.' >&2
        exit 2
      fi
      component_configuration_profile_seen=true
      component_configuration_profile=$2
      shift 2
      ;;
    --allow-partial)
      allow_partial=true
      shift
      ;;
    --acknowledge-kubeconfig-exec-risk)
      exec_risk_acknowledged=true
      shift
      ;;
    --exec-env)
      if (( $# < 2 )); then
        usage
        exit 2
      fi
      exec_env_names+=("$2")
      shift 2
      ;;
    --*)
      printf 'Unknown option: %s\n' "$1" >&2
      usage
      exit 2
      ;;
    *)
      break
      ;;
  esac
done
kubectl_binary=$(command -v kubectl)

if [[ -z $kubeconfig_file || ! -f $kubeconfig_file || ! -r $kubeconfig_file || -L $kubeconfig_file ]]; then
  printf '%s\n' 'An explicit readable, non-symlink kubeconfig file is required.' >&2
  exit 2
fi

file_owner_uid() {
  local value
  if value=$(stat -f '%u' "$1" 2>/dev/null) && [[ $value =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$value"
  elif value=$(stat -c '%u' "$1" 2>/dev/null) && [[ $value =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$value"
  else
    return 1
  fi
}

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

kubeconfig_owner=$(file_owner_uid "$kubeconfig_file")
kubeconfig_mode=$(file_mode "$kubeconfig_file")
kubeconfig_group_digit=$(( (10#$kubeconfig_mode / 10) % 10 ))
kubeconfig_other_digit=$(( 10#$kubeconfig_mode % 10 ))
if [[ $kubeconfig_owner != "$(id -u)" ]] || (( kubeconfig_group_digit != 0 || kubeconfig_other_digit != 0 )); then
  printf '%s\n' 'The kubeconfig must be owned by the invoking user with no group/other permission bits.' >&2
  printf '%s\n' 'Use mode 0600; authentication helpers remain part of the trusted local boundary.' >&2
  exit 2
fi

if [[ $exec_risk_acknowledged != true ]]; then
  printf '%s\n' \
    'Refusing to use kubeconfig without --acknowledge-kubeconfig-exec-risk.' \
    'Review the file first: kubectl may execute authentication helpers declared in it.' >&2
  exit 2
fi

if (( $# == 0 )); then
  usage
  exit 2
fi

if [[ $include_component_configuration == true && $include_pod_status_images == true ]]; then
  printf '%s\n' 'Refusing --include-pod-status-images with --include-component-configuration: the component-configuration mode never persists raw Pod image IDs or references.' >&2
  printf '%s\n' 'Use the privacy-safe component surface alone; it derives active public identities from approved workload projections.' >&2
  exit 2
fi
if [[ $component_configuration_profile_seen == true && $include_component_configuration != true ]]; then
  printf '%s\n' '--component-configuration-profile requires --include-component-configuration.' >&2
  exit 2
fi
if [[ $component_configuration_profile != v2 && $component_configuration_profile != v3 ]]; then
  printf 'Unsupported component configuration profile: %s\n' "$component_configuration_profile" >&2
  exit 2
fi

environment_name_was_ambient() {
  local candidate
  for candidate in "${ambient_environment_names[@]}"; do
    if [[ $candidate == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

exec_env_requested() {
  local candidate
  for candidate in "${exec_env_names[@]}"; do
    if [[ $candidate == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

validated_exec_env_names=()
for environment_name in "${exec_env_names[@]}"; do
  if [[ ! $environment_name =~ ^[A-Za-z_][A-Za-z0-9_]{0,63}$ ]]; then
    printf '%s\n' 'Each --exec-env value must be a bounded environment variable name.' >&2
    exit 2
  fi
  case "$environment_name" in
    PATH|HOME|USER|TMPDIR|LANG|LC_ALL|KUBECONFIG)
      printf 'Environment variable %s is controlled by the collector and must not be forwarded.\n' "$environment_name" >&2
      exit 2
      ;;
    BASH_ENV|ENV|SHELLOPTS|BASHOPTS|CDPATH|GLOBIGNORE|IFS|LD_*|DYLD_*|PYTHON*)
      printf 'Environment variable %s can alter executable loading and is not eligible for forwarding.\n' "$environment_name" >&2
      exit 2
      ;;
  esac
  for validated_name in "${validated_exec_env_names[@]}"; do
    if [[ $validated_name == "$environment_name" ]]; then
      printf 'Duplicate --exec-env value: %s\n' "$environment_name" >&2
      exit 2
    fi
  done
  if ! environment_name_was_ambient "$environment_name"; then
    printf 'Environment variable %s was not present in the invoking environment.\n' "$environment_name" >&2
    exit 2
  fi
  validated_exec_env_names+=("$environment_name")
  if (( ${#validated_exec_env_names[@]} > 64 )); then
    printf '%s\n' 'At most 64 --exec-env values may be forwarded.' >&2
    exit 2
  fi
done

# Dropping an ambient proxy can route around an operator's network policy.
# Require the operator to forward each present proxy variable explicitly.
for proxy_name in HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; do
  if environment_name_was_ambient "$proxy_name" && ! exec_env_requested "$proxy_name"; then
    printf 'Ambient proxy variable %s requires explicit --exec-env %s; refusing to bypass it.\n' "$proxy_name" "$proxy_name" >&2
    exit 2
  fi
done

for dependency in kubectl jq shasum mktemp find python3 cp chmod; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$dependency" >&2
    exit 2
  fi
done
python3_binary=$(command -v python3)
if ! "$python3_binary" -I -S -c '
import os
import sys

names = sys.argv[1:]
baseline = [name for name in ("PATH", "HOME", "USER", "TMPDIR") if name in os.environ]
values = [os.environ[name].encode("utf-8", "surrogateescape") for name in baseline + names]
raise SystemExit(0 if all(len(value) <= 65536 for value in values) and sum(map(len, values)) <= 262144 else 1)
' "${validated_exec_env_names[@]}"; then
  printf '%s\n' 'The selected kubectl environment exceeds the bounded value or total size.' >&2
  exit 2
fi
context_identity_key_hex=$(
  "$python3_binary" -I -S -c 'import os; print(os.urandom(32).hex())'
)
if [[ ! $context_identity_key_hex =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' 'Failed to create the per-run context pseudonym key.' >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ $component_configuration_profile == v3 ]]; then
  adapter_registry_source="$script_dir/component-configuration-adapters-v3.json"
  adapter_filter_source="$script_dir/component-configuration-adapter-v3.jq"
  adapter_aggregate_source="$script_dir/component-configuration-aggregate-v3.jq"
else
  adapter_registry_source="$script_dir/component-configuration-adapters.json"
  adapter_filter_source="$script_dir/component-configuration-adapter.jq"
  adapter_aggregate_source="$script_dir/component-configuration-aggregate.jq"
fi
strict_json_source="$script_dir/reject-duplicate-json.py"
kubectl_stderr_classifier_source="$script_dir/classify-kubectl-stderr.py"
kubectl_bounded_runner_source="$script_dir/run-kubectl-bounded.py"
local_json_stage_source="$script_dir/run-local-json-stage-bounded.py"
crd_page_projection_source="$script_dir/crd-page-projection.jq"
crd_final_merge_source="$script_dir/crd-final-merge.jq"
cert_manager_projection_source="$script_dir/cert-manager-projection.jq"
if [[ $component_configuration_profile == v3 ]]; then
  expected_adapter_registry_digest='sha256:c2631adc13f82d35f20518736a1816d1a1e8155c69b2d0d805f4dd275678d186'
  expected_adapter_filter_digest='sha256:cf9fbb75cdb9a3ec95b8b79e4ffda7d3d905e07f0de707569a16dc827f65bd2e'
  expected_adapter_aggregate_digest='sha256:37e08d478632074dff7930898bc1c1831f4a18e34d2f45eee3516c2b5b5b679c'
else
  expected_adapter_registry_digest='sha256:cd5766d38d7e735903b58f2a4752ab4d9f74325167a5ec7ce3fd8a2451fa7782'
  expected_adapter_filter_digest='sha256:936eaf8491aa39f2bf37a57901123f33cbaf8f4e0e6819c2ccf2064066b23358'
  expected_adapter_aggregate_digest='sha256:08f25050e37ffcfc90e1b67c96a661d68c7b70e4dc9cc42c967d8968bee8b44c'
fi
expected_strict_json_digest='sha256:799a69405e30ee90e1929d48560fa68df57f26cf12bd9c132ad6ad84c6c1b5a7'
expected_kubectl_stderr_classifier_digest='sha256:1166426cfd8b37bb271525cddfd4c98fa2e58d2ebfddf9d096f8432a01e25138'
expected_kubectl_bounded_runner_digest='sha256:6e9eb7555d56e938c32f2dbfdb21e221b861b28efccc22f54772533982a01dda'
expected_local_json_stage_digest='sha256:b99c2719f934d8a07d5f8785817bc1ee8bc85712187d0b38d5c4c3db75123127'
expected_crd_page_projection_digest='sha256:7ab5c4ae22b27786195261bf3d28c9d1707d1c1d577a7c9a27b6e0509825b664'
expected_crd_final_merge_digest='sha256:026a6a98d5a3dd748bbcb8ca5540739715d2191ff5e1203182267bd7d0ed0b32'
expected_cert_manager_projection_digest='sha256:37f7f7db17a96ee2ab1c26bd1e8d68627b299ed2210383047a0a496fee63f604'
if [[ -L $adapter_registry_source || ! -f $adapter_registry_source || -L $adapter_filter_source || ! -f $adapter_filter_source || -L $adapter_aggregate_source || ! -f $adapter_aggregate_source || -L $strict_json_source || ! -f $strict_json_source || -L $kubectl_stderr_classifier_source || ! -f $kubectl_stderr_classifier_source || -L $kubectl_bounded_runner_source || ! -f $kubectl_bounded_runner_source || -L $local_json_stage_source || ! -f $local_json_stage_source || -L $crd_page_projection_source || ! -f $crd_page_projection_source || -L $crd_final_merge_source || ! -f $crd_final_merge_source || -L $cert_manager_projection_source || ! -f $cert_manager_projection_source ]]; then
  printf '%s\n' 'The component configuration adapter registry/filter is missing or symlinked.' >&2
  exit 2
fi
stage_dir=$(mktemp -d /tmp/prufyx-component-adapter.XXXXXX)
chmod 700 "$stage_dir"
trap 'rm -rf -- "$stage_dir"' EXIT
stage_file() {
  local source=$1
  local destination=$2
  if [[ -L $source || ! -f $source ]]; then
    return 1
  fi
  cp -- "$source" "$destination"
  if [[ -L $destination || ! -f $destination ]]; then
    return 1
  fi
  chmod 400 "$destination"
}
stage_file "$adapter_registry_source" "$stage_dir/registry.json" || { printf '%s\n' 'Failed to stage the component adapter registry.' >&2; exit 2; }
stage_file "$adapter_filter_source" "$stage_dir/filter.jq" || { printf '%s\n' 'Failed to stage the component adapter filter.' >&2; exit 2; }
stage_file "$adapter_aggregate_source" "$stage_dir/aggregate.jq" || { printf '%s\n' 'Failed to stage the component adapter aggregate.' >&2; exit 2; }
stage_file "$strict_json_source" "$stage_dir/reject-duplicate-json.py" || { printf '%s\n' 'Failed to stage the strict JSON validator.' >&2; exit 2; }
stage_file "$kubectl_stderr_classifier_source" "$stage_dir/classify-kubectl-stderr.py" || { printf '%s\n' 'Failed to stage the kubectl stderr classifier.' >&2; exit 2; }
stage_file "$kubectl_bounded_runner_source" "$stage_dir/run-kubectl-bounded.py" || { printf '%s\n' 'Failed to stage the bounded kubectl runner.' >&2; exit 2; }
stage_file "$local_json_stage_source" "$stage_dir/run-local-json-stage-bounded.py" || { printf '%s\n' 'Failed to stage the bounded local JSON stage.' >&2; exit 2; }
stage_file "$crd_page_projection_source" "$stage_dir/crd-page-projection.jq" || { printf '%s\n' 'Failed to stage the CRD page projection.' >&2; exit 2; }
stage_file "$crd_final_merge_source" "$stage_dir/crd-final-merge.jq" || { printf '%s\n' 'Failed to stage the CRD final merge.' >&2; exit 2; }
stage_file "$cert_manager_projection_source" "$stage_dir/cert-manager-projection.jq" || { printf '%s\n' 'Failed to stage the cert-manager projection.' >&2; exit 2; }
adapter_registry_file="$stage_dir/registry.json"
adapter_filter_file="$stage_dir/filter.jq"
adapter_aggregate_file="$stage_dir/aggregate.jq"
strict_json_helper="$stage_dir/reject-duplicate-json.py"
kubectl_stderr_classifier_helper="$stage_dir/classify-kubectl-stderr.py"
kubectl_bounded_runner_helper="$stage_dir/run-kubectl-bounded.py"
local_json_stage_helper="$stage_dir/run-local-json-stage-bounded.py"
crd_page_projection_helper="$stage_dir/crd-page-projection.jq"
crd_final_merge_helper="$stage_dir/crd-final-merge.jq"
cert_manager_projection_helper="$stage_dir/cert-manager-projection.jq"
kubectl_stderr_classifier_taxonomy_version='kubectl-stderr-taxonomy-v1'
kubectl_stderr_classifier_authority='heuristic_local_diagnostic_not_proof'

if ! python3 "$strict_json_helper" < "$adapter_registry_file" >/dev/null; then
  printf '%s\n' 'The component adapter registry is malformed or contains duplicate JSON keys.' >&2
  exit 2
fi
if ! jq -e '
  # PRUFYX_REGISTRY_VALIDATOR_BEGIN
  . as $registryRoot |
  type == "object" and (keys | sort) == ["adapters", "apiVersion", "kind", "metadata"] and
  .apiVersion == "prufyx.io/configuration-adapters/v1alpha1" and
  .kind == "ComponentConfigurationAdapterRegistry" and
  (.metadata | type == "object" and (keys | sort) == ["policy", "registryVersion", "schemaVersion"]) and
  ((.metadata.schemaVersion == "1.1.0" and .metadata.registryVersion == "v2" and .metadata.policy == "public_identity_exact_match_non_secret_predicates_declared_context") or
   (.metadata.schemaVersion == "1.2.0" and .metadata.registryVersion == "v3" and .metadata.policy == "public_identity_exact_match_non_secret_predicates_source_bound_declared_context")) and
  (.adapters | type == "array" and length > 0 and length <= 32) and
  ([.adapters[].componentId] | unique | length) == (.adapters | length) and
  ([.adapters[].identities[]] | unique | length) == ([.adapters[].identities[]] | length) and
  ([.adapters[].predicates[].id] | unique | length) == ([.adapters[].predicates[].id] | length) and
  (all(.adapters[]; ((keys | sort) == ["componentId", "identities", "predicates", "workloadKinds"] or (keys | sort) == ["componentId", "declaredRole", "identities", "predicates", "roleEvidenceClass", "workloadKinds"] or (keys | sort) == ["componentId", "declaredRole", "entrypointContract", "identities", "predicates", "roleEvidenceClass", "workloadKinds"]) and
    (.componentId | test("^pkg:oci/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]+$")) and
    (.identities as $ids | ($ids | type == "array" and length > 0 and length <= 16 and (($ids | unique | length) == ($ids | length)) and all($ids[]; type == "string" and test("^(?:(?:docker\\.io|quay\\.io)/)?[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]+$")))) and
    (.workloadKinds as $workloadKinds | ($workloadKinds | type == "array" and length > 0 and length <= 3 and (($workloadKinds | unique | length) == ($workloadKinds | length)) and all(.[]; . as $kind | ["Deployment", "DaemonSet", "StatefulSet"] | index($kind) != null))) and
    (.predicates | type == "array" and length > 0 and length <= 32 and ([.[].id] | unique | length) == length and
      ([.[].flags[0]] | group_by(.) | all(length == 1 or .[0] == "--feature-gates"))))) and
  (all(.adapters[].predicates[];
    ((.valueKind == "enum" and (keys | sort) == ["allowedValues", "flags", "id", "valueKind"] and (.allowedValues as $values | ($values | type == "array" and length > 0 and (($values | unique | length) == ($values | length))))) or
     (.valueKind == "boolean" and (keys | sort) == ["flags", "id", "valueKind"]) or
     (.valueKind == "presence" and (keys | sort) == ["flags", "id", "valueKind"]) or
     (.valueKind == "featureGate" and (keys | sort) == ["featureGate", "flags", "id", "valueKind"] and (.featureGate | type == "string" and test("^[A-Za-z][A-Za-z0-9]{1,127}$")) and .flags == ["--feature-gates"]) or
     (.valueKind == "versionedAgentMode" and (keys | sort) == ["flags", "id", "valueKind"] and .id == "component.prometheus.agent_mode" and .flags == ["--enable-feature", "--agent"]) or
     (.valueKind == "publicImageDigest" and (keys | sort) == ["flags", "id", "valueKind"] and .id == "component.prometheus.image_digest" and .flags == [])) and
    (.id | test("^component\\.[a-z0-9_.-]+$")) and
    (.flags as $flags | ($flags | type == "array" and length <= 3 and (unique | length) == length) and all($flags[]; type == "string" and test("^--[a-z0-9][a-z0-9.-]{1,127}$"))) and
    ((.valueKind != "enum") or (.allowedValues | type == "array" and length > 0 and length <= 16 and all(.[]; type == "string" and length <= 32 and test("^[a-z][a-z0-9_-]{0,31}$")))))) and
  (all(.adapters[];
    if .componentId == "pkg:oci/prometheus/prometheus" then .workloadKinds == ["Deployment", "StatefulSet"] and
      (if $registryRoot.metadata.registryVersion == "v3" then .identities == ["prom/prometheus"] and .declaredRole == "server" and .roleEvidenceClass == "declared_container_context_v1" and (.entrypointContract | type) == "object" and [.predicates[].id] == ["component.prometheus.agent_mode", "component.prometheus.image_digest"] else (has("declaredRole") | not) and (has("roleEvidenceClass") | not) and (has("entrypointContract") | not) end)
    elif .componentId == "pkg:oci/argoproj/argo-workflows" then .workloadKinds == ["Deployment"] and .declaredRole == "workflow-controller" and .roleEvidenceClass == "declared_container_context_v1" and (if $registryRoot.metadata.registryVersion == "v3" then (.entrypointContract | type) == "object" else (has("entrypointContract") | not) end)
    elif .componentId == "pkg:oci/argoproj/argo-cd" then .workloadKinds == ["Deployment", "StatefulSet"] and (has("declaredRole") | not) and (has("roleEvidenceClass") | not)
    elif .componentId == "pkg:oci/cert-manager/cert-manager" then .workloadKinds == ["Deployment"] and (has("declaredRole") | not) and (has("roleEvidenceClass") | not)
    elif .componentId == "pkg:oci/cilium/cilium" then .workloadKinds == ["DaemonSet"] and (has("declaredRole") | not) and (has("roleEvidenceClass") | not)
    else false end)) and
  (if .metadata.registryVersion == "v3" then
     (all(.adapters[] | select(has("entrypointContract")); .entrypointContract as $contract |
       ($contract | type) == "object" and ($contract | keys | sort) == ["acceptedExplicitCommands", "imageBindings", "imageEntrypoint", "sourceBindings"] and
       ($contract.imageEntrypoint | type == "array" and length == 1 and all(.[]; type == "string" and length >= 1 and length <= 128)) and
       ($contract.acceptedExplicitCommands | type == "array" and length >= 1 and length <= 4 and all(.[]; type == "array" and length >= 1 and length <= 8 and all(.[]; type == "string" and length >= 1 and length <= 128))) and
       ($contract.imageBindings | type == "array" and length >= 1 and length <= 4 and ([.[].version] | unique | length) == length and all(.[];
         (.version | type == "string" and test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) and
         ((.referenceClass == "tag" and (keys | sort) == ["referenceClass", "version"]) or
          (.referenceClass == "tag_and_platform_digest" and (keys | sort) == ["defaultPredicateValues", "indexDigest", "platformDigests", "referenceClass", "version"] and (.indexDigest | test("^sha256:[0-9a-f]{64}$")) and (.platformDigests | type == "array" and length >= 1 and length <= 4 and all(.[]; test("^sha256:[0-9a-f]{64}$"))) and .defaultPredicateValues == {"component.prometheus.agent_mode": false})))) and
       ($contract.sourceBindings | type == "array" and length >= 2 and length <= 8 and ([.[].sourceId] | unique | length) == length and all(.[]; (keys | sort) == ["contentDigest", "immutableCommit", "sourceId", "spans", "url"] and (.sourceId | test("^[a-z0-9][a-z0-9._-]+$")) and (.immutableCommit | test("^[0-9a-f]{40}$")) and (.contentDigest | test("^sha256:[0-9a-f]{64}$")) and (.url | startswith("https://raw.githubusercontent.com/")) and (.spans | type == "array" and length >= 1 and length <= 8 and all(.[]; . as $span | (keys | sort) == ["endLine", "startLine", "textDigest"] and ($span.startLine | type == "number" and . >= 1 and floor == .) and ($span.endLine | type == "number" and . >= $span.startLine and floor == .) and ($span.textDigest | test("^sha256:[0-9a-f]{64}$"))))))))
   else all(.adapters[]; has("entrypointContract") | not)
   end)
  # PRUFYX_REGISTRY_VALIDATOR_END
' "$adapter_registry_file" >/dev/null; then
  printf '%s\n' 'The component configuration adapter registry is invalid.' >&2
  exit 2
fi
adapter_registry_digest=$(shasum -a 256 "$adapter_registry_file" | awk '{print "sha256:" $1}')
adapter_filter_digest=$(shasum -a 256 "$adapter_filter_file" | awk '{print "sha256:" $1}')
adapter_aggregate_digest=$(shasum -a 256 "$adapter_aggregate_file" | awk '{print "sha256:" $1}')
strict_json_digest=$(shasum -a 256 "$strict_json_helper" | awk '{print "sha256:" $1}')
kubectl_stderr_classifier_digest=$(shasum -a 256 "$kubectl_stderr_classifier_helper" | awk '{print "sha256:" $1}')
kubectl_bounded_runner_digest=$(shasum -a 256 "$kubectl_bounded_runner_helper" | awk '{print "sha256:" $1}')
local_json_stage_digest=$(shasum -a 256 "$local_json_stage_helper" | awk '{print "sha256:" $1}')
crd_page_projection_digest=$(shasum -a 256 "$crd_page_projection_helper" | awk '{print "sha256:" $1}')
crd_final_merge_digest=$(shasum -a 256 "$crd_final_merge_helper" | awk '{print "sha256:" $1}')
cert_manager_projection_digest=$(shasum -a 256 "$cert_manager_projection_helper" | awk '{print "sha256:" $1}')
if [[ $adapter_registry_digest != "$expected_adapter_registry_digest" || $adapter_filter_digest != "$expected_adapter_filter_digest" || $adapter_aggregate_digest != "$expected_adapter_aggregate_digest" || $strict_json_digest != "$expected_strict_json_digest" || $kubectl_stderr_classifier_digest != "$expected_kubectl_stderr_classifier_digest" || $kubectl_bounded_runner_digest != "$expected_kubectl_bounded_runner_digest" || $local_json_stage_digest != "$expected_local_json_stage_digest" || $crd_page_projection_digest != "$expected_crd_page_projection_digest" || $crd_final_merge_digest != "$expected_crd_final_merge_digest" || $cert_manager_projection_digest != "$expected_cert_manager_projection_digest" ]]; then
  printf '%s\n' 'The component configuration adapter release digests are not approved.' >&2
  exit 2
fi
adapter_registry_json=$(jq -c . "$adapter_registry_file")
component_adapter_version="component-configuration-adapter-$component_configuration_profile"
component_registry_version="$component_configuration_profile"
component_role_evidence_version="$component_configuration_profile"

if [[ -L $output_root ]]; then
  printf '%s\n' 'The output directory must not be a symbolic link.' >&2
  exit 2
fi
mkdir -p -- "$output_root"

generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir=$(mktemp -d "$output_root/kubeconfig-api-snapshot-$stamp.XXXXXX")
chmod 700 "$run_dir"

cleanup_temp_outputs() {
  if [[ -n ${stage_dir:-} && -d ${stage_dir:-} ]]; then
    rm -rf -- "$stage_dir"
  fi
  if [[ -n ${run_dir:-} && -d ${run_dir:-} ]]; then
    find "$run_dir" -type f \( -name '.*.tmp*' -o -name '.*.page.*' -o -name '.*.items.*' -o -name '.*.stderr-class*' -o -name '.component-configuration.ndjson' -o -name '.component-configuration-omissions.ndjson' -o -name '.cert-manager-*' \) -exec rm -f -- {} + 2>/dev/null || true
  fi
}
on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM PIPE
  cleanup_temp_outputs
  exit "$status"
}
trap on_exit EXIT HUP INT TERM PIPE

overall_omissions=0
overall_declared_reads=0
overall_kubernetes_api_read_failures=0
failure_histogram_kubernetes_api_read_failed=0
failure_histogram_strict_json_rejected=0
failure_histogram_projection_filter_rejected=0
failure_histogram_pipeline_failed=0
failure_histogram_kubernetes_api_read_failed_authentication_exec_plugin_failure=0
failure_histogram_kubernetes_api_read_failed_unauthorized=0
failure_histogram_kubernetes_api_read_failed_authorization_rbac_forbidden=0
failure_histogram_kubernetes_api_read_failed_invalid_kubeconfig_context=0
failure_histogram_kubernetes_api_read_failed_tls_certificate=0
failure_histogram_kubernetes_api_read_failed_dns=0
failure_histogram_kubernetes_api_read_failed_transport_timeout_unreachable=0
failure_histogram_kubernetes_api_read_failed_unsupported_not_found_api=0
failure_histogram_kubernetes_api_read_failed_generic_api_read_failure=0
crd_page_limit=50
crd_max_pages=64
crd_max_items=10000
crd_max_versions=100000
crd_max_projected_bytes=$((4 * 1024 * 1024))
crd_overall_timeout_seconds=120
component_configuration_max_fragments=10000
crd_pagination_policy_version='crd-pagination-policy-v1'
crd_pagination_endpoint='/apis/apiextensions.k8s.io/v1/customresourcedefinitions'
crd_pagination_profile='raw-v1-continue'
context_index=0
: > "$run_dir/index.ndjson"

context_hash() {
  {
    printf '%s\n' "$context_identity_key_hex"
    printf '%s' "$1"
  } | "$python3_binary" -I -S -c '
import hashlib
import hmac
import sys

key_line = sys.stdin.buffer.readline()
if len(key_line) != 65 or not key_line.endswith(b"\n"):
    raise SystemExit(2)
key = bytes.fromhex(key_line[:-1].decode("ascii"))
context = sys.stdin.buffer.read()
message = b"prufyx.io/context-identity/v1\0" + context
print("sha256:" + hmac.new(key, message, hashlib.sha256).hexdigest())
'
}

# Execute the pinned bounded runner with a closed environment. A small trusted
# launcher reads selected values from its inherited environment, then execs the
# unchanged pinned runner with only the baseline and operator-selected values.
# Values never enter argv or an observation file. os.execve also excludes
# exported Bash functions and avoids shell failures on readonly variables.
run_kubectl_bounded() {
  "$python3_binary" -I -S -c '
import os
import sys

arguments = sys.argv[1:]
try:
    separator = arguments.index("--")
except ValueError:
    raise SystemExit(125)
kubeconfig = arguments[0]
selected = arguments[1:separator]
runner_argv = arguments[separator + 1:]
if not runner_argv:
    raise SystemExit(125)
clean = {"LANG": "C", "LC_ALL": "C", "KUBECONFIG": kubeconfig}
for name in ("PATH", "HOME", "USER", "TMPDIR"):
    if name in os.environ:
        clean[name] = os.environ[name]
for name in selected:
    if name not in os.environ:
        raise SystemExit(125)
    clean[name] = os.environ[name]
os.execve(sys.executable, [sys.executable, "-I", "-S", *runner_argv], clean)
' "$kubeconfig_file" "${validated_exec_env_names[@]}" -- "$kubectl_bounded_runner_helper" "$@"
}

pipeline_failure_reason() {
  case "$1" in
    kubernetes_api_read_failed_authentication_exec_plugin_failure)
      printf '%s\n' 'Heuristic local classification matched an authentication or exec-plugin diagnostic; this is not authorization proof.'
      ;;
    kubernetes_api_read_failed_unauthorized)
      printf '%s\n' 'Heuristic local classification matched an unauthorized diagnostic; this is not authorization proof.'
      ;;
    kubernetes_api_read_failed_authorization_rbac_forbidden)
      printf '%s\n' 'Heuristic local classification matched a forbidden or RBAC diagnostic; this is not authorization proof.'
      ;;
    kubernetes_api_read_failed_invalid_kubeconfig_context)
      printf '%s\n' 'Heuristic local classification matched an invalid kubeconfig or context diagnostic; this is not proof of configuration state.'
      ;;
    kubernetes_api_read_failed_tls_certificate)
      printf '%s\n' 'Heuristic local classification matched a TLS or certificate diagnostic; this is not proof of endpoint identity.'
      ;;
    kubernetes_api_read_failed_dns)
      printf '%s\n' 'Heuristic local classification matched a DNS diagnostic; this is not proof of endpoint identity.'
      ;;
    kubernetes_api_read_failed_transport_timeout_unreachable)
      printf '%s\n' 'Heuristic local classification matched a timeout or unreachable transport diagnostic; this is not proof of availability.'
      ;;
    kubernetes_api_read_failed_unsupported_not_found_api)
      printf '%s\n' 'Heuristic local classification matched an unsupported or not-found API diagnostic; this is not proof of API capability.'
      ;;
    kubernetes_api_read_failed_generic_api_read_failure)
      printf '%s\n' 'kubectl API read failed without a specific safe heuristic classification; this is not proof of cause.'
      ;;
    kubernetes_api_read_failed)
      printf '%s\n' 'kubectl API read failed before JSON reached local validation; cause remains unknown and this is not proof of authorization state.'
      ;;
    strict_json_rejected)
      printf '%s\n' 'The API response failed bounded strict JSON validation.'
      ;;
    projection_filter_rejected)
      printf '%s\n' 'The allow-listed local projection rejected the API JSON.'
      ;;
    pipeline_failed|*)
      printf '%s\n' 'The collector pipeline failed without a classified stage.'
      ;;
  esac
}

component_configuration_failure_code() {
  case "$1" in
    kubernetes_api_read_failed_authentication_exec_plugin_failure)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHENTICATION_EXEC_PLUGIN_FAILURE'
      ;;
    kubernetes_api_read_failed_unauthorized)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNAUTHORIZED'
      ;;
    kubernetes_api_read_failed_authorization_rbac_forbidden)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN'
      ;;
    kubernetes_api_read_failed_invalid_kubeconfig_context)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_INVALID_KUBECONFIG_CONTEXT'
      ;;
    kubernetes_api_read_failed_tls_certificate)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TLS_CERTIFICATE'
      ;;
    kubernetes_api_read_failed_dns)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_DNS'
      ;;
    kubernetes_api_read_failed_transport_timeout_unreachable)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_TRANSPORT_TIMEOUT_UNREACHABLE'
      ;;
    kubernetes_api_read_failed_unsupported_not_found_api)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_UNSUPPORTED_NOT_FOUND_API'
      ;;
    kubernetes_api_read_failed)
      printf '%s\n' 'COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED'
      ;;
    strict_json_rejected)
      printf '%s\n' 'COMPONENT_CONFIGURATION_STRICT_JSON_REJECTED'
      ;;
    projection_filter_rejected)
      printf '%s\n' 'COMPONENT_CONFIGURATION_PROJECTION_FILTER_REJECTED'
      ;;
    pipeline_failed|*)
      printf '%s\n' 'COMPONENT_CONFIGURATION_PIPELINE_FAILED'
      ;;
  esac
}

record_pipeline_failure() {
  local output_name=$1
  local failure_code=$2
  local failure_reason
  failure_reason=$(pipeline_failure_reason "$failure_code")
  case "$failure_code" in
    kubernetes_api_read_failed|kubernetes_api_read_failed_*)
      failure_histogram_kubernetes_api_read_failed=$((failure_histogram_kubernetes_api_read_failed + 1))
      overall_kubernetes_api_read_failures=$((overall_kubernetes_api_read_failures + 1))
      if [[ $failure_code == kubernetes_api_read_failed ]]; then
        failure_histogram_kubernetes_api_read_failed_generic_api_read_failure=$((failure_histogram_kubernetes_api_read_failed_generic_api_read_failure + 1))
      fi
      case "$failure_code" in
        kubernetes_api_read_failed_authentication_exec_plugin_failure|kubernetes_api_read_failed_unauthorized|kubernetes_api_read_failed_authorization_rbac_forbidden|kubernetes_api_read_failed_invalid_kubeconfig_context|kubernetes_api_read_failed_tls_certificate|kubernetes_api_read_failed_dns|kubernetes_api_read_failed_transport_timeout_unreachable|kubernetes_api_read_failed_unsupported_not_found_api|kubernetes_api_read_failed_generic_api_read_failure)
          case "$failure_code" in
            kubernetes_api_read_failed_authentication_exec_plugin_failure) failure_histogram_kubernetes_api_read_failed_authentication_exec_plugin_failure=$((failure_histogram_kubernetes_api_read_failed_authentication_exec_plugin_failure + 1)) ;;
            kubernetes_api_read_failed_unauthorized) failure_histogram_kubernetes_api_read_failed_unauthorized=$((failure_histogram_kubernetes_api_read_failed_unauthorized + 1)) ;;
            kubernetes_api_read_failed_authorization_rbac_forbidden) failure_histogram_kubernetes_api_read_failed_authorization_rbac_forbidden=$((failure_histogram_kubernetes_api_read_failed_authorization_rbac_forbidden + 1)) ;;
            kubernetes_api_read_failed_invalid_kubeconfig_context) failure_histogram_kubernetes_api_read_failed_invalid_kubeconfig_context=$((failure_histogram_kubernetes_api_read_failed_invalid_kubeconfig_context + 1)) ;;
            kubernetes_api_read_failed_tls_certificate) failure_histogram_kubernetes_api_read_failed_tls_certificate=$((failure_histogram_kubernetes_api_read_failed_tls_certificate + 1)) ;;
            kubernetes_api_read_failed_dns) failure_histogram_kubernetes_api_read_failed_dns=$((failure_histogram_kubernetes_api_read_failed_dns + 1)) ;;
            kubernetes_api_read_failed_transport_timeout_unreachable) failure_histogram_kubernetes_api_read_failed_transport_timeout_unreachable=$((failure_histogram_kubernetes_api_read_failed_transport_timeout_unreachable + 1)) ;;
            kubernetes_api_read_failed_unsupported_not_found_api) failure_histogram_kubernetes_api_read_failed_unsupported_not_found_api=$((failure_histogram_kubernetes_api_read_failed_unsupported_not_found_api + 1)) ;;
            kubernetes_api_read_failed_generic_api_read_failure) failure_histogram_kubernetes_api_read_failed_generic_api_read_failure=$((failure_histogram_kubernetes_api_read_failed_generic_api_read_failure + 1)) ;;
          esac
          ;;
        *)
          failure_code=kubernetes_api_read_failed
          ;;
      esac
      ;;
    strict_json_rejected)
      failure_histogram_strict_json_rejected=$((failure_histogram_strict_json_rejected + 1))
      ;;
    projection_filter_rejected)
      failure_histogram_projection_filter_rejected=$((failure_histogram_projection_filter_rejected + 1))
      ;;
    pipeline_failed|*)
      failure_code=pipeline_failed
      failure_histogram_pipeline_failed=$((failure_histogram_pipeline_failed + 1))
      ;;
  esac
  printf '%s\t%s\t%s\n' "$output_name" "$failure_code" "$failure_reason" >> "$cluster_dir/omissions.tsv"
  overall_omissions=$((overall_omissions + 1))
  CAPTURE_FAILURE_CODE=$failure_code
  CAPTURE_FAILURE_REASON=$failure_reason
}

classify_pipeline_status() {
  if (( $# != 3 )); then
    printf '%s\n' 'pipeline_failed'
    return
  fi
  # The bounded runner owns kubectl's status. An empty stdout stream makes
  # strict-json exit 1, but that downstream result must not hide a classified
  # kubectl failure. Only runner success, or downstream SIGPIPE (141), allows
  # strict/projection failures to take precedence. Internal/interrupt exits
  # are collector pipeline failures.
  case "$1" in
    125|130)
      printf '%s\n' 'pipeline_failed'
      ;;
    141)
      if (( $2 != 0 )); then
        printf '%s\n' 'strict_json_rejected'
      elif (( $3 != 0 )); then
        printf '%s\n' 'projection_filter_rejected'
      else
        printf '%s\n' 'kubernetes_api_read_failed'
      fi
      ;;
    0)
      if (( $2 != 0 )); then
        printf '%s\n' 'strict_json_rejected'
      elif (( $3 != 0 )); then
        printf '%s\n' 'projection_filter_rejected'
      else
        printf '%s\n' 'success'
      fi
      ;;
    *)
      printf '%s\n' 'kubernetes_api_read_failed'
      ;;
  esac
}

classify_crd_pipeline_status() {
  if (( $# != 2 )); then
    printf '%s\n' 'pipeline_failed'
    return
  fi
  case "$1" in
    125|130)
      printf '%s\n' 'pipeline_failed'
      ;;
    141)
      case "$2" in
        125|130) printf '%s\n' 'pipeline_failed' ;;
        1) printf '%s\n' 'strict_json_rejected' ;;
        2) printf '%s\n' 'projection_filter_rejected' ;;
        *) printf '%s\n' 'kubernetes_api_read_failed' ;;
      esac
      ;;
    0)
      case "$2" in
        0) printf '%s\n' 'success' ;;
        125|130) printf '%s\n' 'pipeline_failed' ;;
        1) printf '%s\n' 'strict_json_rejected' ;;
        2) printf '%s\n' 'projection_filter_rejected' ;;
        *) printf '%s\n' 'pipeline_failed' ;;
      esac
      ;;
    *)
      printf '%s\n' 'kubernetes_api_read_failed'
      ;;
  esac
}

classified_api_failure_code() {
  case "$1" in
    authentication_exec_plugin_failure|unauthorized|authorization_rbac_forbidden|invalid_kubeconfig_context|tls_certificate|dns|transport_timeout_unreachable|unsupported_not_found_api)
      printf 'kubernetes_api_read_failed_%s\n' "$1"
      ;;
    generic_api_read_failure|*)
      printf '%s\n' 'kubernetes_api_read_failed'
      ;;
  esac
}

prepare_stderr_classification() {
  local output_name=$1
  stderr_class_file=$(mktemp "$cluster_dir/.${output_name}.stderr-class.XXXXXX")
}

read_stderr_classification() {
  local classification
  classification='generic_api_read_failure'
  if IFS= read -r classification < "$stderr_class_file"; then
    case "$classification" in
      authentication_exec_plugin_failure|unauthorized|authorization_rbac_forbidden|invalid_kubeconfig_context|tls_certificate|dns|transport_timeout_unreachable|unsupported_not_found_api|generic_api_read_failure) ;;
      *) classification='generic_api_read_failure' ;;
    esac
  fi
  rm -f -- "$stderr_class_file"
  stderr_classification=$classification
}

# Query and reduce in one pipeline. The raw kubectl response is never named
# as an output file; only jq's filtered result is moved into the context dir.
capture_json() {
  local output_name=$1
  local jq_filter=$2
  shift 2
  local temporary_output="$cluster_dir/.${output_name}.tmp"
  local -a pipeline_status
  local failure_code
  overall_declared_reads=$((overall_declared_reads + 1))

  if ! prepare_stderr_classification "$output_name"; then
    record_pipeline_failure "$output_name" pipeline_failed
    return 0
  fi
  if run_kubectl_bounded --timeout-seconds 30 --classification-fd 9 -- "$kubectl_binary" --kubeconfig "$kubeconfig_file" --context "$context" --request-timeout=30s "$@" 9>"$stderr_class_file" 2>/dev/null \
    | python3 "$strict_json_helper" 2>/dev/null | jq -S --argjson registry "$adapter_registry_json" "$jq_filter" 2>/dev/null > "$temporary_output"; then
    pipeline_status=( "${PIPESTATUS[@]}" )
  else
    pipeline_status=( "${PIPESTATUS[@]}" )
  fi
  read_stderr_classification
  failure_code=$(classify_pipeline_status "${pipeline_status[@]}")
  if [[ $failure_code == kubernetes_api_read_failed ]]; then
    failure_code=$(classified_api_failure_code "$stderr_classification")
  fi
  if [[ $failure_code == success && -s $temporary_output ]]; then
    mv -- "$temporary_output" "$cluster_dir/$output_name"
    return 0
  fi

  rm -f -- "$temporary_output"
  if [[ $failure_code == success ]]; then
    failure_code=pipeline_failed
  fi
  record_pipeline_failure "$output_name" "$failure_code"
  return 0
}

# Workload lists are fetched once. The jq adapter consumes the response
# directly and always negotiates its safe output: only registry-bound public
# component summaries can reach disk. Raw workload objects, private image
# references, commands, arguments, and environment values never receive a
# filename or leave the jq process.
capture_workload_json() {
  local output_name=$1
  shift
  local temporary_output="$cluster_dir/.${output_name}.tmp"
  local -a pipeline_status
  local failure_code
  local component_failure_code
  local component_failure_reason
  overall_declared_reads=$((overall_declared_reads + 1))

  if ! prepare_stderr_classification "$output_name"; then
    record_pipeline_failure "$output_name" pipeline_failed
    if [[ $include_component_configuration == true ]]; then
      jq -cn --arg code 'COMPONENT_CONFIGURATION_PIPELINE_FAILED' --arg reason 'The collector could not create a private diagnostic channel.' --arg sourceFile "$output_name" '{code: $code, reason: $reason, requiredForEvaluation: true, sourceFile: $sourceFile}' >> "$component_configuration_omissions"
    fi
    return 0
  fi
  if run_kubectl_bounded --timeout-seconds 30 --classification-fd 9 -- "$kubectl_binary" --kubeconfig "$kubeconfig_file" --context "$context" --request-timeout=30s "$@" 9>"$stderr_class_file" 2>/dev/null \
    | python3 "$strict_json_helper" 2>/dev/null | jq -S --argjson registry "$adapter_registry_json" --arg safeOutput true --arg roleEvidenceVersion "$component_role_evidence_version" -f "$adapter_filter_file" 2>/dev/null > "$temporary_output"; then
    pipeline_status=( "${PIPESTATUS[@]}" )
  else
    pipeline_status=( "${PIPESTATUS[@]}" )
  fi
  read_stderr_classification
  failure_code=$(classify_pipeline_status "${pipeline_status[@]}")
  if [[ $failure_code == kubernetes_api_read_failed ]]; then
    failure_code=$(classified_api_failure_code "$stderr_classification")
  fi
  if [[ $failure_code == success && -s $temporary_output ]]; then
    if [[ $include_component_configuration == true ]] && jq -e '.publicImages[]? | select(.componentId == "pkg:oci/cert-manager/cert-manager")' "$temporary_output" >/dev/null 2>&1; then
      cert_manager_workload_present=true
    fi
    jq -S '.publicImages' "$temporary_output" > "$cluster_dir/$output_name"
    if [[ $include_component_configuration == true ]]; then
      candidate_count=$(jq '.configuration | length' "$temporary_output")
      existing_count=$(wc -l < "$component_configuration_fragments" | tr -d ' ')
      if [[ $candidate_count =~ ^[0-9]+$ ]] && (( existing_count + candidate_count <= component_configuration_max_fragments )); then
        jq -c '.configuration[]?' "$temporary_output" >> "$component_configuration_fragments"
        jq -c --arg sourceFile "$output_name" '.omissions[]? | . + {sourceFile: $sourceFile}' "$temporary_output" >> "$component_configuration_omissions"
      else
        jq -cn --arg code 'COMPONENT_CONFIGURATION_OUTPUT_LIMIT_EXCEEDED' --arg reason 'The bounded component configuration fragment limit was exceeded; additional observations remain UNKNOWN.' --arg sourceFile "$output_name" '{code: $code, reason: $reason, requiredForEvaluation: true, sourceFile: $sourceFile}' >> "$component_configuration_omissions"
      fi
    fi
    rm -f -- "$temporary_output"
    return 0
  fi

  rm -f -- "$temporary_output"
  if [[ $failure_code == success ]]; then
    failure_code=pipeline_failed
  fi
  record_pipeline_failure "$output_name" "$failure_code"
  if [[ $include_component_configuration == true ]]; then
    component_failure_code=$(component_configuration_failure_code "$failure_code")
    component_failure_reason=$(pipeline_failure_reason "$failure_code")
    jq -cn --arg code "$component_failure_code" --arg reason "$component_failure_reason" --arg sourceFile "$output_name" '{code: $code, reason: $reason, requiredForEvaluation: true, sourceFile: $sourceFile}' >> "$component_configuration_omissions"
  fi
  return 0
}

capture_api_versions() {
  local output_name=$1
  local raw_path=$2
  local jq_filter=$3
  local temporary_output="$cluster_dir/.${output_name}.tmp"
  local -a pipeline_status
  local failure_code
  overall_declared_reads=$((overall_declared_reads + 1))

  if ! prepare_stderr_classification "$output_name"; then
    record_pipeline_failure "$output_name" pipeline_failed
    return 0
  fi
  if run_kubectl_bounded --timeout-seconds 30 --classification-fd 9 -- "$kubectl_binary" --kubeconfig "$kubeconfig_file" --context "$context" --request-timeout=30s \
    get --raw="$raw_path" 9>"$stderr_class_file" 2>/dev/null | python3 "$strict_json_helper" 2>/dev/null | jq -S "$jq_filter" 2>/dev/null > "$temporary_output"; then
    pipeline_status=( "${PIPESTATUS[@]}" )
  else
    pipeline_status=( "${PIPESTATUS[@]}" )
  fi
  read_stderr_classification
  failure_code=$(classify_pipeline_status "${pipeline_status[@]}")
  if [[ $failure_code == kubernetes_api_read_failed ]]; then
    failure_code=$(classified_api_failure_code "$stderr_classification")
  fi
  if [[ $failure_code == success && -s $temporary_output ]]; then
    mv -- "$temporary_output" "$cluster_dir/$output_name"
    return 0
  fi

  rm -f -- "$temporary_output"
  if [[ $failure_code == success ]]; then
    failure_code=pipeline_failed
  fi
  record_pipeline_failure "$output_name" "$failure_code"
  return 0
}

# CRD schemas make a single get-list response unusually large.  A kubectl
# --chunk-size hint is not a sufficient bound: servers may ignore it and a
# page can still exceed the strict validator while carrying expensive schema
# fields.  Page the raw API explicitly and retain only compact allow-listed
# CRD projections; raw pages never receive a filename.
capture_crd_surface() {
  local output_name=$1
  local temporary_output
  local page_projection_file
  local projected_items_file
  local base_path='/apis/apiextensions.k8s.io/v1/customresourcedefinitions'
  local raw_path
  local continue_token=''
  local encoded_continue
  local next_token
  local token_hash
  local seen_token_hashes=''
  local resource_version_hash=''
  local page_resource_version
  local page_number=0
  local page_count
  local version_count
  local total_items=0
  local total_versions=0
  local projected_bytes=0
  local crd_started_at
  local elapsed_seconds
  local remaining_seconds
  local page_timeout_seconds
  local failure_code
  local local_merge_status
  local -a pipeline_status
  overall_declared_reads=$((overall_declared_reads + 1))
  if ! temporary_output=$(mktemp "$cluster_dir/.${output_name}.tmp.XXXXXX") || \
     ! page_projection_file=$(mktemp "$cluster_dir/.${output_name}.page.XXXXXX") || \
     ! projected_items_file=$(mktemp "$cluster_dir/.${output_name}.items.XXXXXX"); then
    rm -f -- "${temporary_output:-}" "${page_projection_file:-}" "${projected_items_file:-}"
    record_pipeline_failure "$output_name" pipeline_failed
    return 0
  fi
  crd_started_at=$(date +%s)

  while :; do
    elapsed_seconds=$(( $(date +%s) - crd_started_at ))
    remaining_seconds=$(( crd_overall_timeout_seconds - elapsed_seconds ))
    if (( remaining_seconds < 1 )); then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    fi
    page_timeout_seconds=$remaining_seconds
    if (( page_timeout_seconds > 30 )); then
      page_timeout_seconds=30
    fi
    page_number=$((page_number + 1))
    if (( page_number > crd_max_pages )); then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    fi

    raw_path="${base_path}?limit=${crd_page_limit}"
    if [[ -n $continue_token ]]; then
      encoded_continue=$(printf '%s' "$continue_token" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""), end="")') || {
        rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
        record_pipeline_failure "$output_name" pipeline_failed
        return 0
      }
      raw_path="${raw_path}&continue=${encoded_continue}"
    fi

    if ! prepare_stderr_classification "$output_name"; then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    fi
    if run_kubectl_bounded --timeout-seconds "$page_timeout_seconds" --classification-fd 9 -- "$kubectl_binary" --kubeconfig "$kubeconfig_file" --context "$context" --request-timeout=30s \
      get --raw="$raw_path" 9>"$stderr_class_file" 2>/dev/null \
      | python3 "$local_json_stage_helper" --timeout-seconds "$page_timeout_seconds" --strict-json "$strict_json_helper" --jq-filter "$crd_page_projection_helper" --page-limit "$crd_page_limit" \
      > "$page_projection_file"; then
      pipeline_status=( "${PIPESTATUS[@]}" )
    else
      pipeline_status=( "${PIPESTATUS[@]}" )
    fi
    read_stderr_classification
    failure_code=$(classify_crd_pipeline_status "${pipeline_status[@]}")
    if [[ $failure_code == kubernetes_api_read_failed ]]; then
      failure_code=$(classified_api_failure_code "$stderr_classification")
    fi
    if [[ $failure_code != success ]]; then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" "$failure_code"
      return 0
    fi

    page_resource_version=$(jq -r '.resourceVersion' "$page_projection_file") || {
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    }
    token_hash=$(printf '%s' "$page_resource_version" | shasum -a 256 | awk '{print $1}')
    if [[ -z $resource_version_hash ]]; then
      resource_version_hash=$token_hash
    elif [[ $resource_version_hash != "$token_hash" ]]; then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    fi

    if ! page_count=$(jq -r '.items | length' "$page_projection_file") || ! version_count=$(jq -r '[.items[].versions | length] | add // 0' "$page_projection_file"); then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    fi
    total_items=$((total_items + page_count))
    total_versions=$((total_versions + version_count))
    if (( total_items > crd_max_items || total_versions > crd_max_versions )); then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" projection_filter_rejected
      return 0
    fi
    if ! jq -c '.items[]' "$page_projection_file" >> "$projected_items_file"; then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    fi
    projected_bytes=$(wc -c < "$projected_items_file" | tr -d ' ')
    if [[ ! $projected_bytes =~ ^[0-9]+$ ]] || (( projected_bytes > crd_max_projected_bytes )); then
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" projection_filter_rejected
      return 0
    fi

    next_token=$(jq -r '.continue' "$page_projection_file") || {
      rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
      record_pipeline_failure "$output_name" pipeline_failed
      return 0
    }
    if [[ -z $next_token ]]; then
      break
    fi
    token_hash=$(printf '%s' "$next_token" | shasum -a 256 | awk '{print $1}')
    case " $seen_token_hashes " in
      *" $token_hash "*)
        rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
        record_pipeline_failure "$output_name" pipeline_failed
        return 0
        ;;
    esac
    seen_token_hashes="$seen_token_hashes $token_hash"
    continue_token=$next_token
  done

  elapsed_seconds=$(( $(date +%s) - crd_started_at ))
  remaining_seconds=$(( crd_overall_timeout_seconds - elapsed_seconds ))
  if (( remaining_seconds < 1 )); then
    rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
    record_pipeline_failure "$output_name" pipeline_failed
    return 0
  fi
  local_merge_status=0
  python3 "$local_json_stage_helper" --timeout-seconds "$remaining_seconds" --jq-only --slurp --jq-filter "$crd_final_merge_helper" \
    < "$projected_items_file" > "$temporary_output" || local_merge_status=$?
  if (( local_merge_status != 0 )); then
    rm -f -- "$page_projection_file" "$projected_items_file" "$temporary_output"
    if (( local_merge_status == 2 )); then
      record_pipeline_failure "$output_name" projection_filter_rejected
    else
      record_pipeline_failure "$output_name" pipeline_failed
    fi
    return 0
  fi
  rm -f -- "$page_projection_file" "$projected_items_file"
  if [[ ! -s $temporary_output ]]; then
    rm -f -- "$temporary_output"
    record_pipeline_failure "$output_name" pipeline_failed
    return 0
  fi
  mv -- "$temporary_output" "$cluster_dir/$output_name"
  return 0
}

for context in "$@"; do
  directory=$(printf '%03d' "$context_index")
  cluster_dir="$run_dir/$directory"
  mkdir -p -- "$cluster_dir"
  chmod 700 "$cluster_dir"
  : > "$cluster_dir/omissions.tsv"

  context_digest=$(context_hash "$context")
  printf 'Context %s (%s)\n' "$directory" "$context_digest"

  capture_json server-version.json '
    if (type != "object" or (.gitVersion | type) != "string" or .gitVersion == "")
    then error("invalid server version")
    else {
      gitVersion,
      gitCommit: (.gitCommit // null),
      gitTreeState: (.gitTreeState // null),
      buildDate: (.buildDate // null),
      goVersion: (.goVersion // null),
      compiler: (.compiler // null),
      platform: (.platform // null)
    }
    end
  ' get --raw=/version

  capture_json node-profiles.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 20000)
    then error("invalid or excessive node response")
    elif any(.items[]?;
      (.status.nodeInfo | type) != "object" or
      (.status.nodeInfo.kubeletVersion | type) != "string" or (.status.nodeInfo.kubeletVersion | length) == 0 or
      (.status.nodeInfo.containerRuntimeVersion | type) != "string" or (.status.nodeInfo.containerRuntimeVersion | length) == 0 or
      (.status.nodeInfo.osImage | type) != "string" or (.status.nodeInfo.osImage | length) == 0 or
      (.status.nodeInfo.kernelVersion | type) != "string" or (.status.nodeInfo.kernelVersion | length) == 0 or
      (.status.nodeInfo.architecture | type) != "string" or (.status.nodeInfo.architecture | length) == 0 or
      (.status.nodeInfo.operatingSystem | type) != "string" or (.status.nodeInfo.operatingSystem | length) == 0)
    then error("invalid node version or runtime fields")
    else {
      nodeCount: (.items | length),
      profiles: [
        .items[] |
        {
          kubeletVersion: .status.nodeInfo.kubeletVersion,
          kubeProxyVersion: (.status.nodeInfo.kubeProxyVersion // "unknown"),
          containerRuntimeVersion: .status.nodeInfo.containerRuntimeVersion,
          osImage: .status.nodeInfo.osImage,
          kernelVersion: .status.nodeInfo.kernelVersion,
          architecture: .status.nodeInfo.architecture,
          operatingSystem: .status.nodeInfo.operatingSystem,
          providerScheme: ((.spec.providerID // "unknown") | split(":")[0])
        }
      ]
      | sort_by(.)
      | group_by(.)
      | map({profile: .[0], count: length})
    }
    end
  ' get nodes --chunk-size=200 -o json

  # Keep this defined for both collection modes.  The component projection
  # is optional, but its workload-presence predicate must never depend on an
  # unset shell variable under `set -u`.
  cert_manager_workload_present=false
  if [[ $include_component_configuration == true ]]; then
    component_configuration_fragments="$cluster_dir/.component-configuration.ndjson"
    component_configuration_omissions="$cluster_dir/.component-configuration-omissions.ndjson"
    : > "$component_configuration_fragments"
    : > "$component_configuration_omissions"
    # Presence is based on the independently parsed public image projection,
    # not on successful argument/predicate parsing. This preserves UNKNOWN for
    # a detected cert-manager workload whose args are malformed or absent.
  fi

  capture_workload_json deployment-images.json \
    get deployments.apps --all-namespaces --chunk-size=200 -o json
  capture_workload_json daemonset-images.json \
    get daemonsets.apps --all-namespaces --chunk-size=200 -o json
  capture_workload_json statefulset-images.json \
    get statefulsets.apps --all-namespaces --chunk-size=200 -o json
  capture_workload_json replicaset-images.json \
    get replicasets.apps --all-namespaces --chunk-size=200 -o json
  capture_workload_json job-images.json \
    get jobs.batch --all-namespaces --chunk-size=200 -o json
  capture_workload_json cronjob-images.json \
    get cronjobs.batch --all-namespaces --chunk-size=200 -o json
  capture_workload_json replicationcontroller-images.json \
    get replicationcontrollers --all-namespaces --chunk-size=200 -o json

  if [[ $include_pod_status_images == true ]]; then
    capture_json pod-status-images.json '
      def image_reference_without_runtime_prefix:
        sub("^(docker-pullable|containerd)://"; "");
      def public_identity:
        image_reference_without_runtime_prefix
        | sub("@sha256:[0-9a-fA-F]{64}$"; "")
        | if startswith("docker.io/") then .[10:]
          elif startswith("index.docker.io/") then .[17:]
          else .
          end
        | sub(":([^/:]+)$"; "");
      def public_version:
        ((capture(":(?<version>[^/:]+)$")? | .version) // null)
        | if type == "string" and length <= 128 and test("^v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$") then . else null end;
      def public_binding:
        image_reference_without_runtime_prefix as $reference
        | ($reference | public_identity) as $identity
        | ([$registry.adapters[] | select((.identities | index($identity)) != null)][0] // null) as $adapter
        | if $adapter == null then null
          elif ($reference | test("^(?:(?:docker\\.io|index\\.docker\\.io)/)?[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]+@sha256:[0-9a-f]{64}$")) then
            {componentId: $adapter.componentId, observedVersion: null, versionScheme: "digest"}
          elif ($reference | test("^(?:(?:docker\\.io|index\\.docker\\.io)/)?[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]+:[^/:]+$")) and (($reference | public_version) != null) then
            {componentId: $adapter.componentId, observedVersion: ($reference | public_version), versionScheme: "tag"}
          else null
          end;
      if (type != "object" or (.items | type) != "array" or (.items | length) > 100000)
      then error("invalid or excessive Pod response")
      elif any(.items[]?;
        (.metadata.namespace | type) != "string" or
        ((.status.initContainerStatuses // []) | type) != "array" or
        ((.status.containerStatuses // []) | type) != "array" or
        any(((.status.initContainerStatuses // []) + (.status.containerStatuses // []))[]?;
          (.image | type) != "string" or (.image | length) == 0 or (.image | length) > 4096 or
          (.imageID != null and ((.imageID | type) != "string" or (.imageID | length) > 4096)) or
          (.ready != null and ((.ready | type) != "boolean")) or
          (.restartCount != null and ((.restartCount | type) != "number" or (.restartCount < 0) or ((.restartCount | floor) != .restartCount)))))
      then error("invalid Pod status image or status fields")
      else [
        .items[] as $pod
        | (($pod.status.initContainerStatuses // []) + ($pod.status.containerStatuses // []))[]?
        | .image as $rawImage
        | (.imageID // null) as $rawImageID
        | ($rawImage | public_binding) as $publicImage
        | (if ($rawImageID | type) == "string" and ($rawImageID | length) > 0 then ($rawImageID | public_binding) else null end) as $publicImageID
        | {
            scope: (if $pod.metadata.namespace == "kube-system" then "system" else "non-system" end),
            imageIdentity: (if $publicImage then $publicImage.componentId else "PRIVATE_IMAGE_IDENTITY_OMITTED" end),
            observedVersion: (if $publicImage then $publicImage.observedVersion else null end),
            versionScheme: (if $publicImage then $publicImage.versionScheme else "unknown" end),
            publicImageIDBound: ($publicImage != null and $publicImageID != null and $publicImage.componentId == $publicImageID.componentId),
            ready: (.ready // false),
            restartCount: (.restartCount // 0)
          }
      ]
      | sort_by([.scope, .imageIdentity, (.observedVersion // ""), .versionScheme, .publicImageIDBound])
      | group_by({scope, imageIdentity, observedVersion, versionScheme, publicImageIDBound})
      | map({
          scope: .[0].scope,
          imageIdentity: .[0].imageIdentity,
          observedVersion: .[0].observedVersion,
          versionScheme: .[0].versionScheme,
          publicImageIDBound: .[0].publicImageIDBound,
          statusContainerCount: length,
          readyContainerCount: (map(select(.ready == true)) | length),
          restartCount: (map(.restartCount) | add)
        })
      end
    ' get pods --all-namespaces --chunk-size=200 -o json
  fi

  capture_crd_surface crd-api-surface.json

  capture_json aggregated-apis.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 20000)
    then error("invalid or excessive APIService response")
    elif any(.items[]?;
      (.metadata.name | type) != "string" or (.metadata.name | length) == 0 or
      (.spec.version | type) != "string" or (.spec.version | length) == 0 or
      (.spec.group != null and ((.spec.group | type) != "string" or (.spec.group | length) == 0)))
    then error("invalid APIService identity or version")
    else [
      .items[] | {
        group: (.spec.group // "core"),
        version: .spec.version,
        serviceConfigured: (.spec.service != null),
        available: ([.status.conditions[]? | select(.type == "Available") | .status][0] // null)
      }
    ] | sort_by([.group, .version])
    end
  ' get apiservices.apiregistration.k8s.io --chunk-size=200 -o json

  webhook_filter='
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive webhook response")
    elif any(.items[]?;
      (.kind | type) != "string" or (.kind | length) == 0 or
      (.webhooks | type) != "array" or
      any(.webhooks[]?;
        (.admissionReviewVersions | type) != "array" or
        (.rules | type) != "array" or
        any(.rules[]?;
          (.apiGroups | type) != "array" or
          (.apiVersions | type) != "array" or
          (.operations | type) != "array" or
          (.resources | type) != "array"))
    )
    then error("invalid webhook arrays or rules")
    else [
      .items[] | {
        kind,
          webhooks: [
          .webhooks[] | {
            failurePolicy: (.failurePolicy // null),
            matchPolicy: (.matchPolicy // null),
            sideEffects: (.sideEffects // null),
            timeoutSeconds: (.timeoutSeconds // null),
            admissionReviewVersions: .admissionReviewVersions,
            rules: [
              .rules[] | {
                apiGroups: .apiGroups,
                apiVersions: .apiVersions,
                operations: .operations,
                resources: .resources,
                scope: (.scope // null)
              }
            ],
            clientType: (
              if .clientConfig.service != null then "service"
              elif .clientConfig.url != null then "url"
              else "unknown"
              end
            ),
            # Only the cert-manager webhook Service identity is
            # eligible.  Keep the name/namespace transient; the projection
            # receives only this closed boolean.
            identityPresent: (.clientConfig.service != null and (.clientConfig.service.name | type) == "string" and .clientConfig.service.name == "cert-manager-webhook" and (.clientConfig.service.namespace // "cert-manager") == "cert-manager")
          }
        ]
      }
    ] | sort_by(.kind)
    end
  '
  capture_json mutating-webhooks.json "$webhook_filter" \
    get mutatingwebhookconfigurations.admissionregistration.k8s.io --chunk-size=200 -o json
  capture_json validating-webhooks.json "$webhook_filter" \
    get validatingwebhookconfigurations.admissionregistration.k8s.io --chunk-size=200 -o json

  capture_json admission-policy-surface.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive admission policy response")
    elif any(.items[]?;
      ((.spec.validations // []) | type) != "array" or
      ((.spec.variables // []) | type) != "array" or
      (.spec.matchConstraints.resourceRules != null and ((.spec.matchConstraints.resourceRules | type) != "array")) or
      any((.spec.matchConstraints.resourceRules // [])[]?;
        (.apiGroups | type) != "array" or
        (.apiVersions | type) != "array" or
        (.operations | type) != "array" or
        (.resources | type) != "array"))
    then error("invalid admission policy arrays")
    else [
      .items[] | {
        failurePolicy: (.spec.failurePolicy // null),
        validationCount: ((.spec.validations // []) | length),
        variableCount: ((.spec.variables // []) | length),
        resourceRules: [
          .spec.matchConstraints.resourceRules[]? | {
            apiGroups: (.apiGroups // []),
            apiVersions: (.apiVersions // []),
            operations: (.operations // []),
            resources: (.resources // []),
            scope: (.scope // null)
          }
        ]
      }
    ]
    end
  ' get validatingadmissionpolicies.admissionregistration.k8s.io --chunk-size=200 -o json

  capture_json admission-policy-bindings.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive admission policy binding response")
    elif any(.items[]?;
      ((.spec.validationActions // []) | type) != "array" or
      any((.spec.validationActions // [])[]?; type != "string" or length == 0) or
      (.spec.paramRef.parameterNotFoundAction != null and ((.spec.paramRef.parameterNotFoundAction | type) != "string")))
    then error("invalid admission policy binding arrays or actions")
    else [
      .items[] | {
        matchResourcesConfigured: (.spec.matchResources != null),
        paramRefConfigured: (.spec.paramRef != null),
        parameterNotFoundAction: (.spec.paramRef.parameterNotFoundAction // null),
        validationActions: (.spec.validationActions // [])
      }
    ] | sort_by([(.validationActions | join(",")), (.parameterNotFoundAction // "")])
    end
  ' get validatingadmissionpolicybindings.admissionregistration.k8s.io --chunk-size=200 -o json

  if [[ $cert_manager_workload_present == true ]]; then
    # Cert-manager-specific predicates are aggregates over bounded rule fields;
    # subject, role, namespace, and object names never leave jq.
  capture_json cert-manager-rbac-surface.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive RBAC response")
    elif any(.items[]?; (.metadata.name | type) != "string" or ((.rules // []) | type) != "array" or any((.rules // [])[]?; (.apiGroups | type) != "array" or (.resources | type) != "array" or (.verbs | type) != "array"))
    then error("invalid RBAC rule arrays")
    else . as $input | def roleClass($object): if $object.metadata.name == "cert-manager-controller" then "controller" elif $object.metadata.name == "cert-manager-webhook" then "webhook" elif $object.metadata.name == "cert-manager-cainjector" then "cainjector" elif $object.metadata.name == "cert-manager-startupapicheck" then "startupapicheck" else empty end;
      ["controller", "webhook", "cainjector", "startupapicheck"] as $classes |
      reduce $classes[] as $class ({}; .[$class] = {
        serviceaccountsTokenCreate: ([$input.items[]? | . as $role | select((roleClass($role) // "") == $class) | $role.rules[]? | select((.apiGroups | index("")) != null and (.resources | index("serviceaccounts/token")) != null and (.verbs | index("create")) != null)] | length > 0),
        certManagerAPIGroups: ([$input.items[]? | . as $role | select((roleClass($role) // "") == $class) | $role.rules[]? | select(any(.apiGroups[]?; . == "cert-manager.io") and any(.resources[]?; . == "certificates" or . == "certificaterequests" or . == "issuers" or . == "clusterissuers") and any(.verbs[]?; . == "get" or . == "list" or . == "watch"))] | length > 0),
        acmeAPIGroup: ([$input.items[]? | . as $role | select((roleClass($role) // "") == $class) | $role.rules[]? | select(any(.apiGroups[]?; . == "acme.cert-manager.io") and any(.resources[]?; . == "challenges" or . == "orders") and any(.verbs[]?; . == "get" or . == "list" or . == "watch"))] | length > 0)
      })
    end
  ' get clusterroles.rbac.authorization.k8s.io --chunk-size=200 -o json

  capture_json cert-manager-role-surface.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive Role response")
    elif any(.items[]?; (.metadata.name | type) != "string" or (.metadata.namespace | type) != "string" or ((.rules // []) | type) != "array" or any((.rules // [])[]?; (.apiGroups | type) != "array" or (.resources | type) != "array" or (.verbs | type) != "array"))
    then error("invalid Role rule arrays")
    else . as $input | def roleClass($object): if $object.metadata.name == "cert-manager-controller" then "controller" elif $object.metadata.name == "cert-manager-webhook" then "webhook" elif $object.metadata.name == "cert-manager-cainjector" then "cainjector" elif $object.metadata.name == "cert-manager-startupapicheck" then "startupapicheck" else empty end;
      ["controller", "webhook", "cainjector", "startupapicheck"] as $classes |
      reduce $classes[] as $class ({}; .[$class] = {
        serviceaccountsTokenCreate: ([$input.items[]? | . as $role | select(.metadata.namespace == "cert-manager" and (roleClass($role) // "") == $class) | $role.rules[]? | select((.apiGroups | index("")) != null and (.resources | index("serviceaccounts/token")) != null and (.verbs | index("create")) != null)] | length > 0),
        certManagerAPIGroups: ([$input.items[]? | . as $role | select(.metadata.namespace == "cert-manager" and (roleClass($role) // "") == $class) | $role.rules[]? | select(any(.apiGroups[]?; . == "cert-manager.io") and any(.resources[]?; . == "certificates" or . == "certificaterequests" or . == "issuers" or . == "clusterissuers") and any(.verbs[]?; . == "get" or . == "list" or . == "watch"))] | length > 0),
        acmeAPIGroup: ([$input.items[]? | . as $role | select(.metadata.namespace == "cert-manager" and (roleClass($role) // "") == $class) | $role.rules[]? | select(any(.apiGroups[]?; . == "acme.cert-manager.io") and any(.resources[]?; . == "challenges" or . == "orders") and any(.verbs[]?; . == "get" or . == "list" or . == "watch"))] | length > 0)
      })
    end
  ' get roles.rbac.authorization.k8s.io --all-namespaces --chunk-size=200 -o json

  capture_json cert-manager-rolebindings.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive RoleBinding response")
    elif any(.items[]?; ((.subjects? // []) | type) != "array" or (.roleRef | type) != "object" or (.roleRef.kind | type) != "string" or (.roleRef.kind != "Role" and .roleRef.kind != "ClusterRole") or (.roleRef.name | type) != "string" or (.roleRef.name | length) == 0) then error("invalid RoleBinding subjects or role reference")
    else . as $input | def roleClass($object): if $object.roleRef.name == "cert-manager-controller" then "controller" elif $object.roleRef.name == "cert-manager-webhook" then "webhook" elif $object.roleRef.name == "cert-manager-cainjector" then "cainjector" elif $object.roleRef.name == "cert-manager-startupapicheck" then "startupapicheck" else empty end;
      def subjectName($class): if $class == "controller" then "cert-manager" elif $class == "webhook" then "cert-manager-webhook" elif $class == "cainjector" then "cert-manager-cainjector" elif $class == "startupapicheck" then "cert-manager-startupapicheck" else empty end;
      ["controller", "webhook", "cainjector", "startupapicheck"] as $classes |
      reduce $classes[] as $class ({}; .[$class] = any($input.items[]?; . as $binding | (.metadata.namespace // "") == "cert-manager" and ((.roleRef.kind == "Role" and .metadata.namespace == "cert-manager") or .roleRef.kind == "ClusterRole") and (roleClass($binding) // "") == $class and any($binding.subjects[]?; .kind == "ServiceAccount" and .namespace == "cert-manager" and .name == subjectName($class))))
    end
  ' get rolebindings.rbac.authorization.k8s.io --all-namespaces --chunk-size=200 -o json

  capture_json cert-manager-clusterrolebindings.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive ClusterRoleBinding response")
    elif any(.items[]?; ((.subjects? // []) | type) != "array" or (.roleRef | type) != "object" or (.roleRef.kind | type) != "string" or .roleRef.kind != "ClusterRole" or (.roleRef.name | type) != "string" or (.roleRef.name | length) == 0) then error("invalid ClusterRoleBinding subjects or role reference")
    else . as $input |
      def roleClass($object): if $object.roleRef.name == "cert-manager-controller" then "controller" elif $object.roleRef.name == "cert-manager-webhook" then "webhook" elif $object.roleRef.name == "cert-manager-cainjector" then "cainjector" elif $object.roleRef.name == "cert-manager-startupapicheck" then "startupapicheck" else empty end;
      def subjectName($class): if $class == "controller" then "cert-manager" elif $class == "webhook" then "cert-manager-webhook" elif $class == "cainjector" then "cert-manager-cainjector" elif $class == "startupapicheck" then "cert-manager-startupapicheck" else empty end;
      ["controller", "webhook", "cainjector", "startupapicheck"] as $classes |
      reduce $classes[] as $class ({}; .[$class] = any($input.items[]?; . as $binding | (roleClass($binding) // "") == $class and any($binding.subjects[]?; .kind == "ServiceAccount" and .namespace == "cert-manager" and .name == subjectName($class))))
    end
  ' get clusterrolebindings.rbac.authorization.k8s.io --chunk-size=200 -o json

  capture_json cert-manager-health.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive health response")
    elif any(.items[]?;
      ((.spec.replicas? != null) and ((.spec.replicas | type) != "number" or .spec.replicas < 0 or .spec.replicas > 1000000 or (.spec.replicas | floor) != .spec.replicas)) or
      ((.status.readyReplicas? != null) and ((.status.readyReplicas | type) != "number" or .status.readyReplicas < 0 or .status.readyReplicas > 1000000 or (.status.readyReplicas | floor) != .status.readyReplicas)) or
      ((.status.availableReplicas? != null) and ((.status.availableReplicas | type) != "number" or .status.availableReplicas < 0 or .status.availableReplicas > 1000000 or (.status.availableReplicas | floor) != .status.availableReplicas)))
    then error("invalid or excessive health replica count")
    elif any(.items[]?; (.spec.template.spec.containers | type) != "array" or any(.spec.template.spec.containers[]?; (.image | type) != "string"))
    then error("invalid health workload")
    else {
      desiredCount: ([.items[]? | select(any(.spec.template.spec.containers[]?; (.image | test("^(docker\\.io/jetstack|quay\\.io/jetstack|jetstack)/cert-manager-(controller|webhook|cainjector|startupapicheck)(:|@)"))))] | map((.spec.replicas // 1) | if type == "number" and . >= 0 and . <= 1000000 and floor == . then . else empty end) | add // 0),
      readyCount: ([.items[]? | select(any(.spec.template.spec.containers[]?; (.image | test("^(docker\\.io/jetstack|quay\\.io/jetstack|jetstack)/cert-manager-(controller|webhook|cainjector|startupapicheck)(:|@)")))) | (.status.readyReplicas // 0)] | add // 0),
      availableCount: ([.items[]? | select(any(.spec.template.spec.containers[]?; (.image | test("^(docker\\.io/jetstack|quay\\.io/jetstack|jetstack)/cert-manager-(controller|webhook|cainjector|startupapicheck)(:|@)")))) | (.status.availableReplicas // 0)] | add // 0)
    } | if any([.desiredCount, .readyCount, .availableCount][]; type != "number" or . < 0 or . > 1000000 or floor != .) then error("aggregate health count exceeded bound") else . end
    end
  ' get deployments.apps --all-namespaces --chunk-size=200 -o json

  # Prove monitor identity by joining monitor selectors to an observed
  # cert-manager Service and to a target Pod owned by a workload. Only the
  # two closed booleans leave this filter; names, labels, and owner refs do
  # not enter the persisted surface.
  capture_json cert-manager-monitor-targets.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 20000)
    then error("invalid or excessive monitor target response")
    elif any(.items[]?; (.kind | type) != "string" or ((.metadata.namespace // "") | type) != "string")
    then error("invalid monitor target metadata")
    else
      def targetLabels: {"app.kubernetes.io/name":"cert-manager", "app.kubernetes.io/instance":"cert-manager"};
      def hasTargetLabels($labels): ($labels | type) == "object" and all((targetLabels | keys[]); . as $key | $labels[$key] == targetLabels[$key]);
      def certImage: test("^(docker\\.io/jetstack|quay\\.io/jetstack|jetstack)/cert-manager-(controller|webhook|cainjector|startupapicheck)(:|@)");
      def ownedTargetPod:
        .kind == "Pod" and .metadata.namespace == "cert-manager" and
        hasTargetLabels(.metadata.labels // {}) and
        any(.spec.containers[]?; (.image | type) == "string" and (.image | certImage)) and
        any((.metadata.ownerReferences // [])[]?; (.kind == "ReplicaSet" or .kind == "Deployment") and (.name | type) == "string" and (.name | test("^cert-manager(-|$)")));
      def targetService:
        .kind == "Service" and .metadata.namespace == "cert-manager" and
        (.metadata.name == "cert-manager" or .metadata.name == "cert-manager-webhook") and
        ((.spec.selector // {}) | type) == "object" and hasTargetLabels(.spec.selector);
      ([.items[]? | select(ownedTargetPod) | .metadata.labels] ) as $pods |
      ([.items[]? | select(targetService) | .spec.selector] ) as $services |
      {podTargetProven: ($pods | length > 0), serviceTargetProven: any($services[]?; . as $selector | any($pods[]?; . as $labels | all(($selector | keys[]); . as $key | $labels[$key] == $selector[$key])))}
    end
  ' get services,pods --all-namespaces --chunk-size=200 -o json

  capture_json cert-manager-servicemonitors.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid ServiceMonitor response")
    elif any(.items[]?; (.spec.endpoints | type) != "array" or ((.spec.selector.matchLabels // {}) | type) != "object" or ((.spec.namespaceSelector.matchNames // []) | type) != "array" or any(.spec.endpoints[]?; type != "object" or (.path? != null and (.path | type) != "string") or (.port? != null and (.port | type) != "string") or (.targetPort? != null and ((.targetPort | type) != "string" and (.targetPort | type) != "number")))) then error("invalid ServiceMonitor endpoints or selector")
    else ([.items[] | select(.spec.selector.matchLabels["app.kubernetes.io/instance"] == "cert-manager" and .spec.selector.matchLabels["app.kubernetes.io/name"] == "cert-manager" and .spec.namespaceSelector.matchNames == ["cert-manager"] and any(.spec.endpoints[]?; (.port == "http-metrics" or .targetPort == "http-metrics" or .targetPort == 9402) and .path == "/metrics"))] | {serviceMonitorPresent: (length > 0), scrapePortPresent: (any(.[].spec.endpoints[]?; .port == "http-metrics" or .targetPort == "http-metrics" or .targetPort == 9402)), scrapePathPresent: (any(.[].spec.endpoints[]?; .path == "/metrics"))}) end
  ' get servicemonitors.monitoring.coreos.com --all-namespaces --chunk-size=200 -o json

  capture_json cert-manager-podmonitors.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid PodMonitor response")
    elif any(.items[]?; (.spec.podMetricsEndpoints | type) != "array" or ((.spec.selector.matchLabels // {}) | type) != "object" or ((.spec.namespaceSelector.matchNames // []) | type) != "array" or any(.spec.podMetricsEndpoints[]?; type != "object" or (.path? != null and (.path | type) != "string") or (.port? != null and (.port | type) != "string") or (.targetPort? != null and ((.targetPort | type) != "string" and (.targetPort | type) != "number")))) then error("invalid PodMonitor endpoints or selector")
    else ([.items[] | select(.spec.selector.matchLabels["app.kubernetes.io/instance"] == "cert-manager" and .spec.selector.matchLabels["app.kubernetes.io/name"] == "cert-manager" and .spec.namespaceSelector.matchNames == ["cert-manager"] and any(.spec.podMetricsEndpoints[]?; (.port == "http-metrics" or .targetPort == "http-metrics" or .targetPort == 9402) and .path == "/metrics"))] | {podMonitorPresent: (length > 0), scrapePortPresent: (any(.[].spec.podMetricsEndpoints[]?; .port == "http-metrics" or .targetPort == "http-metrics" or .targetPort == 9402)), scrapePathPresent: (any(.[].spec.podMetricsEndpoints[]?; .path == "/metrics"))}) end
    ' get podmonitors.monitoring.coreos.com --all-namespaces --chunk-size=200 -o json
  fi

  capture_json storage-surface.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive storage class response")
    elif any(.items[]?; (.provisioner | type) != "string" or (.provisioner | length) == 0)
    then error("invalid StorageClass provisioner")
    else [
      .items[] | {
        provisioner: .provisioner,
        reclaimPolicy: (.reclaimPolicy // null),
        volumeBindingMode: (.volumeBindingMode // null),
        allowVolumeExpansion: (.allowVolumeExpansion // null),
        parameterKeys: ((.parameters // {}) | keys | sort)
      }
    ] | sort_by([.provisioner, .volumeBindingMode, .reclaimPolicy])
    end
  ' get storageclasses.storage.k8s.io --chunk-size=200 -o json

  capture_json csi-driver-surface.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive CSI driver response")
    elif any(.items[]?; (.metadata.name | type) != "string" or (.metadata.name | length) == 0)
    then error("invalid CSI driver identity")
    else [
      .items[] | {
        driver: .metadata.name,
        attachRequired: (.spec.attachRequired // null),
        podInfoOnMount: (.spec.podInfoOnMount // null),
        storageCapacity: (.spec.storageCapacity // null),
        fsGroupPolicy: (.spec.fsGroupPolicy // null),
        requiresRepublish: (.spec.requiresRepublish // null),
        seLinuxMount: (.spec.seLinuxMount // null),
        tokenRequestsConfigured: ((.spec.tokenRequests // []) | length > 0),
        tokenRequestCount: ((.spec.tokenRequests // []) | length)
      }
    ] | sort_by(.driver)
    end
  ' get csidrivers.storage.k8s.io --chunk-size=200 -o json

  capture_json runtime-classes.json '
    if (type != "object" or (.items | type) != "array" or (.items | length) > 10000)
    then error("invalid or excessive RuntimeClass response")
    elif any(.items[]?; (.handler | type) != "string" or (.handler | length) == 0)
    then error("invalid RuntimeClass handler")
    else [
      .items[] | {
        handler: .handler,
        overheadConfigured: (.overhead != null),
        schedulingConfigured: (.scheduling != null)
      }
    ] | sort_by(.handler)
    end
  ' get runtimeclasses.node.k8s.io --chunk-size=200 -o json

  capture_api_versions core-api-versions.json /api '
    if (type != "object" or (.versions | type) != "array" or any(.versions[]?; (type != "string" or length == 0))) then error("invalid core discovery")
    else {versions: (.versions | sort)} end
  '

  capture_api_versions grouped-api-versions.json /apis '
    if (type != "object" or (.groups | type) != "array" or (.groups | length) > 10000)
    then error("invalid grouped discovery")
    elif any(.groups[]?;
      (.name | type) != "string" or (.name | length) == 0 or
      (.versions | type) != "array" or any(.versions[]?; (.version | type) != "string" or (.version | length) == 0))
    then error("invalid grouped API version")
    else {
      groups: [
        .groups[] | {
          name,
          preferredVersion: (.preferredVersion.version // null),
          versions: ([.versions[]?.version] | sort)
        }
      ] | sort_by(.name)
    }
    end
  '

  if [[ $include_component_configuration == true ]]; then
    # Join only the already-reduced cert-manager surfaces. Every unavailable
    # API is passed as an explicit false availability bit; its predicate is
    # omitted and a bounded UNKNOWN omission is retained.
    cm_empty="$cluster_dir/.cert-manager-empty.json"
    cm_metrics="$cluster_dir/.cert-manager-metrics.json"
    cm_projection="$cluster_dir/.cert-manager-projection.json"
    printf '%s\n' '[]' > "$cm_empty"
    if [[ -f $cluster_dir/cert-manager-rbac-surface.json ]]; then cm_rbac_file="$cluster_dir/cert-manager-rbac-surface.json"; rbac_available=true; else cm_rbac_file="$cm_empty"; rbac_available=false; fi
    if [[ -f $cluster_dir/cert-manager-role-surface.json ]]; then cm_role_file="$cluster_dir/cert-manager-role-surface.json"; role_available=true; else cm_role_file="$cm_empty"; role_available=false; fi
    if [[ -f $cluster_dir/cert-manager-rolebindings.json ]]; then cm_rolebindings_file="$cluster_dir/cert-manager-rolebindings.json"; rolebindings_available=true; else cm_rolebindings_file="$cm_empty"; rolebindings_available=false; fi
    if [[ -f $cluster_dir/cert-manager-clusterrolebindings.json ]]; then cm_clusterrolebindings_file="$cluster_dir/cert-manager-clusterrolebindings.json"; clusterrolebindings_available=true; else cm_clusterrolebindings_file="$cm_empty"; clusterrolebindings_available=false; fi
    if [[ -f $cluster_dir/cert-manager-health.json ]]; then cm_health_file="$cluster_dir/cert-manager-health.json"; health_available=true; else cm_health_file="$cm_empty"; health_available=false; fi
    if [[ -f $cluster_dir/cert-manager-servicemonitors.json ]]; then cm_sm_file="$cluster_dir/cert-manager-servicemonitors.json"; sm_available=true; else cm_sm_file="$cm_empty"; sm_available=false; fi
    if [[ -f $cluster_dir/cert-manager-podmonitors.json ]]; then cm_pm_file="$cluster_dir/cert-manager-podmonitors.json"; pm_available=true; else cm_pm_file="$cm_empty"; pm_available=false; fi
    if [[ -f $cluster_dir/cert-manager-monitor-targets.json ]]; then cm_monitor_targets_file="$cluster_dir/cert-manager-monitor-targets.json"; monitor_targets_available=true; else cm_monitor_targets_file="$cm_empty"; monitor_targets_available=false; fi
    if [[ -f $cluster_dir/crd-api-surface.json ]]; then cm_crd_file="$cluster_dir/crd-api-surface.json"; crd_available=true; else cm_crd_file="$cm_empty"; crd_available=false; fi
    if [[ -f $cluster_dir/validating-webhooks.json ]]; then cm_validating_file="$cluster_dir/validating-webhooks.json"; validating_available=true; else cm_validating_file="$cm_empty"; validating_available=false; fi
    if [[ -f $cluster_dir/mutating-webhooks.json ]]; then cm_mutating_file="$cluster_dir/mutating-webhooks.json"; mutating_available=true; else cm_mutating_file="$cm_empty"; mutating_available=false; fi
    if [[ $rbac_available == true && $role_available == true && $rolebindings_available == true && $clusterrolebindings_available == true ]]; then rbac_available=true; else rbac_available=false; fi
    # The aggregate has both monitor API dimensions. If either API is absent
    # or forbidden, omit the whole metrics projection rather than converting
    # the unavailable monitor kind into a false predicate.
    if [[ $sm_available == true && $pm_available == true && $monitor_targets_available == true ]]; then metrics_available=true; else metrics_available=false; fi
    jq -n -S --slurpfile servicemonitors "$cm_sm_file" --slurpfile podmonitors "$cm_pm_file" --slurpfile targets "$cm_monitor_targets_file" \
      '($servicemonitors[0] // {}) as $sm0 | ($podmonitors[0] // {}) as $pm0 | ($targets[0] // {}) as $target0 | ($sm0 | if type == "object" then . else {} end) as $sm | ($pm0 | if type == "object" then . else {} end) as $pm | ($target0 | if type == "object" then . else {} end) as $target | {serviceMonitorPresent: (($sm.serviceMonitorPresent == true) and ($target.serviceTargetProven == true)), podMonitorPresent: (($pm.podMonitorPresent == true) and ($target.podTargetProven == true)), scrapePortPresent: (($sm.scrapePortPresent == true and $target.serviceTargetProven == true) or ($pm.scrapePortPresent == true and $target.podTargetProven == true)), scrapePathPresent: (($sm.scrapePathPresent == true and $target.serviceTargetProven == true) or ($pm.scrapePathPresent == true and $target.podTargetProven == true)), monitorIdentityProven: (($target.serviceTargetProven == true) or ($target.podTargetProven == true))}' > "$cm_metrics"
    jq -n -S \
      --slurpfile configuration "$component_configuration_fragments" \
      --slurpfile crds "$cm_crd_file" \
      --slurpfile validating "$cm_validating_file" \
      --slurpfile mutating "$cm_mutating_file" \
      --slurpfile rbac "$cm_rbac_file" \
      --slurpfile roles "$cm_role_file" \
      --slurpfile rolebindings "$cm_rolebindings_file" \
      --slurpfile clusterrolebindings "$cm_clusterrolebindings_file" \
      --slurpfile metrics "$cm_metrics" \
      --slurpfile health "$cm_health_file" \
      --argjson crdAvailable "$crd_available" \
      --argjson validatingAvailable "$validating_available" \
      --argjson mutatingAvailable "$mutating_available" \
      --argjson rbacAvailable "$rbac_available" \
      --argjson roleBindingsAvailable "$rolebindings_available" \
      --argjson clusterRoleBindingsAvailable "$clusterrolebindings_available" \
      --argjson metricsAvailable "$metrics_available" \
      --argjson healthAvailable "$health_available" \
      -f "$cert_manager_projection_helper" > "$cm_projection"
    jq -c '.row // empty' "$cm_projection" >> "$component_configuration_fragments"
    jq -c --arg sourceFile 'cert-manager-derived-predicates' '.omissions[]? | . + {sourceFile: $sourceFile}' "$cm_projection" >> "$component_configuration_omissions"
    jq -n -S \
      --arg apiVersion 'prufyx.io/configuration-surface/v1alpha1' \
      --arg kind 'ComponentConfigurationSurface' \
      --arg adapterVersion "$component_adapter_version" \
      --arg registryVersion "$component_registry_version" \
      --arg registryDigest "$adapter_registry_digest" \
      --arg filterDigest "$adapter_filter_digest" \
      --arg aggregateDigest "$adapter_aggregate_digest" \
      --arg strictJsonDigest "$strict_json_digest" \
      --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
      --arg kubectlStderrClassifierTaxonomyVersion "$kubectl_stderr_classifier_taxonomy_version" \
      --arg kubectlStderrClassifierAuthority "$kubectl_stderr_classifier_authority" \
      --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" \
      --arg certManagerProjectionDigest "$cert_manager_projection_digest" \
      --arg licenseDisposition 'metadata_only_derived_predicates' \
      --slurpfile configuration "$component_configuration_fragments" \
      --slurpfile inputOmissions "$component_configuration_omissions" \
      -f "$adapter_aggregate_file" > "$cluster_dir/component-configuration-surface.json"
    rm -f -- "$component_configuration_fragments" "$component_configuration_omissions" "$cm_empty" "$cm_metrics" "$cm_projection"
  fi

  if [[ -s $cluster_dir/omissions.tsv ]]; then
    collection_status=partial_for_declared_surface
  else
    collection_status=complete_for_declared_surface
  fi
  omission_count=$(wc -l < "$cluster_dir/omissions.tsv" | tr -d ' ')

  jq -n -S \
    --arg schema 'prufyx.io/kubeconfig-api-observation/v1alpha1' \
    --arg generatedAt "$generated_at" \
    --arg contextHash "$context_digest" \
    --arg collectionStatus "$collection_status" \
    --argjson includePodStatusImages "$include_pod_status_images" \
    --argjson includeComponentConfiguration "$include_component_configuration" \
    --arg componentConfigurationAdapterVersion "$component_adapter_version" \
      --arg componentConfigurationRegistryVersion "$component_registry_version" \
      --arg componentConfigurationRegistryDigest "$adapter_registry_digest" \
      --arg componentConfigurationFilterDigest "$adapter_filter_digest" \
      --arg componentConfigurationAggregateDigest "$adapter_aggregate_digest" \
      --arg componentConfigurationStrictJsonDigest "$strict_json_digest" \
      --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
      --arg kubectlStderrClassifierTaxonomyVersion "$kubectl_stderr_classifier_taxonomy_version" \
      --arg kubectlStderrClassifierAuthority "$kubectl_stderr_classifier_authority" \
      --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" \
      --arg crdPaginationPolicyVersion "$crd_pagination_policy_version" \
      --arg crdPaginationEndpoint "$crd_pagination_endpoint" \
      --arg crdPaginationProfile "$crd_pagination_profile" \
      --arg crdLocalJsonStageDigest "$local_json_stage_digest" \
      --arg crdPageProjectionDigest "$crd_page_projection_digest" \
      --arg crdFinalMergeDigest "$crd_final_merge_digest" \
      --argjson crdPageLimit "$crd_page_limit" \
      --argjson crdMaxPages "$crd_max_pages" \
      --argjson crdMaxItems "$crd_max_items" \
      --argjson crdMaxVersions "$crd_max_versions" \
      --argjson crdMaxProjectedBytes "$crd_max_projected_bytes" \
      --argjson crdOverallTimeoutSeconds "$crd_overall_timeout_seconds" \
    --argjson omissionCount "$omission_count" \
    '{
      schema: $schema,
      format: "KubeconfigAPIObservation",
      generatedAt: $generatedAt,
      contextHash: $contextHash,
      collectionStatus: $collectionStatus,
      includePodStatusImages: $includePodStatusImages,
      includeComponentConfiguration: $includeComponentConfiguration,
      componentConfigurationAdapterVersion: (if $includeComponentConfiguration then $componentConfigurationAdapterVersion else null end),
      componentConfigurationRegistryVersion: (if $includeComponentConfiguration then $componentConfigurationRegistryVersion else null end),
      componentConfigurationRegistryDigest: (if $includeComponentConfiguration then $componentConfigurationRegistryDigest else null end),
      componentConfigurationFilterDigest: (if $includeComponentConfiguration then $componentConfigurationFilterDigest else null end),
      componentConfigurationAggregateDigest: (if $includeComponentConfiguration then $componentConfigurationAggregateDigest else null end),
      componentConfigurationStrictJsonDigest: (if $includeComponentConfiguration then $componentConfigurationStrictJsonDigest else null end),
      kubectlStderrClassifierDigest: $kubectlStderrClassifierDigest,
      kubectlStderrClassifierTaxonomyVersion: $kubectlStderrClassifierTaxonomyVersion,
      kubectlStderrClassifierAuthority: $kubectlStderrClassifierAuthority,
      kubectlBoundedRunnerDigest: $kubectlBoundedRunnerDigest,
      crdPaginationPolicy: {
        version: $crdPaginationPolicyVersion,
        endpoint: $crdPaginationEndpoint,
        profile: $crdPaginationProfile,
        pageLimit: $crdPageLimit,
        maxPages: $crdMaxPages,
        maxItems: $crdMaxItems,
        maxVersions: $crdMaxVersions,
        maxProjectedBytes: $crdMaxProjectedBytes,
        overallTimeoutSeconds: $crdOverallTimeoutSeconds,
        localJsonStageDigest: $crdLocalJsonStageDigest,
        pageProjectionDigest: $crdPageProjectionDigest,
        finalMergeDigest: $crdFinalMergeDigest
      },
      omissionCount: $omissionCount,
      dataClassification: "confidential local inventory",
      authority: "local unsigned API observation",
      evaluationEligible: false,
      notACompatibilitySnapshot: true,
      retained: [
        "Kubernetes server and node component versions",
        "canonical public component identities and bounded versions from approved workload projections",
        (if $includePodStatusImages then "optional typed registry-bound public Pod component/version summaries and image-ID binding booleans" else "Pod status images and image IDs are not retained" end),
        "optional reviewed public component configuration predicates from workload arguments",
        (if $includeComponentConfiguration then "cert-manager exact six CRD served/storage, admission, scoped RBAC, scrape-presence, bounded health-count, and closed install-mode predicates" else "cert-manager configuration predicates are omitted unless explicitly opted in" end),
        "CRD, aggregated API, admission policy/webhook, storage, CSI, and RuntimeClass signals",
        "core and grouped API discovery versions"
      ],
      omittedByPolicy: [
        "Secrets and Secret payloads",
        "ConfigMaps and ConfigMap payloads",
        "logs, events, metrics, and traces",
        "raw Kubernetes manifests",
        "object, namespace, workload, Pod, and node names",
        "labels, annotations, environment values, and command arguments",
        "unrecognized or private workload and Pod image identities and image IDs",
        "credentials, endpoints, provider instance IDs, and business data",
        "Helm release metadata, rendered values, and component configuration values",
        "cert-manager names, namespaces, subjects, raw labels/annotations, DNS endpoint/address values, Secret/ConfigMap data, pod names/logs/status details, and unallowlisted flags"
      ],
      disclosure: [
        "workload projections exclude raw image references, image IDs, private registry paths, and workload identity; only exact registry-bound public component summaries are retained",
        (if $includePodStatusImages then "Pod status output retains typed component/version summaries for exact public registry identities with strict version syntax; private, unrecognized, or malformed identities use a fixed omission marker, and image IDs reduce to a same-component binding boolean" else "Pod status images are omitted" end),
        "CRD, CSI, storage, webhook, and API names may expose platform architecture",
        "contextHash is a randomized per-run pseudonym: repeated contexts match only within this observation run; the key is discarded, cross-run replay is intentionally unavailable, and the value is not authenticated cluster identity",
        "kubectl may execute an authentication plugin configured by the explicit kubeconfig",
        "kubectl and its exec plugin receive only PATH, HOME, USER, and TMPDIR when present, a fixed C locale, the explicit kubeconfig, and operator-selected --exec-env values; values are not retained",
        "complete API responses pass through local kubectl and jq before filtered fields are retained"
      ]
    }' > "$cluster_dir/snapshot-metadata.json"

  (
    cd "$cluster_dir"
    find . -type f ! -name MANIFEST.sha256 -print \
      | LC_ALL=C sort \
      | while IFS= read -r file; do shasum -a 256 "$file"; done \
      > MANIFEST.sha256
  )

  jq -c -S \
    --arg directory "$directory" \
    --arg contextHash "$context_digest" \
    --arg status "$collection_status" \
    --argjson omissionCount "$omission_count" \
    '{directory: $directory, contextHash: $contextHash, collectionStatus: $status, omissionCount: $omissionCount}' \
    "$cluster_dir/snapshot-metadata.json" >> "$run_dir/index.ndjson"

  context_index=$((context_index + 1))
done

jq -s -S \
  --arg schema 'prufyx.io/kubeconfig-api-observation-index/v1alpha1' \
  --arg generatedAt "$generated_at" \
  '{schema: $schema, generatedAt: $generatedAt, contexts: .}' \
  "$run_dir/index.ndjson" > "$run_dir/index.json"
rm -f -- "$run_dir/index.ndjson"

(
  cd "$run_dir"
  find . -type f ! -name MANIFEST.sha256 -print \
    | LC_ALL=C sort \
    | while IFS= read -r file; do shasum -a 256 "$file"; done \
    > MANIFEST.sha256
)
chmod 600 "$run_dir"/*.json "$run_dir"/MANIFEST.sha256 2>/dev/null || true

printf 'Created local API observation directory: %s\n' "$run_dir"
printf 'Verify context files with: (cd %s && shasum -a 256 -c MANIFEST.sha256)\n' "$run_dir"
printf 'Failure histogram: kubernetes_api_read_failed=%d kubernetes_api_read_failed_authentication_exec_plugin_failure=%d kubernetes_api_read_failed_unauthorized=%d kubernetes_api_read_failed_authorization_rbac_forbidden=%d kubernetes_api_read_failed_invalid_kubeconfig_context=%d kubernetes_api_read_failed_tls_certificate=%d kubernetes_api_read_failed_dns=%d kubernetes_api_read_failed_transport_timeout_unreachable=%d kubernetes_api_read_failed_unsupported_not_found_api=%d kubernetes_api_read_failed_generic_api_read_failure=%d strict_json_rejected=%d projection_filter_rejected=%d pipeline_failed=%d\n' \
  "$failure_histogram_kubernetes_api_read_failed" \
  "$failure_histogram_kubernetes_api_read_failed_authentication_exec_plugin_failure" \
  "$failure_histogram_kubernetes_api_read_failed_unauthorized" \
  "$failure_histogram_kubernetes_api_read_failed_authorization_rbac_forbidden" \
  "$failure_histogram_kubernetes_api_read_failed_invalid_kubeconfig_context" \
  "$failure_histogram_kubernetes_api_read_failed_tls_certificate" \
  "$failure_histogram_kubernetes_api_read_failed_dns" \
  "$failure_histogram_kubernetes_api_read_failed_transport_timeout_unreachable" \
  "$failure_histogram_kubernetes_api_read_failed_unsupported_not_found_api" \
  "$failure_histogram_kubernetes_api_read_failed_generic_api_read_failure" \
  "$failure_histogram_strict_json_rejected" \
  "$failure_histogram_projection_filter_rejected" \
  "$failure_histogram_pipeline_failed" >&2
if (( overall_declared_reads > 0 && overall_kubernetes_api_read_failures == overall_declared_reads )); then
  printf '%s\n' 'WARNING: all declared API reads failed at kubernetes_api_read_failed; check the reviewed kubeconfig endpoint, authentication, and read-only RBAC.' >&2
fi
if (( overall_omissions > 0 )) && [[ $allow_partial != true ]]; then
  printf 'The observation is partial: %d declared reads were unavailable or invalid.\n' "$overall_omissions" >&2
  exit 6
fi
if (( overall_omissions > 0 )); then
  printf 'WARNING: partial observation accepted by --allow-partial; omission count: %d.\n' "$overall_omissions" >&2
fi
