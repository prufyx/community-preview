#!/usr/bin/env bash
set -Eeuo pipefail

# Synthetic jq-only contract tests.  This never invokes kubectl or the
# snapshot collector and contains no customer snapshot input.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
script_dir=$(pwd -P)
registry=component-configuration-adapters.json
registry_v3=component-configuration-adapters-v3.json
filter=component-configuration-adapter.jq
aggregate=component-configuration-aggregate.jq
filter_v3=component-configuration-adapter-v3.jq
aggregate_v3=component-configuration-aggregate-v3.jq
fixture=testdata/component-configuration-workloads.json
snapshot_script=kubeconfig-api-snapshot.sh
strict_json=reject-duplicate-json.py
kubectl_stderr_classifier=classify-kubectl-stderr.py
kubectl_bounded_runner=run-kubectl-bounded.py
registry_json=$(jq -c . "$registry")
registry_v3_json=$(jq -c . "$registry_v3")
registry_digest="sha256:$(shasum -a 256 "$registry" | awk '{print $1}')"
registry_v3_digest="sha256:$(shasum -a 256 "$registry_v3" | awk '{print $1}')"
filter_digest="sha256:$(shasum -a 256 "$filter" | awk '{print $1}')"
aggregate_digest="sha256:$(shasum -a 256 "$aggregate" | awk '{print $1}')"
filter_v3_digest="sha256:$(shasum -a 256 "$filter_v3" | awk '{print $1}')"
aggregate_v3_digest="sha256:$(shasum -a 256 "$aggregate_v3" | awk '{print $1}')"
strict_json_digest="sha256:$(shasum -a 256 "$strict_json" | awk '{print $1}')"
kubectl_stderr_classifier_digest="sha256:$(shasum -a 256 "$kubectl_stderr_classifier" | awk '{print $1}')"
kubectl_bounded_runner_digest="sha256:$(shasum -a 256 "$kubectl_bounded_runner" | awk '{print $1}')"
test "$strict_json_digest" = 'sha256:799a69405e30ee90e1929d48560fa68df57f26cf12bd9c132ad6ad84c6c1b5a7'
test "$registry_v3_digest" = 'sha256:c2631adc13f82d35f20518736a1816d1a1e8155c69b2d0d805f4dd275678d186'

for dependency in jq shasum mktemp awk python3; do
  command -v "$dependency" >/dev/null 2>&1 || { printf 'missing dependency: %s\n' "$dependency" >&2; exit 2; }
done

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

# Compile and exercise the exact registry validator embedded in the
# production snapshot script. This catches jq parser changes before any
# collector invocation is possible.
awk '/PRUFYX_REGISTRY_VALIDATOR_BEGIN/{inside=1; next} /PRUFYX_REGISTRY_VALIDATOR_END/{inside=0} inside {print}' "$snapshot_script" > "$tmp/registry-validator.jq"
test -s "$tmp/registry-validator.jq"
jq -n -f "$tmp/registry-validator.jq" >/dev/null
jq -e -f "$tmp/registry-validator.jq" "$registry" >/dev/null
jq -e -f "$tmp/registry-validator.jq" "$registry_v3" >/dev/null
python3 "$strict_json" < "$registry" >/dev/null
python3 - "$tmp/oversized.json" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write("x" * (16 * 1024 * 1024 + 1))
PY
if python3 "$strict_json" < "$tmp/oversized.json" >/dev/null; then
  printf '%s\n' 'strict JSON pass-through accepted an oversized response' >&2
  exit 1
fi
printf '%s\n' '{"duplicate":1,"duplicate":2}' > "$tmp/duplicate.json"
if python3 "$strict_json" < "$tmp/duplicate.json" >/dev/null; then
  printf '%s\n' 'strict JSON pass-through accepted duplicate object keys' >&2
  exit 1
fi
jq 'del(.adapters[0].predicates)' "$registry" > "$tmp/registry-missing-predicates.json"
if jq -e -f "$tmp/registry-validator.jq" "$tmp/registry-missing-predicates.json" >/dev/null 2>&1; then
  printf '%s\n' 'registry validator accepted missing predicates' >&2
  exit 1
fi
jq '.adapters[0].componentId = "pkg:oci/Private/hidden"' "$registry" > "$tmp/registry-malformed-component.json"
if jq -e -f "$tmp/registry-validator.jq" "$tmp/registry-malformed-component.json" >/dev/null 2>&1; then
  printf '%s\n' 'registry validator accepted malformed component identity' >&2
  exit 1
fi
for variant in metadata-extra metadata-policy predicate-id-duplicate predicate-flag-duplicate identity-duplicate; do
  case "$variant" in
    metadata-extra) jq '.metadata.extra = true' "$registry" > "$tmp/registry-$variant.json" ;;
    metadata-policy) jq '.metadata.policy = "permissive"' "$registry" > "$tmp/registry-$variant.json" ;;
    predicate-id-duplicate) jq '.adapters[1].predicates[0].id = .adapters[0].predicates[0].id' "$registry" > "$tmp/registry-$variant.json" ;;
    predicate-flag-duplicate) jq '.adapters[0].predicates[0].flags = ["--web.enable-admin-api", "--web.enable-admin-api"]' "$registry" > "$tmp/registry-$variant.json" ;;
    identity-duplicate) jq '.adapters[1].identities += [.adapters[0].identities[0]]' "$registry" > "$tmp/registry-$variant.json" ;;
  esac
  if jq -e -f "$tmp/registry-validator.jq" "$tmp/registry-$variant.json" >/dev/null 2>&1; then
    printf 'registry validator accepted %s\n' "$variant" >&2
    exit 1
  fi
done
jq '.adapters[1].roleEvidenceClass = "runtime_process_identity_v1"' "$registry" > "$tmp/registry-unsafe-evidence-class.json"
if jq -e -f "$tmp/registry-validator.jq" "$tmp/registry-unsafe-evidence-class.json" >/dev/null 2>&1; then
  printf '%s\n' 'registry validator accepted an unapproved runtime evidence class' >&2
  exit 1
fi
jq -e -S --argjson registry "$registry_json" -f "$filter" "$fixture" > "$tmp/one.json"
jq -e -S --argjson registry "$registry_json" --arg safeOutput false -f "$filter" "$fixture" > "$tmp/one-v1-false.json"
cmp "$tmp/one.json" "$tmp/one-v1-false.json"
jq -e '.configuration | any(.[]; .componentId == "pkg:oci/prometheus/prometheus")' "$tmp/one.json" >/dev/null
jq -e '.configuration | any(.[]; .componentId == "pkg:oci/argoproj/argo-workflows")' "$tmp/one.json" >/dev/null
jq -e '.configuration | any(.[]; .componentId == "pkg:oci/cert-manager/cert-manager")' "$tmp/one.json" >/dev/null
jq -e '.configuration | all(.[]; (keys | index("image") | not) and (keys | index("args") | not))' "$tmp/one.json" >/dev/null
jq -e '.configuration | all(.[]; (.predicates | keys | all(. as $name | $name | startswith("component."))))' "$tmp/one.json" >/dev/null
jq -e '.omissions | any(.code == "COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED")' "$tmp/one.json" >/dev/null
jq -e '.omissions | any(.code == "COMPONENT_CONFIGURATION_PREDICATE_CONFLICT")' "$tmp/one.json" >/dev/null
jq -e '.omissions | any(.code == "COMPONENT_CONFIGURATION_PREDICATE_MALFORMED")' "$tmp/one.json" >/dev/null
if jq -e '.configuration | tostring | test("customer-secret|customer-endpoint|must-not-retain|password")' "$tmp/one.json" >/dev/null; then
  printf '%s\n' 'secret-like synthetic values crossed the configuration output boundary' >&2
  exit 1
fi

# Absent/explicit v1 remains roleless. Explicit v2 emits only the registered
# declared-container context token; true, unsupported, malformed, and
# conflicting negotiation fails before producing output.
assert_role_rejected() {
  local label=$1
  shift
  if jq -e -S --argjson registry "$registry_json" "$@" -f "$filter" "$fixture" > "$tmp/role-$label.out" 2> "$tmp/role-$label.err"; then
    printf 'role evidence negotiation accepted invalid matrix case: %s\n' "$label" >&2
    exit 1
  fi
  test ! -s "$tmp/role-$label.out"
  grep -F 'unsupported process-role evidence version' "$tmp/role-$label.err" >/dev/null
  if grep -E 'customer-secret|customer-endpoint|must-not-retain|password' "$tmp/role-$label.err" >/dev/null 2>&1; then
    printf '%s\n' 'role-evidence diagnostic leaked a raw synthetic value' >&2
    exit 1
  fi
}

jq -e -S --argjson registry "$registry_json" --arg roleEvidenceVersion v1 -f "$filter" "$fixture" > "$tmp/role-v1-explicit.json"
cmp "$tmp/one.json" "$tmp/role-v1-explicit.json"
jq '.items[2].spec.template.spec.containers[0].args = ["--namespaced", "--managed-namespace", "default"]' "$fixture" > "$tmp/v2-fixture.json"
jq -e -S --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/v2-fixture.json" > "$tmp/role-v2-explicit.json"
jq -e '
  . as $root
  | ($root.configuration[] | select(.componentId == "pkg:oci/argoproj/argo-workflows")
    | .roles == ["workflow-controller"]
      and (.predicateEvidence | length == 2)
      and all(.predicateEvidence[]; .sourceRole == "workflow-controller" and .evidenceClass == "declared_container_context_v1" and .state == "observed"))
' "$tmp/role-v2-explicit.json" >/dev/null
if jq -e 'tostring | test("customer-secret|customer-endpoint|must-not-retain|password|argocd-server")' "$tmp/role-v2-explicit.json" >/dev/null; then
  printf '%s\n' 'declared-role projection retained a private value or inferred the shared Argo CD role' >&2
  exit 1
fi
jq '.items = [.items[2]] | .items[0].spec.template.spec.containers[0].image = "quay.io/argoproj/argocd:v3.5.2" | .items[0].spec.template.spec.containers[0].args = ["--insecure=false"]' "$fixture" > "$tmp/shared-argocd.json"
jq -e -S --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/shared-argocd.json" > "$tmp/shared-argocd-out.json"
jq -e '(.configuration[0] | (has("roles") | not) and (has("predicateEvidence") | not)) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_UNAVAILABLE")' "$tmp/shared-argocd-out.json" >/dev/null
jq -e -S --argjson registry "$registry_json" --argjson emitRoleEvidence false -f "$filter" "$fixture" > "$tmp/role-emit-false.json"
cmp "$tmp/one.json" "$tmp/role-emit-false.json"
jq -e -S --argjson registry "$registry_json" --argjson roleEvidence false -f "$filter" "$fixture" > "$tmp/role-alias-false.json"
cmp "$tmp/one.json" "$tmp/role-alias-false.json"
assert_role_rejected emit-true --argjson emitRoleEvidence true
assert_role_rejected role-true --argjson roleEvidence true
assert_role_rejected role-v3 --arg roleEvidenceVersion v3
assert_role_rejected emit-malformed --arg emitRoleEvidence maybe
assert_role_rejected version-false --arg roleEvidenceVersion false
assert_role_rejected conflicting-disabled-v1 --arg roleEvidenceVersion v1 --argjson emitRoleEvidence false
assert_role_rejected conflicting-v1-v2 --arg emitRoleEvidence v1 --arg roleEvidenceVersion v2

# The cert-manager projection consumes only reduced synthetic surfaces. Verify
# the exact six CRDs, admission, RBAC, metrics, and bounded health counts, and
# verify unavailable APIs become omissions rather than false predicates.
projection_args=(
  --slurpfile configuration "$script_dir/testdata/cert-manager-projection-configuration.json"
  --slurpfile crds "$script_dir/testdata/cert-manager-projection-crds.json"
  --slurpfile validating "$script_dir/testdata/cert-manager-projection-webhooks.json"
  --slurpfile mutating "$script_dir/testdata/cert-manager-projection-webhooks.json"
  --slurpfile rbac "$script_dir/testdata/cert-manager-projection-rbac.json"
  --slurpfile roles "$script_dir/testdata/cert-manager-projection-roles.json"
  --slurpfile rolebindings "$script_dir/testdata/cert-manager-projection-rolebindings.json"
  --slurpfile clusterrolebindings "$script_dir/testdata/cert-manager-projection-clusterrolebindings.json"
  --slurpfile metrics "$script_dir/testdata/cert-manager-projection-metrics.json"
  --slurpfile health "$script_dir/testdata/cert-manager-projection-health.json"
  --argjson crdAvailable true --argjson validatingAvailable true
  --argjson mutatingAvailable true --argjson rbacAvailable true
  --argjson metricsAvailable true --argjson healthAvailable true
)
jq -n -S "${projection_args[@]}" -f "$script_dir/cert-manager-projection.jq" > "$tmp/cert-projection.json"
jq -e '.row.predicates["component.cert_manager.crd_certificates_v1_served"] == true and
  .row.predicates["component.cert_manager.crd_orders_v1_storage"] == true and
  .row.predicates["component.cert_manager.admission_webhook_v1"] == true and
  .row.predicates["component.cert_manager.rbac_acme_api_group"] == true and
  .row.predicates["component.cert_manager.metrics_scrape_path_present"] == true and
  .row.predicates["component.cert_manager.health_ready_count"] == 3 and
  .row.predicates["component.cert_manager.install_mode"] == "unknown"' "$tmp/cert-projection.json" >/dev/null
if jq -e 'tostring | test("namespace|endpoint|address|secret|password")' "$tmp/cert-projection.json" >/dev/null; then
  printf '%s\n' 'cert-manager projection leaked a sensitive identity/value' >&2
  exit 1
fi
jq -n -S \
  --slurpfile configuration "$script_dir/testdata/cert-manager-projection-configuration.json" \
  --slurpfile crds "$script_dir/testdata/cert-manager-projection-crds.json" \
  --slurpfile validating "$script_dir/testdata/cert-manager-projection-webhooks.json" \
  --slurpfile mutating "$script_dir/testdata/cert-manager-projection-webhooks.json" \
  --slurpfile rbac "$script_dir/testdata/cert-manager-projection-rbac.json" \
  --slurpfile roles "$script_dir/testdata/cert-manager-projection-roles.json" \
  --slurpfile rolebindings "$script_dir/testdata/cert-manager-projection-rolebindings.json" \
  --slurpfile clusterrolebindings "$script_dir/testdata/cert-manager-projection-clusterrolebindings.json" \
  --slurpfile metrics "$script_dir/testdata/cert-manager-projection-metrics.json" \
  --slurpfile health "$script_dir/testdata/cert-manager-projection-health.json" \
  --argjson crdAvailable false --argjson validatingAvailable true \
  --argjson mutatingAvailable true --argjson rbacAvailable true \
  --argjson metricsAvailable true --argjson healthAvailable true \
  -f "$script_dir/cert-manager-projection.jq" > "$tmp/cert-projection-missing.json"
jq -e '(.row.predicates | keys | all(test("^component\\.cert_manager\\.crd_") | not)) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_CRD_SURFACE_UNAVAILABLE")' "$tmp/cert-projection-missing.json" >/dev/null
projection_metrics_missing=("${projection_args[@]}")
for index in "${!projection_metrics_missing[@]}"; do
  if [[ ${projection_metrics_missing[$index]} == metricsAvailable ]]; then
    projection_metrics_missing[$((index + 1))]=false
  fi
done
jq -n -S "${projection_metrics_missing[@]}" -f "$script_dir/cert-manager-projection.jq" > "$tmp/cert-projection-metrics-missing.json"
jq -e '(.row.predicates | keys | all(test("^component\\.cert_manager\\.metrics_") | not)) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_API_UNAVAILABLE")' "$tmp/cert-projection-metrics-missing.json" >/dev/null
projection_metrics_unproven=("${projection_args[@]}")
for index in "${!projection_metrics_unproven[@]}"; do
  if [[ ${projection_metrics_unproven[$index]} == "$script_dir/testdata/cert-manager-projection-metrics.json" ]]; then
    projection_metrics_unproven[$index]="$tmp/cert-manager-monitor-target-unproven.json"
  fi
done
jq '.monitorIdentityProven = false' "$script_dir/testdata/cert-manager-projection-metrics.json" > "$tmp/cert-manager-monitor-target-unproven.json"
jq -n -S "${projection_metrics_unproven[@]}" -f "$script_dir/cert-manager-projection.jq" > "$tmp/cert-projection-metrics-unproven.json"
jq -e '(.row.predicates | keys | all(test("^component\\.cert_manager\\.metrics_") | not)) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_API_UNAVAILABLE" and (.reason | test("target workload identity")))' "$tmp/cert-projection-metrics-unproven.json" >/dev/null

# Cert-manager feature-gates are parsed as a closed allow-list of typed
# booleans; unrelated gates and their values never cross the output boundary.
jq '.items[4].spec.template.spec.containers[0].args += ["--feature-gates=ACMEUseARI=true,ListenerSets=false,CAInjectorMerging=true,UnrelatedSecretGate=true"]' "$fixture" > "$tmp/cert-feature-gates.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/cert-feature-gates.json" > "$tmp/cert-feature-gates.out"
jq -e '.configuration[] | select(.componentId == "pkg:oci/cert-manager/cert-manager") | .predicates["component.cert_manager.controller_present"] == true and .predicates["component.cert_manager.feature_gate_acme_use_ari"] == true and .predicates["component.cert_manager.feature_gate_listener_sets"] == false and .predicates["component.cert_manager.feature_gate_ca_injector_merging"] == true' "$tmp/cert-feature-gates.out" >/dev/null
if jq -e 'tostring | test("UnrelatedSecretGate|customer-secret|token=|endpoint=")' "$tmp/cert-feature-gates.out" >/dev/null; then
  printf '%s\n' 'unrelated feature-gate value crossed the configuration output boundary' >&2
  exit 1
fi
jq '.items[4].spec.template.spec.containers[0].args += ["--feature-gates=ListenerSets=true,ListenerSets=false"]' "$fixture" > "$tmp/cert-feature-conflict.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/cert-feature-conflict.json" | jq -e '.configuration | all(.[]; .componentId != "pkg:oci/cert-manager/cert-manager")' >/dev/null

# Reviewed workload-role contract: a Job is never effective configuration;
# init-only is omitted, while a mixed workload reads regular containers only.
jq '{items: [(.items[0] | .kind = "Job")]}' "$fixture" > "$tmp/job.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/job.json" \
  | jq -e '.configuration == [] and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_WORKLOAD_ROLE_UNSUPPORTED")' >/dev/null
jq '{items: [(.items[0] | .spec.template.spec.initContainers = .spec.template.spec.containers | .spec.template.spec.containers = [])]}' "$fixture" > "$tmp/init-only.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/init-only.json" \
  | jq -e '.configuration == [] and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_NO_REGULAR_CONTAINERS")' >/dev/null
jq '{items: [(.items[0] | .spec.template.spec.initContainers = [{image: "registry.private.invalid/hidden/secret:9.9.9", args: ["--password=do-not-retain"]}]) ]}' "$fixture" > "$tmp/mixed.json"
jq -e -S --argjson registry "$registry_json" -f "$filter" "$tmp/mixed.json" > "$tmp/mixed-out.json"
jq -e '.configuration | length == 1 and all(.[]; tostring | test("hidden|secret|password|do-not-retain") | not)' "$tmp/mixed-out.json" >/dev/null
jq -e '.publicImages | all(.[]; has("componentId") and has("observedVersion") and (tostring | test("quay.io|imageID|sha256:") | not))' "$tmp/mixed-out.json" >/dev/null
jq '.items[0].spec.template.spec.containers += [{image: "registry.private.invalid/customer/secret:9.9.9", args: ["--password=must-not-retain"]}]' "$tmp/mixed.json" > "$tmp/mixed-safe-input.json"
jq -e -S --argjson registry "$registry_json" --arg safeOutput true -f "$filter" "$tmp/mixed-safe-input.json" > "$tmp/mixed-safe-out.json"
jq -e '.images == [] and (.publicImages | length > 0) and (.configuration | length == 1)' "$tmp/mixed-safe-out.json" >/dev/null
if jq -e 'tostring | test("registry\\.private\\.invalid|do-not-retain|password")' "$tmp/mixed-safe-out.json" >/dev/null; then
  printf '%s\n' 'safe component output retained a raw private image or token' >&2
  exit 1
fi
jq '{items: [(.items[0] | .spec.template.spec.containers[0].image = "quay.io/prometheus/prometheus@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]}' "$fixture" > "$tmp/digest.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/digest.json" \
  | jq -e '.publicImages | any(.[]; .versionScheme == "digest" and .observedVersion == null)' >/dev/null
jq '{items: [(.items[0] | .spec.template.spec.containers[0].image = "quay.io/prometheus/prometheus:v3.14.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]}' "$fixture" > "$tmp/tag-digest.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/tag-digest.json" \
  | jq -e '(.publicImages | any(.[]; .componentId == "pkg:oci/prometheus/prometheus" and .versionScheme == "digest" and .observedVersion == null)) and (.configuration | any(.[]; .componentId == "pkg:oci/prometheus/prometheus" and .versionScheme == "digest" and .observedVersion == null))' >/dev/null
jq '{items: [(.items[0] | .spec.template.spec.containers[0].image = "quay.io/prometheus/prometheus")]}' "$fixture" > "$tmp/untagged.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/untagged.json" \
  | jq -e '.publicImages | any(.[]; .versionScheme == "unknown" and .observedVersion == null)' >/dev/null
for version in latest main master nightly dev snapshot arbitrary-tag 01.2.3 v01.2.3 1.02.3 1.2.03 1.2.3-01 1.2.3- 1.2.3-. 1.2.3-alpha..1; do
  jq --arg version "$version" '{items: [(.items[0] | .spec.template.spec.containers[0].image = ("quay.io/prometheus/prometheus:" + $version))]}' "$fixture" > "$tmp/tag-$version.json"
  jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/tag-$version.json" \
    | jq -e '(.configuration == []) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_VERSION_UNRESOLVED")' >/dev/null
done
for version in 0.0.0 1.2.3 v1.2.3 1.2.3-0 1.2.3-alpha.1 v1.2.3+build.7 1.2.3-alpha.1+build.7; do
  jq --arg version "$version" '{items: [(.items[0] | .spec.template.spec.containers[0].image = ("quay.io/prometheus/prometheus:" + $version))]}' "$fixture" > "$tmp/tag-valid-$version.json"
  jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/tag-valid-$version.json" \
    | jq -e --arg version "$version" 'any(.configuration[]; .observedVersion == $version and .versionScheme == "tag")' >/dev/null
done

for mode in inline-empty split-empty split-missing; do
  jq --arg mode "$mode" '
    .items[2].spec.template.spec.containers[0].args =
      (if $mode == "inline-empty" then ["--managed-namespace="]
       elif $mode == "split-empty" then ["--managed-namespace", ""]
       else ["--managed-namespace"] end)
  ' "$fixture" > "$tmp/presence-$mode.json"
  jq -e --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/presence-$mode.json" \
    | jq -e '(.configuration | any(.componentId == "pkg:oci/argoproj/argo-workflows") | not) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_PREDICATE_MALFORMED")' >/dev/null
done
for namespace in false none a a-b9 "$(printf 'a%.0s' {1..63})"; do
  jq --arg namespace "$namespace" '.items[2].spec.template.spec.containers[0].args = ["--managed-namespace", $namespace]' "$fixture" > "$tmp/presence-valid-name.json"
  jq -e --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/presence-valid-name.json" \
    | jq -e 'any(.configuration[]; .predicates["component.argo_workflows.managed_namespace_configured"] == true)' >/dev/null
done
for namespace in Upper invalid.name -leading trailing- "$(printf 'a%.0s' {1..64})"; do
  jq --arg namespace "$namespace" '.items[2].spec.template.spec.containers[0].args = ["--managed-namespace", $namespace]' "$fixture" > "$tmp/presence-invalid-name.json"
  jq -e --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/presence-invalid-name.json" \
    | jq -e '(.configuration | any(.componentId == "pkg:oci/argoproj/argo-workflows") | not) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_PREDICATE_MALFORMED")' >/dev/null
done
jq '.items[2].spec.template.spec.containers[0].args = ["--managed-namespace=first", "--managed-namespace", "second"]' "$fixture" > "$tmp/presence-conflict.json"
jq -e --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/presence-conflict.json" \
  | jq -e '(.configuration | any(.componentId == "pkg:oci/argoproj/argo-workflows") | not) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_PREDICATE_CONFLICT")' >/dev/null
for mode in inline split; do
  jq --arg mode "$mode" '
    .items[2].spec.template.spec.containers[0].args =
      (if $mode == "inline" then ["--managed-namespace=customer-secret"]
       else ["--managed-namespace", "customer-secret"] end)
  ' "$fixture" > "$tmp/presence-$mode.json"
  jq -e --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/presence-$mode.json" \
    | jq -e 'any(.configuration[]; .componentId == "pkg:oci/argoproj/argo-workflows" and .predicates["component.argo_workflows.managed_namespace_configured"] == true and .roles == ["workflow-controller"] and (.predicateEvidence | any(.predicateId == "component.argo_workflows.managed_namespace_configured" and .evidenceClass == "declared_container_context_v1"))) and (tostring | test("customer-secret") | not)' >/dev/null
done

jq '.items[0].spec.template.spec.containers[0].command = ["/bin/prometheus", "--password=must-not-retain"]' "$fixture" > "$tmp/command.json"
jq -e --argjson registry "$registry_json" -f "$filter" "$tmp/command.json" > "$tmp/command-out.json"
jq -e '(.configuration | any(.componentId == "pkg:oci/prometheus/prometheus") | not) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE")' "$tmp/command-out.json" >/dev/null
if jq -e 'tostring | test("must-not-retain|password")' "$tmp/command-out.json" >/dev/null; then
  printf '%s\n' 'command surface crossed the configuration output boundary' >&2
  exit 1
fi

# `--flag=value`, split values, duplicate equal values, duplicate conflicts,
# malformed enum values, and private identities are all covered above.  Run
# deterministic aggregation pressure at the declared 20/50/1000 sizes.
for count in 20 50 1000; do
  jq --argjson count "$count" '. as $root | .items = [range(0; $count) as $i | $root.items[2]]' "$tmp/v2-fixture.json" > "$tmp/input-$count.json"
  jq -e -S --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/input-$count.json" > "$tmp/out-$count-a.json"
  jq -e -S --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/input-$count.json" > "$tmp/out-$count-b.json"
  cmp "$tmp/out-$count-a.json" "$tmp/out-$count-b.json"
  test "$(jq '.configuration | length' "$tmp/out-$count-a.json")" -eq "$count"
  jq -c '.configuration[]' "$tmp/out-$count-a.json" > "$tmp/config-$count.ndjson"
  jq -c '.omissions[]? | . + {sourceFile: "synthetic-images.json"}' "$tmp/out-$count-a.json" > "$tmp/omissions-$count.ndjson"
  jq -n -S \
    --arg apiVersion 'prufyx.io/configuration-surface/v1alpha1' \
    --arg kind 'ComponentConfigurationSurface' \
    --arg adapterVersion 'component-configuration-adapter-v2' \
    --arg registryVersion 'v2' \
    --arg registryDigest "$registry_digest" \
    --arg filterDigest "$filter_digest" \
    --arg aggregateDigest "$aggregate_digest" \
    --arg strictJsonDigest "$strict_json_digest" \
    --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
    --arg kubectlStderrClassifierTaxonomyVersion 'kubectl-stderr-taxonomy-v1' \
    --arg kubectlStderrClassifierAuthority 'heuristic_local_diagnostic_not_proof' \
    --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" \
    --arg certManagerProjectionDigest "" \
    --arg licenseDisposition 'metadata_only_derived_predicates' \
    --slurpfile configuration "$tmp/config-$count.ndjson" \
    --slurpfile inputOmissions "$tmp/omissions-$count.ndjson" \
    -f "$aggregate" > "$tmp/surface-$count.json"
  test "$(jq '.components | length' "$tmp/surface-$count.json")" -eq 1
  test "$(jq '.components[0].observationCount' "$tmp/surface-$count.json")" -eq "$count"
  jq -e '.components[0].roles == ["workflow-controller"] and (.components[0].predicateEvidence | length == 2)' "$tmp/surface-$count.json" >/dev/null
done

# A mixed classified/unclassified row cannot retain positive role evidence.
jq -c '.configuration[] | select(.componentId == "pkg:oci/argoproj/argo-workflows")' "$tmp/role-v2-explicit.json" > "$tmp/mixed-role.ndjson"
jq -c '.configuration[] | select(.componentId == "pkg:oci/argoproj/argo-workflows") | del(.roles, .predicateEvidence)' "$tmp/role-v2-explicit.json" >> "$tmp/mixed-role.ndjson"
jq -n -S \
  --arg apiVersion 'prufyx.io/configuration-surface/v1alpha1' --arg kind 'ComponentConfigurationSurface' \
  --arg adapterVersion 'component-configuration-adapter-v2' --arg registryVersion 'v2' \
  --arg registryDigest "$registry_digest" --arg filterDigest "$filter_digest" --arg aggregateDigest "$aggregate_digest" \
  --arg strictJsonDigest "$strict_json_digest" --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
  --arg kubectlStderrClassifierTaxonomyVersion 'kubectl-stderr-taxonomy-v1' --arg kubectlStderrClassifierAuthority 'heuristic_local_diagnostic_not_proof' \
  --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" --arg certManagerProjectionDigest '' \
  --arg licenseDisposition 'metadata_only_derived_predicates' --slurpfile configuration "$tmp/mixed-role.ndjson" --argjson inputOmissions '[]' \
  -f "$aggregate" > "$tmp/mixed-role-surface.json"
jq -e '(.components[0].predicates | length) == 0 and ((.components[0] | has("roles")) | not) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS")' "$tmp/mixed-role-surface.json" >/dev/null

# Producer v3 admits only source-bound declared entrypoints and exact public
# image/version bindings. These fixtures contain public synthetic canaries;
# command lines and unrelated argument values must not cross the projection.
prom_255_image='docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad'
prom_310_image='docker.io/prom/prometheus:v3.1.0@sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2'
jq -n --arg image "$prom_255_image" '{items:[{kind:"Deployment",spec:{template:{spec:{containers:[{image:$image,command:["/bin/prometheus"],args:["--enable-feature=native-histograms,agent","--customer-token=PRUFYX_SYNTHETIC_SECRET_NEVER_RETAIN"]}],initContainers:[]}}}}]}' > "$tmp/v3-prom-255-agent.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-255-agent.out"
jq -e --arg digest 'sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad' '
  .configuration == [{componentId:"pkg:oci/prometheus/prometheus",observationCount:1,observationState:"observed",observedVersion:"2.55.1",predicateEvidence:[{evidenceClass:"declared_container_context_v1",predicateId:"component.prometheus.agent_mode",sourceRole:"server",state:"observed"},{evidenceClass:"declared_container_context_v1",predicateId:"component.prometheus.image_digest",sourceRole:"server",state:"observed"}],predicates:{"component.prometheus.agent_mode":true,"component.prometheus.image_digest":$digest},roles:["server"],versionConflict:false,versionScheme:"tag"}]' "$tmp/v3-prom-255-agent.out" >/dev/null
if jq -e 'tostring | test("customer-token|PRUFYX_SYNTHETIC_SECRET_NEVER_RETAIN")' "$tmp/v3-prom-255-agent.out" >/dev/null; then
  printf '%s\n' 'v3 Prometheus projection retained an unrelated raw argument' >&2
  exit 1
fi
jq '.items[0].spec.template.spec.containers[0].args = ["--enable-feature","native-histograms","--enable-feature=agent,agent"]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-255-repeated-feature.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-255-repeated-feature.json" | jq -e '.configuration[0].predicates["component.prometheus.agent_mode"] == true' >/dev/null

jq --arg image "$prom_310_image" '.items[0].spec.template.spec.containers[0] = {image:$image,command:["/bin/prometheus"],args:["--enable-feature=agent"]}' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-310-legacy-only.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-310-legacy-only.json" > "$tmp/v3-prom-310-legacy-only.out"
jq -e '.configuration[0].predicates["component.prometheus.agent_mode"] == false and .configuration[0].predicates["component.prometheus.image_digest"] == "sha256:0ea5254abf85f87901e8cfbd18fd243c59162c338ce0acd86aa2b0153d83dce2"' "$tmp/v3-prom-310-legacy-only.out" >/dev/null
jq '.items[0].spec.template.spec.containers[0].args += ["--agent"]' "$tmp/v3-prom-310-legacy-only.json" > "$tmp/v3-prom-310-agent.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-310-agent.json" | jq -e '.configuration[0].predicates["component.prometheus.agent_mode"] == true' >/dev/null
jq '.items[0].spec.template.spec.containers[0].args = ["--config.file","/etc/prometheus/prometheus.yml","--agent"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-310-split-unrelated.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-310-split-unrelated.json" | jq -e '.configuration[0].predicates["component.prometheus.agent_mode"] == true' >/dev/null
jq '.items[0].spec.template.spec.containers[0].args = ["--no-agent"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-310-no-agent.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-310-no-agent.json" | jq -e '(.configuration | all(.componentId != "pkg:oci/prometheus/prometheus" or .internalParticipationState == "incomplete")) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_PREDICATE_MALFORMED")' >/dev/null
jq 'del(.items[0].spec.template.spec.containers[0].args)' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-310-default-args.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-310-default-args.json" | jq -e '.configuration[0].predicates["component.prometheus.agent_mode"] == false' >/dev/null
jq '.items[0].spec.template.spec.containers[0].args = []' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-310-empty-args.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-310-empty-args.json" | jq -e '.configuration[0].predicates["component.prometheus.agent_mode"] == false' >/dev/null

assert_v3_omission() {
  local fixture_file=$1
  local code=$2
  jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$fixture_file" > "$tmp/v3-negative.out"
  jq -e --arg code "$code" '(.configuration | all(.componentId != "pkg:oci/prometheus/prometheus" or (.internalParticipationState == "incomplete" and (has("predicates") | not)))) and any(.omissions[]; .code == $code)' "$tmp/v3-negative.out" >/dev/null
  if jq -e 'tostring | test("PRUFYX_SYNTHETIC_SECRET_NEVER_RETAIN")' "$tmp/v3-negative.out" >/dev/null; then
    printf 'v3 negative diagnostic leaked raw input for %s\n' "$code" >&2
    exit 1
  fi
}

jq '.items[0].spec.template.spec.containers[0].image = "docker.io/prom/prometheus:v2.55.1"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-tag-only.json"
assert_v3_omission "$tmp/v3-prom-tag-only.json" COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED
jq '.items[0].spec.template.spec.containers[0].image = "docker.io/prom/prometheus@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-digest-only.json"
assert_v3_omission "$tmp/v3-prom-digest-only.json" COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED
jq '.items[0].spec.template.spec.containers[0].image = "docker.io/prom/prometheus:v2.55.1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-digest-mismatch.json"
assert_v3_omission "$tmp/v3-prom-digest-mismatch.json" COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED
jq '.items[0].spec.template.spec.containers[0].image = "docker.io/prom/prometheus:v2.55.0@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-version-unsupported.json"
assert_v3_omission "$tmp/v3-prom-version-unsupported.json" COMPONENT_CONFIGURATION_ENTRYPOINT_VERSION_UNSUPPORTED
jq '.items[0].spec.template.spec.containers[0].image = "docker.io/prom/prometheus:2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-tag-spelling-unverified.json"
assert_v3_omission "$tmp/v3-prom-tag-spelling-unverified.json" COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED
jq '.items[0].spec.template.spec.containers[0].command = ["/bin/sh","-c"]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-wrapper.json"
assert_v3_omission "$tmp/v3-prom-wrapper.json" COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE
jq '.items[0].spec.template.spec.containers[0].args = ["--agent"]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-old-dedicated.json"
assert_v3_omission "$tmp/v3-prom-old-dedicated.json" COMPONENT_CONFIGURATION_PREDICATE_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--enable-feature=agent","--no-agent=true"]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-old-negated-assigned.json"
assert_v3_omission "$tmp/v3-prom-old-negated-assigned.json" COMPONENT_CONFIGURATION_PREDICATE_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--agent","--agent"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-repeat-agent.json"
assert_v3_omission "$tmp/v3-prom-repeat-agent.json" COMPONENT_CONFIGURATION_PREDICATE_CONFLICT
jq '.items[0].spec.template.spec.containers[0].args = ["--agent","true"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-split-agent.json"
assert_v3_omission "$tmp/v3-prom-split-agent.json" COMPONENT_CONFIGURATION_ARGS_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--config.file","--agent"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-ambiguous-preceding-flag.json"
assert_v3_omission "$tmp/v3-prom-ambiguous-preceding-flag.json" COMPONENT_CONFIGURATION_PREDICATE_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["unexpected-positional","--agent"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-leading-positional.json"
assert_v3_omission "$tmp/v3-prom-leading-positional.json" COMPONENT_CONFIGURATION_ARGS_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--config.file","","--agent"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-empty-split-value.json"
assert_v3_omission "$tmp/v3-prom-empty-split-value.json" COMPONENT_CONFIGURATION_ARGS_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--agent=false"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-assigned-agent.json"
assert_v3_omission "$tmp/v3-prom-assigned-agent.json" COMPONENT_CONFIGURATION_PREDICATE_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--enable-feature"]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-missing-feature-value.json"
assert_v3_omission "$tmp/v3-prom-missing-feature-value.json" COMPONENT_CONFIGURATION_PREDICATE_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["$(MODE)"] | .items[0].spec.template.spec.containers[0].env = [{name:"MODE",value:"--agent"}]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-env-substitution.json"
assert_v3_omission "$tmp/v3-prom-env-substitution.json" COMPONENT_CONFIGURATION_ARGS_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--","--agent"]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-option-terminator.json"
assert_v3_omission "$tmp/v3-prom-option-terminator.json" COMPONENT_CONFIGURATION_ARGS_MALFORMED
jq '.items[0].spec.template.spec.containers[0].args = ["--agent","$(EXTRA)"] | .items[0].spec.template.spec.containers[0].env = [{name:"EXTRA",value:"--storage.agent.path=/private"}]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-agent-env-substitution.json"
assert_v3_omission "$tmp/v3-prom-agent-env-substitution.json" COMPONENT_CONFIGURATION_ARGS_MALFORMED
jq --arg wide "$(printf 'é%.0s' {1..257})" '.items[0].spec.template.spec.containers[0].args = [$wide]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-utf8-args.json"
assert_v3_omission "$tmp/v3-prom-utf8-args.json" COMPONENT_CONFIGURATION_ARGS_MALFORMED
jq --arg wide "$(printf 'é%.0s' {1..65})" '.items[0].spec.template.spec.containers[0].command = [$wide]' "$tmp/v3-prom-310-agent.json" > "$tmp/v3-prom-utf8-command.json"
assert_v3_omission "$tmp/v3-prom-utf8-command.json" COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE
jq '.items[0].spec.template.spec.containers[0].image = "quay.io/prometheus/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-unreviewed-repository.json"
assert_v3_omission "$tmp/v3-prom-unreviewed-repository.json" COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED
jq '.items[0].spec.template.spec.containers[0].image = "index.docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-index-host.json"
assert_v3_omission "$tmp/v3-prom-index-host.json" COMPONENT_CONFIGURATION_IDENTITY_UNRESOLVED
jq '.items[0].spec.template.spec.containers[0].image = "docker.io/prom/prometheus:v2.55.1@sha256:F4DEF6B3B61109A6EEEA59945D578BB7E926C36CB0E036A23E3CEB8B6DE024AD"' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-uppercase-digest.json"
assert_v3_omission "$tmp/v3-prom-uppercase-digest.json" COMPONENT_CONFIGURATION_IMAGE_BINDING_UNVERIFIED
jq '.items[0].spec.template.spec.containers += [.items[0].spec.template.spec.containers[0]]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-shared-role.json"
assert_v3_omission "$tmp/v3-prom-shared-role.json" COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS
jq '.items[0].spec.template.spec.initContainers = [.items[0].spec.template.spec.containers[0]]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-matching-init.json"
assert_v3_omission "$tmp/v3-prom-matching-init.json" COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS
jq '.items[0].spec.template.spec.containers += [(.items[0].spec.template.spec.containers[0] | .image = "index.docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad")]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-index-alias-shared-role.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-index-alias-shared-role.json" | jq -e '(.configuration | all(.componentId != "pkg:oci/prometheus/prometheus" or (.internalParticipationState == "incomplete" and (has("predicates") | not)))) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS")' >/dev/null
jq '.items[0].spec.template.spec.initContainers = [(.items[0].spec.template.spec.containers[0] | .image = "index.docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad")]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-index-alias-init-role.json"
assert_v3_omission "$tmp/v3-prom-index-alias-init-role.json" COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS
jq '.items += [(.items[0] | .spec.template.spec.containers[0].command = ["/bin/sh","-c"])]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-two-controller-partial.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-two-controller-partial.json" > "$tmp/v3-prom-two-controller-partial.out"
jq -e '(.configuration | length) == 2 and all(.configuration[]; .componentId == "pkg:oci/prometheus/prometheus" and .internalParticipationState == "incomplete" and (has("predicates") | not)) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE") and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS")' "$tmp/v3-prom-two-controller-partial.out" >/dev/null
jq '.items += [.items[0]]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-two-controller-coherent.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-two-controller-coherent.json" | jq -e '(.configuration | length) == 2 and all(.configuration[]; .predicates["component.prometheus.agent_mode"] == true)' >/dev/null
jq '.items += [(.items[0] | .kind = "ReplicaSet" | .spec.template.spec.containers[0].command = ["/bin/sh","-c"])]' "$tmp/v3-prom-255-agent.json" > "$tmp/v3-prom-generated-replicaset.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-prom-generated-replicaset.json" | jq -e '(.configuration | length) == 1 and .configuration[0].predicates["component.prometheus.agent_mode"] == true and (.omissions | length) == 0' >/dev/null

jq -n '{items:[{kind:"Deployment",spec:{template:{spec:{containers:[{image:"quay.io/argoproj/workflow-controller:v4.1.2",command:["workflow-controller"],args:["--namespaced","--managed-namespace","default"]}],initContainers:[]}}}}]}' > "$tmp/v3-argo-exact-command.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-argo-exact-command.json" > "$tmp/v3-argo-exact-command.out"
jq -e '.configuration[0].roles == ["workflow-controller"] and .configuration[0].predicates["component.argo_workflows.namespaced_mode"] == true and .configuration[0].predicates["component.argo_workflows.managed_namespace_configured"] == true and (.configuration[0].predicateEvidence | length) == 2' "$tmp/v3-argo-exact-command.out" >/dev/null
jq '.items[0].spec.template.spec.containers[0].command = ["/bin/workflow-controller"]' "$tmp/v3-argo-exact-command.json" > "$tmp/v3-argo-wrapper.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-argo-wrapper.json" | jq -e '.configuration == [] and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE")' >/dev/null
jq 'del(.items[0].spec.template.spec.containers[0].command)' "$tmp/v3-argo-exact-command.json" > "$tmp/v3-argo-command-absent.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-argo-command-absent.json" | jq -e '.configuration == [] and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE")' >/dev/null
jq '.items[0].spec.template.spec.initContainers = [{image:"busybox:1.36",args:["PRUFYX_SYNTHETIC_SECRET_NEVER_RETAIN"]}]' "$tmp/v3-argo-exact-command.json" > "$tmp/v3-argo-mixed-init.json"
jq -e -S --argjson registry "$registry_v3_json" --arg roleEvidenceVersion v3 -f "$filter_v3" "$tmp/v3-argo-mixed-init.json" | jq -e '(.configuration | length) == 1 and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_INIT_CONTAINERS_IGNORED") and (tostring | test("PRUFYX_SYNTHETIC_SECRET_NEVER_RETAIN") | not)' >/dev/null

# The same explicit command remains unavailable under producer v2.
jq -e -S --argjson registry "$registry_json" --arg roleEvidenceVersion v2 -f "$filter" "$tmp/v3-argo-exact-command.json" | jq -e '.configuration == [] and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_COMMAND_SURFACE_UNAVAILABLE")' >/dev/null

jq -c '.configuration[]' "$tmp/v3-argo-exact-command.out" > "$tmp/v3-config.ndjson"
jq -n -S --arg apiVersion 'prufyx.io/configuration-surface/v1alpha1' --arg kind 'ComponentConfigurationSurface' \
  --arg adapterVersion 'component-configuration-adapter-v3' --arg registryVersion 'v3' \
  --arg registryDigest 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' --arg filterDigest "$filter_v3_digest" --arg aggregateDigest "$aggregate_v3_digest" \
  --arg strictJsonDigest "$strict_json_digest" --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
  --arg kubectlStderrClassifierTaxonomyVersion 'kubectl-stderr-taxonomy-v1' --arg kubectlStderrClassifierAuthority 'heuristic_local_diagnostic_not_proof' \
  --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" --arg certManagerProjectionDigest '' --arg licenseDisposition 'metadata_only_derived_predicates' \
  --slurpfile configuration "$tmp/v3-config.ndjson" --argjson inputOmissions '[]' -f "$aggregate_v3" > "$tmp/v3-surface.json"
jq -e '.metadata.schemaVersion == "1.1.0" and .metadata.adapterVersion == "component-configuration-adapter-v3" and .metadata.registryVersion == "v3"' "$tmp/v3-surface.json" >/dev/null

# Incomplete participation markers are internal to the filter/aggregate pipe.
# Even when a complete row arrived from a separate workload-list response,
# one incomplete eligible controller removes the paired Prometheus facts.
jq -c '.configuration[0]' "$tmp/v3-prom-255-agent.out" > "$tmp/v3-cross-file-participation.ndjson"
jq -c '.configuration[0]' "$tmp/v3-prom-two-controller-partial.out" >> "$tmp/v3-cross-file-participation.ndjson"
jq -n -S --arg apiVersion 'prufyx.io/configuration-surface/v1alpha1' --arg kind 'ComponentConfigurationSurface' \
  --arg adapterVersion 'component-configuration-adapter-v3' --arg registryVersion 'v3' \
  --arg registryDigest "$registry_v3_digest" --arg filterDigest "$filter_v3_digest" --arg aggregateDigest "$aggregate_v3_digest" \
  --arg strictJsonDigest "$strict_json_digest" --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
  --arg kubectlStderrClassifierTaxonomyVersion 'kubectl-stderr-taxonomy-v1' --arg kubectlStderrClassifierAuthority 'heuristic_local_diagnostic_not_proof' \
  --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" --arg certManagerProjectionDigest '' --arg licenseDisposition 'metadata_only_derived_predicates' \
  --slurpfile configuration "$tmp/v3-cross-file-participation.ndjson" --argjson inputOmissions '[]' -f "$aggregate_v3" > "$tmp/v3-cross-file-participation-surface.json"
jq -e '(.components | all(.componentId != "pkg:oci/prometheus/prometheus")) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS") and (tostring | test("internalParticipationState") | not)' "$tmp/v3-cross-file-participation-surface.json" >/dev/null

jq -c '.configuration[0]' "$tmp/v3-prom-255-agent.out" > "$tmp/v3-prom-valid-row.ndjson"
relevant_read_omission='[{"code":"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN","reason":"The eligible workload read was unavailable.","requiredForEvaluation":true,"sourceFile":"statefulset-images.json"}]'
jq -n -S --arg apiVersion 'prufyx.io/configuration-surface/v1alpha1' --arg kind 'ComponentConfigurationSurface' \
  --arg adapterVersion 'component-configuration-adapter-v3' --arg registryVersion 'v3' \
  --arg registryDigest "$registry_v3_digest" --arg filterDigest "$filter_v3_digest" --arg aggregateDigest "$aggregate_v3_digest" \
  --arg strictJsonDigest "$strict_json_digest" --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
  --arg kubectlStderrClassifierTaxonomyVersion 'kubectl-stderr-taxonomy-v1' --arg kubectlStderrClassifierAuthority 'heuristic_local_diagnostic_not_proof' \
  --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" --arg certManagerProjectionDigest '' --arg licenseDisposition 'metadata_only_derived_predicates' \
  --slurpfile configuration "$tmp/v3-prom-valid-row.ndjson" --argjson inputOmissions "$relevant_read_omission" -f "$aggregate_v3" > "$tmp/v3-relevant-read-incomplete.json"
jq -e '(.components | all(.componentId != "pkg:oci/prometheus/prometheus")) and any(.omissions[]; .code == "COMPONENT_CONFIGURATION_DECLARED_ROLE_AMBIGUOUS")' "$tmp/v3-relevant-read-incomplete.json" >/dev/null

unrelated_read_omission='[{"code":"COMPONENT_CONFIGURATION_KUBERNETES_API_READ_FAILED_AUTHORIZATION_RBAC_FORBIDDEN","reason":"An unrelated read was unavailable.","requiredForEvaluation":true,"sourceFile":"cert-manager-health.json"}]'
jq -n -S --arg apiVersion 'prufyx.io/configuration-surface/v1alpha1' --arg kind 'ComponentConfigurationSurface' \
  --arg adapterVersion 'component-configuration-adapter-v3' --arg registryVersion 'v3' \
  --arg registryDigest "$registry_v3_digest" --arg filterDigest "$filter_v3_digest" --arg aggregateDigest "$aggregate_v3_digest" \
  --arg strictJsonDigest "$strict_json_digest" --arg kubectlStderrClassifierDigest "$kubectl_stderr_classifier_digest" \
  --arg kubectlStderrClassifierTaxonomyVersion 'kubectl-stderr-taxonomy-v1' --arg kubectlStderrClassifierAuthority 'heuristic_local_diagnostic_not_proof' \
  --arg kubectlBoundedRunnerDigest "$kubectl_bounded_runner_digest" --arg certManagerProjectionDigest '' --arg licenseDisposition 'metadata_only_derived_predicates' \
  --slurpfile configuration "$tmp/v3-prom-valid-row.ndjson" --argjson inputOmissions "$unrelated_read_omission" -f "$aggregate_v3" > "$tmp/v3-unrelated-read-incomplete.json"
jq -e 'any(.components[]; .componentId == "pkg:oci/prometheus/prometheus" and .predicates["component.prometheus.agent_mode"] == true)' "$tmp/v3-unrelated-read-incomplete.json" >/dev/null

printf '%s\n' 'component configuration adapter synthetic tests: PASS'
