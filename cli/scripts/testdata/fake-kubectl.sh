#!/usr/bin/env bash
set -Eeuo pipefail

mode=${FAKE_KUBECTL_MODE:-success}
if [[ -n ${FAKE_KUBECTL_CALL_LOG:-} ]]; then
  printf '%s\n' "$*" >> "$FAKE_KUBECTL_CALL_LOG"
fi

if [[ $mode == environment-probe ]]; then
  kubeconfig_argument=''
  previous=''
  for argument in "$@"; do
    if [[ $previous == --kubeconfig ]]; then
      kubeconfig_argument=$argument
      break
    fi
    previous=$argument
  done
  if [[ -n $kubeconfig_argument ]]; then
    jq -n -S \
      --arg ambientPrivate "$(if [[ -n ${AMBIENT_PRIVATE_SENTINEL:-} ]]; then printf present; else printf absent; fi)" \
      --arg ambientReadonly "$(if [[ -n ${AMBIENT_READONLY_SENTINEL:-} ]]; then printf present; else printf absent; fi)" \
      --arg exportedFunction "$(if declare -F SYNTHETIC_AMBIENT_FUNCTION >/dev/null 2>&1; then printf present; else printf absent; fi)" \
      --arg kubernetesService "$(if [[ -n ${KUBERNETES_SERVICE_HOST:-} ]]; then printf present; else printf absent; fi)" \
      --arg explicitPlugin "$(if [[ -n ${AWS_PROFILE:-} ]]; then printf present; else printf absent; fi)" \
      --arg explicitProxy "$(if [[ -n ${HTTPS_PROXY:-} ]]; then printf present; else printf absent; fi)" \
      --arg baseline "$(if [[ -n ${PATH:-} && -n ${HOME:-} && -n ${USER:-} && -n ${TMPDIR:-} ]]; then printf present; else printf absent; fi)" \
      --arg kubeconfig "$(if [[ ${KUBECONFIG:-} == "$kubeconfig_argument" ]]; then printf exact; else printf absent_or_changed; fi)" \
      '{ambientPrivate: $ambientPrivate, ambientReadonly: $ambientReadonly, exportedFunction: $exportedFunction, kubernetesService: $kubernetesService, explicitPlugin: $explicitPlugin, explicitProxy: $explicitProxy, baseline: $baseline, kubeconfig: $kubeconfig}' \
      > "$kubeconfig_argument.environment-probe.json"
  fi
fi
failure_status=0
case "$mode" in
  kubernetes-api-read-failed)
    printf '%s\n' 'SENSITIVE_FAKE_KUBECTL_STDERR endpoint=https://sensitive.example token=canary' >&2
    failure_status=42
    ;;
  inherited-writer)
    printf '%s\n' 'SENSITIVE_FAKE_KUBECTL_STDERR endpoint=https://sensitive.example token=canary' >&2
    failure_status=42
    ;;
  endless-stderr|ignore-term)
    trap '' TERM
    while :; do
      printf '%s\n' 'SENSITIVE_FAKE_KUBECTL_STDERR endpoint=https://sensitive.example token=canary' >&2
    done
    ;;
  silent-hang-ignore-term)
    trap '' TERM
    exec 1>/dev/null 2>/dev/null
    while :; do :; done
    ;;
  setsid-descendant)
    trap '' TERM
    python3 - <<'PY'
import os
import time

child = os.fork()
if child == 0:
    os.setsid()
    time.sleep(2)
    os._exit(0)
time.sleep(0.05)
PY
    while :; do :; done
    ;;
  auth-exec-plugin)
    printf '%s\n' 'error: exec plugin: executable /sensitive/plugin failed for https://sensitive.example token=canary' >&2
    failure_status=42
    ;;
  auth-no-stdout)
    printf '%s\n' 'error: exec plugin: executable /sensitive/plugin failed for https://sensitive.example token=canary' >&2
    exit 42
    ;;
  unauthorized)
    printf '%s\n' 'Error from server (Unauthorized): endpoint=https://sensitive.example token=canary' >&2
    failure_status=42
    ;;
  rbac-forbidden)
    printf '%s\n' 'Error from server (Forbidden): secrets is forbidden endpoint=https://sensitive.example token=canary' >&2
    failure_status=42
    ;;
  invalid-kubeconfig-context)
    printf '%s\n' 'error: context "sensitive-context" does not exist in kubeconfig token=canary' >&2
    failure_status=42
    ;;
  tls-certificate)
    printf '%s\n' 'Unable to connect to the server: x509: certificate signed by unknown authority endpoint=https://sensitive.example token=canary' >&2
    failure_status=42
    ;;
  dns)
    printf '%s\n' 'Unable to connect to the server: dial tcp: lookup sensitive.example: no such host token=canary' >&2
    failure_status=42
    ;;
  transport-timeout-unreachable)
    printf '%s\n' 'Unable to connect to the server: context deadline exceeded (network is unreachable) token=canary' >&2
    failure_status=42
    ;;
  timeout-no-stdout)
    printf '%s\n' 'Unable to connect to the server: context deadline exceeded (network is unreachable) token=canary' >&2
    exit 124
    ;;
  unsupported-not-found-api)
    printf '%s\n' 'Error from server (NotFound): the server could not find the requested resource endpoint=https://sensitive.example token=canary' >&2
    failure_status=42
    ;;
esac

raw_path=''
for argument in "$@"; do
  if [[ $argument == --raw=* ]]; then
    raw_path=${argument#--raw=}
  fi
done

if [[ $raw_path == /apis/apiextensions.k8s.io/v1/customresourcedefinitions* ]]; then
  python3 - "$mode" "$raw_path" <<'PY'
import json
import sys
from urllib.parse import parse_qs, urlsplit

mode, raw_path = sys.argv[1:]
query = parse_qs(urlsplit(raw_path).query, keep_blank_values=True)
token = query.get("continue", [""])[0]

def item(index, filler=0, duplicate_version=False, wide=False, invalid_nested=False):
    versions = [
        {"name": "v1", "served": True, "storage": True,
         "schema": {"openAPIV3Schema": {"description": "x" * filler}}
         if filler else {"openAPIV3Schema": {}}}
    ]
    if wide:
        versions = [
            {"name": "v%03d-%s-%d" % (version, "x" * 120, index), "served": True, "storage": version == 0,
             "schema": {"openAPIV3Schema": {}}, "subresources": {"status": {}}}
            for version in range(32)
        ]
    if duplicate_version:
        versions.append(dict(versions[0]))
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "synthetic-%d.example" % index},
        "spec": {
            "group": "synthetic.example",
            "names": {"kind": "Synthetic%d" % index, "plural": "synthetics%d" % index},
            "scope": "Namespaced",
            "versions": versions,
            **({"conversion": "invalid"} if invalid_nested else {}),
        },
    }

def page(items, next_token="", resource_version="synthetic-rv-1"):
    return {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList",
            "metadata": {"resourceVersion": resource_version, "continue": next_token}, "items": items}

if mode == "crd-duplicate-key":
    sys.stdout.write('{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinitionList","metadata":{"resourceVersion":"synthetic-rv-1","continue":""},"items":[{"spec":{"group":"synthetic.example","group":"duplicate.example","names":{"kind":"Synthetic","plural":"synthetics"},"scope":"Namespaced","versions":[{"name":"v1"}]}}]}')
elif mode == "crd-malformed-page":
    sys.stdout.write('{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinitionList","items":[')
elif mode == "crd-duplicate-version":
    json.dump(page([item(1, duplicate_version=True)]), sys.stdout, separators=(",", ":"))
elif mode == "crd-invalid-nested-shape":
    json.dump(page([item(1, invalid_nested=True)]), sys.stdout, separators=(",", ":"))
elif mode == "crd-resource-version-mismatch":
    next_cursor = "rv-cursor" if not token else ""
    page_resource_version = "synthetic-rv-1" if not token else "synthetic-rv-2"
    json.dump(page([item(1)], next_cursor, page_resource_version), sys.stdout, separators=(",", ":"))
elif mode == "crd-page-oversized":
    json.dump(page([item(1, filler=17 * 1024 * 1024)]), sys.stdout, separators=(",", ":"))
elif mode == "crd-aggregate-bytes":
    start = 0 if not token else int(token.split("-")[-1])
    next_token = "wide-%d" % (start + 50) if start < 850 else ""
    json.dump(page([item(index, wide=True) for index in range(start, start + 50)], next_token), sys.stdout, separators=(",", ":"))
elif mode == "crd-malformed-token":
    json.dump(page([item(1)], "bad\ntoken"), sys.stdout, separators=(",", ":"))
elif mode == "crd-oversized-token":
    json.dump(page([item(1)], "t" * 4097), sys.stdout, separators=(",", ":"))
elif mode == "crd-max-items":
    json.dump(page([item(index) for index in range(51)]), sys.stdout, separators=(",", ":"))
elif mode == "crd-repeated-continue":
    json.dump(page([item(1)], "repeat-token"), sys.stdout, separators=(",", ":"))
elif mode == "crd-max-pages":
    if not token:
        next_token = "page-1"
    else:
        next_token = "page-%d" % (int(token.split("-")[-1]) + 1)
    json.dump(page([], next_token), sys.stdout, separators=(",", ":"))
elif mode == "crd-api-failure" and token:
    sys.stderr.write("Error from server (Unauthorized): synthetic page failure\n")
    raise SystemExit(42)
elif mode == "crd-empty-page":
    json.dump(page([] if not token else [item(2)], "empty-token" if not token else ""), sys.stdout, separators=(",", ":"))
elif mode == "crd-large-pages":
    start = 0 if not token else 10
    json.dump(page([item(index, filler=1000000) for index in range(start, start + 10)], "large-token" if not token else ""), sys.stdout, separators=(",", ":"))
elif mode in ("crd-multipage", "crd-api-failure"):
    json.dump(page([item(2), item(1)] if not token else [item(4), item(3)], "opaque+token/%2F?&" if not token else ""), sys.stdout, separators=(",", ":"))
elif mode.startswith("component-"):
    names = [
        ("cert-manager.io", "certificates", "Certificate"),
        ("cert-manager.io", "certificaterequests", "CertificateRequest"),
        ("cert-manager.io", "issuers", "Issuer"),
        ("cert-manager.io", "clusterissuers", "ClusterIssuer"),
        ("acme.cert-manager.io", "challenges", "Challenge"),
        ("acme.cert-manager.io", "orders", "Order"),
    ]
    items = [{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
              "metadata": {"name": plural + "." + group},
              "spec": {"group": group, "names": {"kind": kind, "plural": plural},
                       "scope": "Namespaced", "versions": [{"name": "v1", "served": True, "storage": True}]}}
             for group, plural, kind in names]
    json.dump(page(items), sys.stdout, separators=(",", ":"))
else:
    json.dump(page([item(1)]), sys.stdout, separators=(",", ":"))
PY
  page_status=$?
  if [[ $mode == crd-* ]]; then
    exit "$page_status"
  fi
  exit "$failure_status"
fi

if [[ $mode == inherited-writer && $raw_path == /version ]]; then
  (sleep 5) >&2 &
fi

if [[ -n $raw_path ]]; then
  case "$mode:$raw_path" in
    server-version-boringcrypto:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11 X:boringcrypto","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-clean:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-malicious-suffix:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11 X:evil","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-malicious-core-suffix:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11evil","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-malicious-core-suffix-boringcrypto:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11evil X:boringcrypto","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-malicious-build-suffix:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11+evil","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-malicious-fourth-segment:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11.4","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-malicious-boringcrypto-suffix:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11 X:boringcrypto:evil","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-newline:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11\nX:boringcrypto","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-nul:/version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.25.11\u0000X:boringcrypto","compiler":"gc","platform":"linux/amd64"}' ;;
    server-version-long:/version) python3 - <<'PY'
import json
print(json.dumps({"gitVersion":"v1.34.0", "gitCommit":"synthetic", "gitTreeState":"clean", "buildDate":"2026-01-01T00:00:00Z", "goVersion":"go1.25.11" + ("a" * 4096), "compiler":"gc", "platform":"linux/amd64"}, separators=(",", ":")))
PY
      ;;
    invalid-json:/version)
      printf '%s\n' '{"gitVersion":"v1.34.0","gitVersion":"v1.34.1"}'
      ;;
    oversized-json:/version)
      python3 - <<'PY'
import sys
try:
    sys.stdout.write('{"gitVersion":"v1.34.0","padding":"' + ('x' * (16 * 1024 * 1024)) + '"}\n')
    sys.stdout.flush()
except BrokenPipeError:
    pass
PY
      ;;
    *)
      case "$raw_path" in
        /version) printf '%s\n' '{"gitVersion":"v1.34.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1.24","compiler":"gc","platform":"linux/amd64"}' ;;
        /api) printf '%s\n' '{"kind":"APIVersions","versions":[]}' ;;
        /apis) printf '%s\n' '{"kind":"APIGroupList","groups":[]}' ;;
        *) exit 1 ;;
      esac
      ;;
  esac
  exit "$failure_status"
fi

joined=" $* "
case "$mode:$joined" in
  projection-filter-rejected:*" get nodes "*)
    printf '%s\n' '{"items":[{"status":{"nodeInfo":{}}}]}'
    ;;
  workload-filter-rejected:*" get deployments.apps "*)
    printf '%s\n' '{"items":[{"kind":"Deployment","spec":{"template":{"spec":{"containers":[{"image":{}}]}}}}]}'
    ;;
  component-v3-prom-cross-kind:*" get deployments.apps "*)
    printf '%s\n' '{"items":[{"kind":"Deployment","metadata":{"name":"synthetic-prometheus-server","namespace":"synthetic"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"prometheus","image":"docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad","command":["/bin/prometheus"],"args":["--enable-feature=agent"]}],"initContainers":[]}}},"status":{"readyReplicas":1,"availableReplicas":1}}]}'
    ;;
  component-v3-prom-cross-kind:*" get statefulsets.apps "*)
    printf '%s\n' '{"items":[{"kind":"StatefulSet","metadata":{"name":"PRUFYX_SYNTHETIC_PRIVATE_WORKLOAD_NEVER_RETAIN","namespace":"synthetic"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"prometheus","image":"docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad","command":["/bin/sh","-c"],"args":["PRUFYX_SYNTHETIC_SECRET_NEVER_RETAIN"]}],"initContainers":[]}}},"status":{"readyReplicas":1,"availableReplicas":1}}]}'
    ;;
  component-v3-prom-statefulset-forbidden:*" get deployments.apps "*)
    printf '%s\n' '{"items":[{"kind":"Deployment","metadata":{"name":"synthetic-prometheus-server","namespace":"synthetic"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"prometheus","image":"docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad","command":["/bin/prometheus"],"args":["--enable-feature=agent"]}],"initContainers":[]}}},"status":{"readyReplicas":1,"availableReplicas":1}}]}'
    ;;
  component-v3-prom-statefulset-forbidden:*" get statefulsets.apps "*)
    printf '%s\n' 'Error from server (Forbidden): statefulsets.apps is forbidden synthetic' >&2
    exit 42
    ;;
  component-v3-prom:*" get deployments.apps "*)
    printf '%s\n' '{"items":[{"kind":"Deployment","metadata":{"name":"PRUFYX_SYNTHETIC_PRIVATE_WORKLOAD_NEVER_RETAIN","namespace":"synthetic"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"prometheus","image":"docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad","command":["/bin/prometheus"],"args":["--enable-feature=native-histograms,agent","--synthetic-private-token=PRUFYX_SYNTHETIC_SECRET_NEVER_RETAIN"]}],"initContainers":[]}}},"status":{"readyReplicas":1,"availableReplicas":1}}]}'
    ;;
  component-*:*" get deployments.apps "*)
    printf '%s\n' '{"items":[{"kind":"Deployment","metadata":{"name":"cert-manager","namespace":"cert-manager"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"cert-manager-controller","image":"quay.io/jetstack/cert-manager-controller:v1.20.3","args":["--feature-gates=ExperimentalCertificateSigningRequestControllers=true"]}]}}},"status":{"readyReplicas":1,"availableReplicas":1}},{"kind":"Deployment","metadata":{"name":"synthetic-workflow-controller","namespace":"synthetic"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"synthetic-controller-inline","image":"quay.io/argoproj/workflow-controller:v4.1.2","args":["--managed-namespace=customer-secret"]},{"name":"synthetic-controller-split","image":"quay.io/argoproj/workflow-controller:v4.1.2","args":["--managed-namespace","customer-secret"]}]}}},"status":{"readyReplicas":1,"availableReplicas":1}}]}'
    ;;
  pod-private-images:*" get deployments.apps "*)
    printf '%s\n' '{"items":[{"kind":"Deployment","metadata":{"name":"PRIVATE_OBJECT_NAME_NEVER_RETAIN","namespace":"synthetic"},"spec":{"template":{"spec":{"containers":[{"name":"private","image":"private.invalid/prom/prometheus:v2.55.1","command":["PRIVATE_COMMAND_NEVER_RETAIN"],"env":[{"name":"TOKEN","value":"PRIVATE_ENV_NEVER_RETAIN"}]},{"name":"prometheus","image":"docker.io/prom/prometheus:v2.55.1","args":[]}]}}}}]}'
    ;;
  pod-private-images:*" get pods "*)
    printf '%s\n' '{"items":[{"metadata":{"name":"PRIVATE_OBJECT_NAME_NEVER_RETAIN","namespace":"synthetic"},"spec":{"containers":[{"name":"private","image":"private.invalid/prom/prometheus:v2.55.1","command":["PRIVATE_COMMAND_NEVER_RETAIN"],"env":[{"name":"TOKEN","value":"PRIVATE_ENV_NEVER_RETAIN"}]}]},"status":{"containerStatuses":[{"image":"private.invalid/prom/prometheus:v2.55.1","imageID":"docker-pullable://private.invalid/prom/prometheus@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ready":true,"restartCount":2},{"image":"docker.io/prom/prometheus:v2.55.1","imageID":"docker-pullable://docker.io/prom/prometheus@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ready":true,"restartCount":1},{"image":"docker.io/prom/prometheus:v2.55.1","imageID":"docker-pullable://private.invalid/prom/prometheus@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","ready":false,"restartCount":0},{"image":"docker.io/prom/prometheus:PRIVATE_TAG_CANARY","imageID":null,"ready":false,"restartCount":0},{"image":"docker.io/prom/prometheus:2.55.1\nPRIVATE_CONTROL_CANARY","imageID":null,"ready":false,"restartCount":0}]}}]}'
    ;;
  component-*:*" get validatingwebhookconfigurations.admissionregistration.k8s.io "*|component-*:*" get mutatingwebhookconfigurations.admissionregistration.k8s.io "*)
    printf '%s\n' '{"items":[{"kind":"ValidatingWebhookConfiguration","webhooks":[{"admissionReviewVersions":["v1"],"failurePolicy":"Fail","clientConfig":{"service":{"name":"cert-manager-webhook","namespace":"cert-manager"}},"rules":[{"apiGroups":["cert-manager.io"],"apiVersions":["v1"],"operations":["CREATE"],"resources":["certificates"]}]}]}]}'
    ;;
  component-*:*" get clusterroles.rbac.authorization.k8s.io "*)
    if [[ $mode == component-rbac-same-name-role || $mode == component-rbac-unrelated-namespace ]]; then
      printf '%s\n' '{"items":[]}'
    elif [[ $mode == component-rbac-unrelated-resource ]]; then
      printf '%s\n' '{"items":[{"metadata":{"name":"cert-manager-controller"},"rules":[{"apiGroups":["example.invalid"],"resources":["widgets"],"verbs":["get"]}]}]}'
    else
      printf '%s\n' '{"items":[{"metadata":{"name":"cert-manager-controller"},"rules":[{"apiGroups":[""],"resources":["serviceaccounts/token"],"verbs":["create"]},{"apiGroups":["cert-manager.io"],"resources":["certificates","issuers"],"verbs":["get","list","watch"]},{"apiGroups":["acme.cert-manager.io"],"resources":["challenges","orders"],"verbs":["get","list","watch"]}]}]}'
    fi
    ;;
  component-*:*" get roles.rbac.authorization.k8s.io "*)
    if [[ $mode == component-rbac-unrelated-namespace || $mode == component-rbac-same-name-role ]]; then
      printf '%s\n' '{"items":[{"metadata":{"name":"cert-manager-controller","namespace":"other-namespace"},"rules":[{"apiGroups":["cert-manager.io"],"resources":["certificates"],"verbs":["get"]}]}]}'
    else
      printf '%s\n' '{"items":[]}'
    fi
    ;;
  component-*:*" get rolebindings.rbac.authorization.k8s.io "*)
    if [[ $mode == component-rbac-unrelated-namespace ]]; then
      printf '%s\n' '{"items":[{"metadata":{"namespace":"other-namespace"},"roleRef":{"kind":"Role","name":"cert-manager-controller"},"subjects":[{"kind":"ServiceAccount","name":"cert-manager","namespace":"cert-manager"}]}]}'
    elif [[ $mode == component-rbac-same-name-role ]]; then
      printf '%s\n' '{"items":[{"metadata":{"namespace":"cert-manager"},"roleRef":{"kind":"ClusterRole","name":"cert-manager-controller"},"subjects":[{"kind":"ServiceAccount","name":"cert-manager","namespace":"cert-manager"}]}]}'
    elif [[ $mode == component-rbac-unrelated-sa ]]; then
      printf '%s\n' '{"items":[{"metadata":{"namespace":"cert-manager"},"roleRef":{"kind":"ClusterRole","name":"cert-manager-controller"},"subjects":[{"kind":"ServiceAccount","name":"unrelated","namespace":"cert-manager"}]}]}'
    else
      printf '%s\n' '{"items":[{"metadata":{"namespace":"cert-manager"},"roleRef":{"kind":"ClusterRole","name":"cert-manager-controller"},"subjects":[{"kind":"ServiceAccount","name":"cert-manager","namespace":"cert-manager"}]}]}'
    fi
    ;;
  component-*:*" get clusterrolebindings.rbac.authorization.k8s.io "*)
    if [[ $mode == component-rbac-same-name-role || $mode == component-rbac-unrelated-namespace ]]; then
      printf '%s\n' '{"items":[]}'
    elif [[ $mode == component-rbac-unrelated-sa ]]; then
      printf '%s\n' '{"items":[{"roleRef":{"kind":"ClusterRole","name":"cert-manager-controller"},"subjects":[{"kind":"ServiceAccount","name":"unrelated","namespace":"cert-manager"}]}]}'
    else
      printf '%s\n' '{"items":[{"roleRef":{"kind":"ClusterRole","name":"cert-manager-controller"},"subjects":[{"kind":"ServiceAccount","name":"cert-manager","namespace":"cert-manager"}]}]}'
    fi
    ;;
  component-*:*" get servicemonitors.monitoring.coreos.com "*)
    printf '%s\n' '{"items":[{"spec":{"namespaceSelector":{"matchNames":["cert-manager"]},"selector":{"matchLabels":{"app.kubernetes.io/name":"cert-manager","app.kubernetes.io/instance":"cert-manager"}},"endpoints":[{"port":"http-metrics","path":"/metrics"}]}}]}'
    ;;
  component-*:*" get podmonitors.monitoring.coreos.com "*)
    printf '%s\n' '{"items":[{"spec":{"namespaceSelector":{"matchNames":["cert-manager"]},"selector":{"matchLabels":{"app.kubernetes.io/name":"cert-manager","app.kubernetes.io/instance":"cert-manager"}},"podMetricsEndpoints":[{"port":"http-metrics","path":"/metrics"}]}}]}'
    ;;
  component-*:*" get services,pods "*)
    if [[ $mode == component-monitor-label-collision ]]; then
      printf '%s\n' '{"items":[{"kind":"Service","metadata":{"name":"cert-manager","namespace":"cert-manager"},"spec":{"selector":{"app.kubernetes.io/name":"cert-manager","app.kubernetes.io/instance":"cert-manager"}}},{"kind":"Pod","metadata":{"namespace":"cert-manager","labels":{"app.kubernetes.io/name":"other","app.kubernetes.io/instance":"other"},"ownerReferences":[{"kind":"ReplicaSet","name":"other-abc"}]},"spec":{"containers":[{"image":"quay.io/example/other:v1"}]}}]}'
    elif [[ $mode == component-monitor-unrelated-target ]]; then
      printf '%s\n' '{"items":[{"kind":"Service","metadata":{"name":"cert-manager","namespace":"cert-manager"},"spec":{"selector":{"app.kubernetes.io/name":"cert-manager","app.kubernetes.io/instance":"cert-manager"}}},{"kind":"Pod","metadata":{"namespace":"cert-manager","labels":{"app.kubernetes.io/name":"cert-manager","app.kubernetes.io/instance":"cert-manager"},"ownerReferences":[]},"spec":{"containers":[{"image":"quay.io/example/other:v1"}]}}]}'
    else
      printf '%s\n' '{"items":[{"kind":"Service","metadata":{"name":"cert-manager","namespace":"cert-manager"},"spec":{"selector":{"app.kubernetes.io/name":"cert-manager","app.kubernetes.io/instance":"cert-manager"}}},{"kind":"Pod","metadata":{"namespace":"cert-manager","labels":{"app.kubernetes.io/name":"cert-manager","app.kubernetes.io/instance":"cert-manager"},"ownerReferences":[{"kind":"ReplicaSet","name":"cert-manager-abc"}]},"spec":{"containers":[{"image":"quay.io/jetstack/cert-manager-controller:v1.20.3"}]}}]}'
    fi
    ;;
  *)
    case "$joined" in
      *" get nodes "*)
        printf '%s\n' '{"items":[{"status":{"nodeInfo":{"kubeletVersion":"v1.34.0","containerRuntimeVersion":"containerd://1.7","osImage":"Synthetic Linux","kernelVersion":"6.1.0","architecture":"amd64","operatingSystem":"linux"}}}]}'
        ;;
      *" get "*)
        printf '%s\n' '{"items":[]}'
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
esac
exit "$failure_status"
