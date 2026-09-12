# Prufyx Community Preview

Prufyx is a local, offline review tool for narrowly scoped configuration and
upgrade facts. It reads a caller selected file, compares it with a signed or
embedded source contract, and returns `PASS`, `BLOCKED`, or `UNKNOWN`. A result
is a bounded finding; it is not whole upgrade, cluster, runtime, or data safety
validation.

This repository is a source preview at [github.com/prufyx/community-preview](https://github.com/prufyx/community-preview).
Build the executable from source with the vendored Go modules. There is no
official prebuilt binary, release feed, or automatic knowledge refresh for
this preview.

## Quickstart: a MetalLB migration fact

The example below uses the caller's proposed native Kubernetes JSON. It does
not contact Kubernetes, a registry, or MetalLB.

This quickstart requires Go 1.26.8. It creates a temporary binary and private
0600 inputs outside the checkout.

```sh
set -eu
umask 077
PREVIEW_DIR="$(mktemp -d)"
trap 'rm -rf "$PREVIEW_DIR"' EXIT
test "$(go env GOVERSION)" = go1.26.8
(cd cli && \
  GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o "$PREVIEW_DIR/prufyx-community" ./cmd/prufyx-community)
cat > "$PREVIEW_DIR/metallb-legacy.json" <<'JSON'
{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"metallb-system"},"data":{"config":"address-pools: []"}}
JSON
chmod 600 "$PREVIEW_DIR/metallb-legacy.json"
legacy_result=0
"$PREVIEW_DIR/prufyx-community" check cncf --project metallb --native-resource "$PREVIEW_DIR/metallb-legacy.json" \
  --from 0.12.1 --to 0.13.2 --now 2026-09-11T00:00:00Z --format human || legacy_result=$?
test "$legacy_result" -eq 10

cat > "$PREVIEW_DIR/metallb-cr.json" <<'JSON'
{"apiVersion":"metallb.io/v1beta1","kind":"IPAddressPool","metadata":{"name":"pool","namespace":"metallb-system"},"spec":{"addresses":["192.0.2.10-192.0.2.20"]}}
JSON
chmod 600 "$PREVIEW_DIR/metallb-cr.json"
"$PREVIEW_DIR/prufyx-community" check cncf --project metallb --native-resource "$PREVIEW_DIR/metallb-cr.json" \
  --from 0.12.1 --to 0.13.2 --now 2026-09-11T00:00:00Z --format human
```

The selected legacy ConfigMap is **BLOCKED** because the reviewed 0.13.2
contract no longer consumes that 0.12 configuration shape. Convert the
operator-owned configuration with [MetalLB's migration procedure](https://metallb.io/configuration/migration_to_crds/), save the resulting
reviewed CR resource as another 0600 JSON file, and rerun the same command with
that path. The corrected input is checked only as the submitted resource;
unsupported, incomplete, or ambiguous shapes remain **UNKNOWN**. Do not read
this example as proof that a cluster was converted or that traffic is safe.

## What is covered

The current generated inventory reports **64 executable projects**, **110
selected source references**, and **58 projects with retained source records**.
The [full generated inventory](cli/docs/generated/community-support-inventory.json)
contains the exact capabilities and source bindings.

Explicit adopter-managed refresh continues through the existing signed TUF
import/update path. A Community CLI built from this source reports authenticated
TUF freshness separately from source-evidence expiry and exposes the fixed CNCF
target contract. The maintainer binary can export a complete compatible
replacement target, prepare each sequential signing payload, sign public role
metadata with encrypted local role keys, and verify the final package. See the
[adopter update overview](cli/docs/knowledge-updates.md), [publisher
workflow](cli/docs/knowledge-publisher.md), and [offline signer
workflow](cli/docs/knowledge-signer.md). No official Prufyx root or feed is
configured by these source tools.

The 2026-09-12 development-preview expansion currently admits **115 selected
exact project/version pairs across 23 projects**. Each row uses five selected
earlier stable releases and one exact reviewed target; it does not claim five
universal minor lines. The [latest-target coverage matrix](cli/docs/latest-upgrade-coverage-2026-09-12.md)
distinguishes native input from operator declarations and states the predicate
and `UNKNOWN` boundary for every project. Notation remains an explicit
qualification gap. Jaeger's retained `1.76.0` to `2.20.0` route is additional
to the selected-pair count, and one selected Cortex pair was already present.
Prometheus also has an additional canonical `2.55.1` to `3.14.0` depth
route over existing declared facts; it does not change the 23-project,
115-selected-pair matrix.
This is current source-preview development scope, not an official release or a
whole-upgrade compatibility claim.

The original twenty-four documented scenario examples are:

| Project | Scoped scenario | Local input |
| --- | --- | --- |
| Argo Workflows | 3.5.0 → 3.6.0 and five exact origins → 4.1.3 check the server `--basehref` to `--base-href` rename | native exact-image Kubernetes Deployment JSON with complete selected argv |
| Argo CD | 2.14.0 → 3.0.0 preserves declared v2 visibility; five exact origins → 3.5.2 check one selected Helm OCI repository | complete, precedence-resolved private ConfigMap or pre-apply repository Secret with explicit plain-HTTP intent and route guards |
| Ceph | Quincy 17.2.7 → Reef 18.2.0 rejects a selected current FileStore OSD | private native per-OSD metadata JSON output |
| Cloud Custodian | 0.9.50 → 0.9.51 removes the selected IAM access-key `json-diff` policy filter | private policy JSON |
| CloudNativePG | 1.29.0 → 1.30.0 cluster reference must remain immutable | paired Kubernetes JSON objects |
| MetalLB | 0.12.1 → 0.13.2 legacy ConfigMap configuration is removed | ConfigMap or reviewed CR JSON |
| NATS | 2.10.0 → 2.11.0 rejects ASCII spaces in supplied selected names | native JSON configuration subset |
| Contour | 1.19.0 → 1.20.0 selected `networking.x-k8s.io/v1alpha1` resources need explicit migration | Kubernetes resource JSON |
| CNI | spec 0.4.0 → 1.0.0 removes non-List configuration | plugin configuration JSON |
| Distribution | 2.8.3 → 3.0.0 removes schema 1 manifests | manifest JSON |
| Emissary-Ingress | 3.10.0 → 4.0.1 removes `diagd --metrics-endpoint` | caller-selected argv JSON |
| Fluent Bit | 3.2.0 → 4.0.0 requires an intended OpenTelemetry HTTP/2 setting to stay enabled | complete classic configuration plus current-default and preservation declarations |
| Fluentd | 1.17.1 → 1.18.0 changes treatment of one selected unquoted interpolation marker | paired literal JSON declaration with completeness, current-default, and preservation guards |
| Grafana | 10.4.0 → 11.0.0 rejects explicit legacy alerting enablement | complete, precedence-resolved `grafana.ini` |
| Harbor | 2.7.0 → 2.8.0 removes the installer `--with-chartmuseum` option | caller-declared complete literal installer argv JSON |
| Kibana | 8.18.0 → 9.0.0 removes `xpack.reporting.roles.allow` | complete, precedence-resolved `kibana.yml` |
| KubeVirt | 1.8.4 → 1.9.0 rejects interfaces with no or multiple bindings | VM/VMI JSON |
| Grafana Loki | 2.9.8 → 3.0.0 removes legacy compactor shared-store settings | complete, precedence-resolved native Loki YAML |
| Grafana Loki | 2.9.8 → 3.0.0 requires `store: tsdb` and `schema: v13` when structured metadata is enabled | complete, precedence-resolved native Loki schema configuration YAML |
| OpenCost | 1.119.0 → 1.120.0 moves enabled cloud-cost collection from provider-derived configuration to an explicitly selected cloud-integration file | operator-declared source selection JSON |
| OpenFGA | 1.17.1 → 1.18.0 requires OIDC issuer and audience when effective config is complete | effective-config JSON |
| OpenTelemetry Collector | 0.110.0 → 0.111.0 removes the selected `logging` exporter | complete, precedence-resolved native Collector YAML with declared official distribution |
| Prometheus | 2.55.1 → 3.1.0 renames selected `scrape_classic_histograms` | complete, precedence-resolved scrape-config YAML |
| Prometheus | 2.55.1 → 3.1.0 removes selected Alertmanager `api_version: v1` | complete, precedence-resolved `alerting.alertmanagers` entry YAML |

Use `prufyx check cncf --project PROJECT` for CNCF scenarios, including Cloud
Custodian and Prometheus, and `prufyx check
project --project PROJECT` for the separately scoped community-project scenarios
(Argo Workflows, Ceph, Fluent Bit, Grafana, Kibana, and Grafana Loki), with the input contract
documented in [community checks](cli/docs/community-checks.md). Version arguments select
an exact reviewed source contract. They do not identify a running installation.
CNI numbers are specification editions, not a library release claim. OpenFGA's
JSON is a caller-declared, already-resolved effective configuration; it does
not infer flag, environment, or file precedence. Every scenario leaves
unrepresented facts and whole-system behavior **UNKNOWN**.

The embedded profiles also include cert-manager, Prometheus, SPIFFE X.509-SVID
and CloudEvents structured JSON checks, plus a TiKV 8.5.8 GCS WIF full-backup
target preflight. These are named subsets and planned-operation checks, not
additional claims of complete product support.

## Offline operation and result meaning

The quickstart uses vendored modules. Its temporary binary and inputs stay
outside the checkout.

The checks read local files and do not execute supplied source, workloads,
plugins, or commands. Keep inputs under `umask 077` and mode 0600. Reports
minimize recognized facts and omit raw values, paths, credentials, and private
configuration content. Exit status is `0` for PASS, `10` for BLOCKED, `11` for
UNKNOWN or ATTENTION, `2` for invalid input, and `3` for integrity failure.

Knowledge evaluation stays local. An explicit `db update` may download an
operator-selected metadata package for local verification; it can reuse an
existing canonical fact and admitted input format after review. A new fact type
or input format can require a CLI update. There is no official feed, startup
refresh, or automatic knowledge admission.

## Contribute reviewed evidence

Maintainers can start with the [upstream contribution guide](cli/docs/upstream-contributions.md),
then use the offline scaffold and validator described there. A packet is a
candidate for independent source and semantic review, not an accepted rule.
The [review record template](cli/docs/upstream-review-record-template.md) keeps
source, implementation, and maintainer decisions separate. Existing facts and
rule operators may support a metadata-only update after review; new facts,
engine behavior, or native input adapters may require a CLI release.

Contributions remain local until a maintainer accepts and publishes reviewed
knowledge. Do not upload customer configuration. The project is maintained by
Spas Atanasov. First-party code is licensed under [Apache-2.0](LICENSE);
third-party files retain their own notices in [THIRD-PARTY.md](THIRD-PARTY.md).
Contributors follow the repository's DCO sign-off requirement in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Limits

A finding describes only the named predicate, source pair, input shape, and
operator intent supplied to that invocation. It does not prove migration
completion, API discovery, effective configuration, runtime compatibility,
availability, backup completion, identity trust, or security. Review the
project's upstream documentation and test the complete deployment separately.
Feedback can be returned through the repository's contribution and issue
workflow; this preview makes no support or compatibility commitment.
