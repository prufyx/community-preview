# Prufyx

Review configuration changes before a Kubernetes component upgrade.

Prufyx runs narrowly scoped upgrade checks, standards-conformance subsets, and
planned-operation preflights locally and offline. It connects a finding to the
exact upstream source, explains the setting to review, and records the inputs
needed to reproduce the result. No account or model is required.

**Community development preview.** Each result belongs to one named reviewed
transition, standards-conformance subset, or planned target preflight.
Whole-upgrade compatibility remains UNKNOWN.

## DEVELOPMENT / SOURCE PREVIEW

This development/source preview is prepared for early technical review. Source
build is the primary entry; it does not describe an official binary alpha, tag,
feed, release, or hosted service. The useful question is whether a developer can
turn one exact proposed configuration into a source-linked local finding, apply
the narrow correction, and recheck it without a cluster or network connection.

### Five-minute local path

From the repository root, use Go 1.26.8 already installed on your machine. The
repository vendors its Go modules, and these flags deliberately prevent module or
toolchain downloads:

```sh
cd cli
GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o ../prufyx ./cmd/prufyx-community
cd ..
# Shell-local convenience for later documented `prufyx` examples; no global install.
export PATH="$PWD:$PATH"

umask 077
PREVIEW_DIR="$(mktemp -d)"
printf '%s\n' '{"prometheus":{"servicemonitor":{"path":"/custom"}}}' >"$PREVIEW_DIR/values.json"
set +e
./prufyx check cert-manager-values \
  --from 1.20.3 --to 1.21.1 --values "$PREVIEW_DIR/values.json" --format human >"$PREVIEW_DIR/blocked.txt"
preview_result=$?
set -e
test "$preview_result" -eq 10
sed -n '1,18p' "$PREVIEW_DIR/blocked.txt"

printf '%s\n' '{}' >"$PREVIEW_DIR/values.json"
./prufyx check cert-manager-values \
  --from 1.20.3 --to 1.21.1 --values "$PREVIEW_DIR/values.json" --format human >"$PREVIEW_DIR/recheck.txt"
sed -n '1,18p' "$PREVIEW_DIR/recheck.txt"
```

The first command is a scoped **BLOCKED** result because the reviewed target
chart removes `prometheus.servicemonitor.path`; the second rechecks the same
narrow rule after removing that setting. This is not a full Helm-schema,
deployed-chart, runtime, or whole-upgrade validation. Those boundaries remain
**UNKNOWN**. Keep the generated input and reports local; the CLI records the
recognized setting paths and input digest, not the values.

### Feedback that helps

Please use the [source-preview feedback form](.github/ISSUE_TEMPLATE/source-preview-feedback.md)
to answer these specific questions:

1. Did the pinned-Go, vendored, offline build path work on your supported
   development machine?
2. Did the blocked report make the exact setting and narrow correction clear?
3. Which configuration-aware, non-sensitive input would save you the most
   compatibility research time next?
4. Which missing evidence should continue to be reported as **UNKNOWN** rather
   than inferred from nearby facts?

Review feedback is not an approval, support commitment, compatibility claim, or
permission to upload customer data. First-party Prufyx source and docs are
Apache-2.0; [third-party material](THIRD-PARTY.md) retains its own attribution and
licenses. Proposed changes follow the existing [contribution guide](CONTRIBUTING.md),
including DCO sign-off.

## Prebuilt releases

No prebuilt release matching this development/source preview is available.
Historical prerelease assets do not include current capabilities; build from
source above for this preview. When a future release owner supplies an exact
archive and matching `SHA256SUMS`, [verify archive provenance](cli/docs/signing-provenance.md)
before execution; do not substitute an unverified URL or an older alpha archive.

## Cert-manager limits

The source-preview path covers one removed monitoring-setting predicate between
cert-manager 1.20.3 and 1.21.1. The same migration also removes
`prometheus.servicemonitor.targetPort` and `prometheus.podmonitor.path`.

Helm's target chart schema also catches these removed keys. Prufyx adds a
focused migration explanation and reproducible local report; it does not
perform full Helm schema validation. A **PASS** means only that these three
removed settings are absent. Other chart or runtime problems may remain.

## Supported checks

| Check | Reviewed transition | Input and result |
| --- | --- | --- |
| cert-manager removed monitoring values | 1.20.3 → 1.21.1, exact chart digests shown in the report | Proposed merged JSON values; removed-key findings and remediation |
| Prometheus declared Agent mode | 2.55.1 → 3.1.0, exact Linux arm64/v8 image manifests | Optional producer-v3 observation and proposed workload JSON; declared mode preservation |
| CloudEvents structured JSON core envelope | No version transition; CloudEvents edition 1.0 named subset | Private native event JSON; staged scoped `PASS`, `FAIL`, or `UNKNOWN` |
| [generic CNCF source constraints](cli/docs/CNCF-SOURCE-PREVIEW.md) | Exact project/version pair and declared input contract shown by `check cncf` | Private declared native input or prepared observation; scoped `PASS`, `BLOCKED`, or `UNKNOWN` only |
| [SPIFFE X.509-SVID public-leaf URI-SAN subset](cli/docs/spiffe-x509-svid.md) | No version transition; named SPIFFE subset | One private local PEM or DER certificate; scoped `PASS`, `FAIL`, or `UNKNOWN` |
| [TiKV GCS WIF full-backup preflight](cli/docs/tikv-gcp-v2-wif-backup.md) | Target TiKV 8.5.8, no fabricated from/to transition | Private TOML plus declared GCS full-backup WIF operation; scoped setting `PASS` or `BLOCKED`, with aggregate readiness `UNKNOWN` |

Version arguments select a reviewed source contract. They do not authenticate
the chart deployed in your cluster. Unsupported inputs and missing or ambiguous
evidence stay **UNKNOWN**. Versioned-check reports keep the whole-upgrade
aggregate **UNKNOWN**; a standards-conformance result is limited to its named
subset.

The `check` command's exit status belongs to its named check: `0` PASS, `10`
BLOCKED, `11` UNKNOWN or ATTENTION, `2` invalid input, and `3` integrity failure.
The older `validate-prometheus-mode` command preserves its aggregate exit `11`
for every completed assessment.

See [commands and input contracts](cli/docs/community-checks.md) and the
[Prometheus observation runbook](cli/docs/prometheus-mode.md). The
[source gate](cli/release/COMMUNITY-SOURCE-GATE.md) describes how to reconstruct
and test the exact published package.

## Contribute upstream evidence

Project developers can prepare a versioned evidence packet for a new catalogue
identity or a specific transition. The [contributor workflow](cli/docs/upstream-contributions.md)
includes an offline validator, examples, and an issue template. The source
preview feedback form is for technical-review observations; it does not submit
or approve an evidence packet.

The [review record template](cli/docs/upstream-review-record-template.md) helps
contributors bind endpoint versions, retained sources, scoped claims and test
cases, with separate source, implementation and maintainer review decisions.

Validation produces a **CANDIDATE**, not a compatibility decision. Independent
source review, scoped tests, and maintainer acceptance precede any rule change;
signed knowledge publication remains a separate step. Contributions never grant
model-training permission or upload customer configuration.

Maintainers can also verify an existing local collection of public upstream
files with the [offline source-corpus verifier](cli/docs/source-corpus.md).
It binds exact retained bytes and line spans to declared source metadata, so
reviewers can repeat a source review. It neither downloads files nor promotes
them into compatibility rules. The shipped example contains synthetic data.

For multiple shards, the [collection verifier](cli/docs/source-corpus-collection.md)
checks a bounded private local index, verifies each shard, rejects conflicting
source metadata and duplicate records, and counts shared objects once. Its
receipt establishes retained-byte consistency; source interpretation and rule
acceptance remain separate reviews.

The separate [maintainer capture tool](cli/docs/public-source-capture.md) can
fetch an explicitly requested, bounded set of immutable public GitHub files.
It checks declared file and span hashes, retains private candidate evidence,
and hands it to the offline verifier and independent review. It receives no
customer configuration and is not invoked by the product CLI. Capture does
not approve rules, establish release provenance, or publish a knowledge feed.

## Unreleased offline knowledge database

The current source tree includes an unreleased, explicit opt-in database for
selecting operator-provisioned signed cert-manager, CNCF, TiKV target-preflight,
or isolated SPIFFE X.509-SVID and CloudEvents conformance profiles in separate
local stores. Explicit `db update` can download a complete package from an
operator-selected HTTPS source, retaining it for local verification and recovery.
There is no hosted feed, production signing command, automatic startup refresh,
or official Prufyx trust root. See [explicit downloads](cli/docs/knowledge-updates.md).
Embedded knowledge remains the default when no external database is selected,
and Prometheus knowledge remains embedded.

The [knowledge database guide](cli/docs/knowledge-database.md) documents the
strict package profile and current/historical selection semantics. A
[runnable synthetic example](cli/examples/community/knowledge/README.md)
creates ephemeral fixture keys and demonstrates complete empty coverage followed
by the existing reviewed cert-manager rule with the same binary. These source
capabilities are not part of the published alpha.4 release assets. The
[CNCF database guide](cli/docs/cncf-knowledge-database.md) and its
[runnable example](cli/examples/cncf/knowledge/README.md) demonstrate the same
empty-to-active update for generic constraints. New rules can use existing
compiled facts and operators; new input capabilities still require a CLI update.
This first alpha requires separate stores for incompatible CLI capabilities;
the database guide explains how to preserve earlier stores for replay.

## Unreleased CNCF source-constraint preview

The current source adds `catalog cncf` and `check cncf` for explicitly declared,
minimized inputs. The pinned catalogue contains 255 CNCF project identities; 30 are selected for
initial work. Separately, generic source rules cover 42 catalogued rule projects
(47 exact scoped constraints over 89 registered facts and 372 rule-scoped
cases). The two named checks, two standards-conformance profiles, and the TiKV
target preflight are tracked separately, giving an executable-project union of
47. The [pinned official Graduated roster][cncf-roster]
has 39 identities across all categories; each has one accepted local scoped
journey in the [generated Community support inventory](cli/docs/generated/community-support-inventory.md).
That roster coverage does not establish all-version support, runtime behavior,
or whole-upgrade safety. Catalogue membership and priority do not mean tested
support or an adoption ranking.

## Unreleased SPIFFE X.509-SVID conformance subset

`prufyx check spiffe-x509-svid` accepts one private local DER or PEM certificate
and checks a named public-leaf URI-SAN subset: non-CA, exactly one URI SAN,
lowercase `spiffe` scheme, and non-root path. It reports scoped `PASS`, `FAIL`,
or `UNKNOWN` without inventing a version transition or counting the existing
SPIRE rule twice. The [operator and profile guide](cli/docs/spiffe-x509-svid.md)
documents private input, exact replay pins, explicit isolated signed local
metadata, and the unverified full SPIFFE ID, trust, possession, issuance, and
runtime boundaries.

## Unreleased CloudEvents structured JSON conformance subset

`prufyx check cloudevents-structured-json` reads one private native event JSON
file and checks a named edition 1.0 core-envelope subset. It stages the required
`specversion`, `id`, `source`, and `type` predicates before checking that
`data` and `data_base64` are not both present. It reports scoped `PASS`, `FAIL`,
or `UNKNOWN` without inventing a version transition. The [operator and profile
guide](cli/docs/cloudevents-structured-json.md) documents private input,
Unicode and duplicate-key boundaries, exact replay pins, isolated signed local
metadata, and the unchecked payload, transport, SDK, delivery, signing,
authentication, and runtime behavior.

The current generic preview includes separate exact Falco 0.40.0 to 0.41.0
and 0.40.0 to 0.42.0 constraints, plus Kuma 2.8.0 to 2.9.0. Each requires explicit
operator-declared proposed facts for the reviewed command surface. The Falco
old-option set is `-A`, `-b`,
`--print-base64`, `-S`, and `--snaplen`; the Kuma set is
`--exclude-outbound-tcp-ports-for-uids` and
`--exclude-outbound-udp-ports-for-uids`. These are declarations about effective
options, with no argv parser. A declared old-option presence is scoped
BLOCKED; definite absence can be scoped PASS only with all applicability guards.
Missing, custom, ambiguous, or other-surface input remains UNKNOWN. These
checks do not infer options from a current configuration or claim startup or
runtime behavior.

SPIRE adds an exact 1.10.4 to 1.11.0 constraint for a declared proposed direct
`spire-server entry create` invocation. The legacy `-ttl` and `--ttl` spellings
must both be absent for a scoped PASS, with the official distribution and exact
command-surface guards. This check does not parse argv, validate replacement
TTL values, inspect entries, or establish server behavior.

Dragonfly adds two exact 2.2.3 to 2.2.4 constraints for the manager and scheduler
configuration surfaces. A declared requirement to retain debug logging, together
with declared prior verbose-debug intent, is BLOCKED when debug logging is
declared disabled in the proposed matching surface. Declared enabled logging
passes only that scoped requirement. Missing intent, a different surface, or a
custom distribution remains UNKNOWN. The check does not parse configuration or
infer logging defaults, and it does not run Dragonfly.

Cortex adds an exact 1.17.2 to 1.21.1 constraint for the declared proposed
upstream Cortex command. The removed `-querier.at-modifier-enabled` option must
be absent for a scoped PASS. The option was already nonfunctional; this checks
only declared input compatibility, without parsing argv or establishing query
behavior.

Strimzi adds an exact 0.51.0 to 1.0.0 constraint for a declared proposed Kafka
custom resource. With explicit intent to admit that resource against the official
target Kafka CRD, a declared `kafka.strimzi.io/v1beta2` API is scoped BLOCKED.
This requires all distribution, resource-surface and admission-intent guards.
It does not inspect installed CRDs, call an API server, migrate stored resources,
or assess KafkaTopic, KafkaUser or application runtime.

Karmada adds an exact 1.18.3 to 1.19.0 constraint for the application-failover
`purgeMode` in a declared PropagationPolicy or ClusterPropagationPolicy. With
explicit intent to admit that policy against the official target CRD, declared
`Immediately` or `Graciously` is scoped BLOCKED; review the corresponding
`Directly` or `Gracefully` replacement. This checks declared input only, without
parsing policy resources, installing CRDs, calling an API server or testing failover.

Linkerd adds an exact 2.13.7 to 2.14.0 target-schema constraint. It requires
explicit operator-declared proposed facts for the reviewed
`meshtls_authentication_crd` surface. Linkerd checks the target
MeshTLSAuthentication CRD selector constraint. Declare
`distribution=official_upstream`, `execution_surface=meshtls_authentication_crd`,
and `schema_validation_required=true` on the proposed side. Exactly one selector
property (`identities` or `identityRefs`) explicitly present and known empty
while the other is known absent is scoped BLOCKED;
exactly one selector property explicitly present and known nonempty while the
other is known absent is scoped PASS. Both, neither,
missing, unresolved, custom-surface, or unsupported declarations remain UNKNOWN.
This is a target-schema constraint only: the preview does not parse CRDs, call an
API server, migrate stored objects, or prove runtime behavior.
The optional local `prepare cncf --project linkerd` adapter derives selector
emptiness from a private MeshTLSAuthentication JSON resource. Distribution and
schema-validation intent remain explicit declarations; preparation reports
disclose that CRD schema validation was not performed.

```sh
./prufyx catalog cncf --priority
./prufyx catalog cncf --project helm --format json
```

Try the [local preparation and constraint examples](cli/examples/cncf/README.md), including the
[single-command Argo CD ConfigMap review](cli/examples/cncf/README.md#review-an-argo-cd-inheritance-change-from-one-configmap) and
[single-command Knative Serving Service review](cli/examples/cncf/README.md#review-a-knative-serving-startup-probe-from-one-service),
the [TUF Updater source-call review](cli/examples/cncf/README.md#review-a-tuf-updater-source-call), and the
[KFP Python SDK component-authoring review](cli/examples/cncf/README.md#review-a-kfp-python-sdk-component-authoring-change), and the
[CRI-O ArtifactStore named-reference review](cli/examples/cncf/README.md#review-a-cri-o-artifactstore-named-reference-plan), then read the
[input and contribution guide](cli/docs/CNCF-SOURCE-PREVIEW.md). Each rule records
the exact reviewed version pair, required facts, primary source revision, file
digest, lines and review expiry. Unsupported versions and missing facts remain
UNKNOWN. A passing source constraint does not prove an upgrade starts or works.
None of these generic transitions has been reproduced in a runtime environment.

For the exact Kyverno 1.12.5 to 1.13.0 constraint, `prepare cncf` can derive the
required facts from a private proposed Pod or Deployment JSON file. Choose the
container and declare `--distribution official_upstream` explicitly. Only the
bare `reports-controller` command and a narrow literal integer-option grammar
are recognized. Missing distribution, other commands or paths, wrappers, and
unresolved arguments remain UNKNOWN. Older boolean-only Kyverno declarations
remain parseable but cannot satisfy the new scope guards. Preparation does not
verify an image or run Kyverno; review its minimized output before checking it.

This preview reads embedded metadata or an explicitly selected signed local
CNCF database, together with private local declarations. Checks have no implicit
download or model call; only explicit `db update` downloads a package.
External selection never falls back to embedded rules;
an empty external revision means no coverage. These
capabilities are unreleased and absent from historical alpha.4 assets.

[cncf-roster]: <https://github.com/cncf/landscape/blob/a38cc989ee728c814d2d56f46aad59484e5a20d0/landscape.yml>

## Optional local collection

The cert-manager values check needs no cluster access. For the Prometheus check,
you can explicitly collect minimized facts using a named kubeconfig and context.
Collection is read-only and remains local. Kubeconfig credential helpers can run
only through the collector's disclosed local execution path.

The collector omits raw command lines, environment values, private image paths,
workload names, Secrets and ConfigMap contents. Context pseudonyms change between
collection runs; replay of the same admitted observation is deterministic.
See [local collection](cli/docs/local-collection.md) before collecting.

## Help improve the next check

An actionable unsupported transition is useful feedback. Share the public
component and exact versions, the setting that changed, and the upstream source
that explains it. Use a synthetic example. Keep cluster data and credentials
private. [Contribution guidance](CONTRIBUTING.md) explains the review and tests
needed to add a check.

Prufyx is maintained by [Spas Atanasov](https://github.com/airstand) and licensed
under [Apache License 2.0](LICENSE), with DCO sign-off for contributions.
[Security issues](SECURITY.md) have a private reporting channel.

Broader versions, additional component checks and easier Helm/Kustomize input
preparation are future work. Customer time savings and demand have not yet been
measured. Upstream project names identify the subject of a check and imply no
endorsement by those projects or the CNCF.
