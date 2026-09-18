# Community checks

Build the public binary from the repository root with Go 1.26.8:

```sh
(cd cli && GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o ../prufyx ./cmd/prufyx-community)
```

The Community checks evaluate local files offline. They never contact a cluster
or upload values. The cert-manager values input must be a regular, single-link
JSON file readable only by its owner because Helm values commonly contain
credentials. Relative paths are accepted. Create inputs under `umask 077`, or
run `chmod 600 values.json` before the check.

## Discovering embedded source-rule routes

Use `catalog checks` to inspect the exact embedded source-rule identities for
one project and, optionally, one exact transition. It reads no configuration,
does not evaluate a check, and reports source evidence freshness as
`NOT_EVALUATED`.

```sh
./prufyx catalog checks --project prometheus --from 2.55.1 --to 3.1.0 --format json
./prufyx catalog checks --project mariadb-operator --from 26.3.0 --to 26.6.0
```

The output distinguishes generic embedded CNCF canonical-input coverage from
exact native routes. Each generic canonical input itself contains the listed
exact from/to pair, so its command deliberately has no `--from` or `--to`
flags. Community project rules are discoverable but their generic
declaration route is `NOT_EXPOSED_BY_PUBLIC_CLI`; only a mechanically bound
native descriptor may recommend `check project`. A descriptor is typed command
guidance: replace `FILE`, `NAME`, `RFC3339`, and `BOOL` with caller-supplied
values. It does not declare an assessment, validate a target, or establish
runtime behavior. Named checks appear only as scoped `--help` hints.

## Fluentd selected-literal treatment

For Fluentd `1.17.1` to `1.18.0`, `prepare cncf --project fluentd` accepts a
private JSON declaration containing paired selected `current` and `proposed`
literal values. It requires all three caller guards to be true:
`selectedValueComplete`, `currentDefaultUsed`, and
`preserveLiteralTreatment`. It derives only whether one simple unquoted
`#{...}` marker is present. The selected values must be byte-identical, except
for the exact single-quote wrapper around the unchanged current literal.
This does not parse a Fluentd file, Ruby, interpolation, plugins, or runtime
behavior. Use the private-copy walkthrough in
[`examples/cncf/fluentd-literal-treatment`](../examples/cncf/fluentd-literal-treatment/README.md).

## Harbor installer argv

For Harbor `2.7.0` to `2.8.0` and the exact `2.10.3`, `2.11.2`, `2.12.4`, `2.13.5`, or `2.14.4` to `2.15.2` pairs, `prepare cncf --project harbor` accepts one
private JSON declaration of the selected installer argv. Set
`effectiveArgvDeclared=true` only after selecting a complete, literal
`make/install.sh` argument vector. The check classifies only the removed
`--with-chartmuseum` option. `--help`, wrappers, values, duplicates, unknown
options, and unresolved inputs remain UNKNOWN. It does not execute the
installer or inspect Harbor configuration, charts, database state, or runtime.
Use the private-copy walkthrough in
[`examples/cncf/harbor-installer-argv`](../examples/cncf/harbor-installer-argv/README.md).

## containerd selected official runtime shim

For containerd `1.7.28` to `2.0.0`, the native TOML route checks the
`runtime_type` of one explicitly selected CRI runtime handler. It admits config
version 2 under `plugins."io.containerd.grpc.v1.cri"` and config version 3
under `plugins."io.containerd.cri.v1.runtime"`. The target automatically
migrates version 2 configuration and the reviewed migration preserves
`runtime_type`, so version 2 alone never blocks.

The two removed official bundled runtime types are
`io.containerd.runtime.v1.linux` and `io.containerd.runc.v1`.
`io.containerd.runc.v2` clears only this selected shim-availability constraint.
The complete, precedence-resolved, official-upstream, and
official-bundled-runtimes-only flags are caller declarations. The last one
means that no separately installed custom shim supplies the legacy runtime
name. Imports, `runtime_path` overrides, custom runtime types, missing handlers,
wrong plugin tables, or omitted declarations remain UNKNOWN. The parser does
not read imports, search the host, run containerd or a shim, inspect a cluster,
or prove configuration startup, container creation, or whole-upgrade behavior.

See the private-copy walkthrough and BLOCKED, PASS, and UNKNOWN examples in
[`examples/cncf/containerd-runtime-shim`](../examples/cncf/containerd-runtime-shim/README.md).

## CoreDNS direct federation directive

The native Corefile route evaluates the presence of a direct, literal
`federation` directive for only the reviewed `1.6.9` to `1.7.0` transition and
the `1.9.4`, `1.10.1`, `1.11.4`, `1.12.4`, or `1.13.2` to `1.14.7`
transitions. It is a local usability route for the existing CoreDNS federation
rule; it does not add a project, rule, or upgrade-pair claim.

Copy a synthetic Corefile to a private local path before use:

```sh
umask 077
cp examples/cncf/coredns-corefile/blocked.Corefile Corefile
chmod 600 Corefile
./prufyx check cncf --project coredns \
  --coredns-corefile Corefile --coredns-corefile-complete \
  --coredns-distribution official --from 1.13.2 --to 1.14.7 \
  --now 2026-09-13T00:00:00Z
```

The caller declares that the selected local Corefile is complete and belongs to
the official distribution. The parser detects only a literal `federation`
token in a direct directive position inside a simple server block. A direct
directive is `BLOCKED`; a safely admitted absence is a scoped `PASS` for this
one federation-removal constraint. Distribution identity, completeness, other
plugin validity, referenced files, DNS behavior, runtime state, and whole
upgrade safety are outside the result.

Balanced brace-delimited plugin bodies are admitted structurally up to 32
levels, but their properties are opaque and a `federation` token inside one is
not a direct directive. `import`, snippets, substitutions, quoted or escaped
text, malformed Corefile structure, and deeper nesting return `UNKNOWN` rather
than a negative-presence PASS. The parser does not read referenced files or
execute CoreDNS. Pinned
CoreDNS `1.14.7` documentation supports server blocks, comments, imports, and
substitutions (`corefile.5.md` lines 5-11 and 28-37) and ordinary plugin bodies
(`plugin/health/README.md` lines 19-25; `plugin/forward/README.md` lines
34-56). Pinned source evidence for the existing rule is the CoreDNS `1.7.0`
release note at commit `f59c03d09c3a3a12f571ad1087b979325f3dae30` and the
`1.14.7` `plugin.cfg` at commit
`427fc80ed9ca47f354585eb30a3f1332950856c4`. See the complete synthetic
BLOCKED, PASS, and UNKNOWN walkthrough in
[`examples/cncf/coredns-corefile`](../examples/cncf/coredns-corefile/README.md).

## Strimzi Kafka v1beta2 API removal

The native Kafka resource route evaluates which `kafka.strimzi.io` API version
one caller-selected rendered `kind: Kafka` resource, or one flat `v1` `List` of
rendered resources, literally uses. It covers only the reviewed `0.51.0` to
`1.0.0` transition. It is a local usability route for the existing Strimzi
`strimzi.kafka-v1beta2-api-removed.1-0` rule; it does not add a project, rule,
or upgrade-pair claim.

```sh
umask 077
cat > kafka.json <<'JSON'
{"apiVersion":"kafka.strimzi.io/v1beta2","kind":"Kafka","metadata":{"name":"cluster","namespace":"kafka"},"spec":{"kafka":{"replicas":3}}}
JSON
chmod 600 kafka.json
./prufyx check cncf --project strimzi \
  --kafka-resource kafka.json --strimzi-distribution official_upstream \
  --target-kafka-crd-admission-required --from 0.51.0 --to 1.0.0 \
  --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution and that the selected resources
must be admitted by the target Kafka CRD. Any selected `Kafka` document on
`kafka.strimzi.io/v1beta2` is `BLOCKED`; a selection whose `Kafka` documents are
all on `kafka.strimzi.io/v1` is a scoped `PASS` for this one removal
constraint. A `custom_build` declaration, an undeclared target-CRD admission
intent, `KafkaTopic`, `KafkaUser` or unrelated kinds, another served
`kafka.strimzi.io` version, unresolved templating, a paginated or typed list,
and a structurally unresolved object all remain `UNKNOWN` rather than a
negative-presence PASS.

The route does not install or read a CRD, run API admission or conversion,
inspect stored objects, or establish operator, broker, topic, or client
behavior. Pinned source evidence for the existing rule is the Strimzi
`040-Crd-kafka.yaml` served-version block and `CHANGELOG.md` at commit
`4836c7dd74ce973f06d97936916ed7f20c1a2ff0`, the same CRD at commit
`54081abf97d0e5e524de773b88343756934db1a8`, and the
`con-api-conversion-v1.adoc` upgrade module. Whole-upgrade safety remains
`UNKNOWN`.

## Falco removed 0.40 CLI spellings

The native Falco argv route decides whether one caller-declared explicit
effective Falco argv literally contains any of `-A`, `-b`, `--print-base64`,
`-S`, or `--snaplen`. It covers only the reviewed `0.40.0` to `0.41.0` and
`0.40.0` to `0.42.0` transitions. It is a local usability route for the existing
`falco.deprecated-cli-flags-removed` rules; it does not add a project, rule, or
upgrade-pair claim.

```sh
umask 077
cat > falco-argv.json <<'JSON'
["falco","-c","/etc/falco/falco.yaml","--snaplen","256"]
JSON
chmod 600 falco-argv.json
./prufyx check cncf --project falco \
  --falco-argv falco-argv.json --falco-distribution official_upstream \
  --from 0.40.0 --to 0.41.0 --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution. An argv containing a removed
spelling is `BLOCKED`; an argv on the reviewed `falco` executable surface
containing none of the five spellings is a scoped `PASS` for this one removal
constraint.

The adapter models no Falco option table, because an option table that guessed
an arity wrongly could skip a removed spelling as if it were another option's
value. It compares every token instead, so absence is reported only when no
token in the whole argv can be one of the five spellings. A `custom_build`
declaration, an undeclared distribution, a wrapper or any other command surface,
a clustered or value-attached short token such as `-Ab` or `-S256`, a bare `-`
or `--`, unresolved templating, and an unparseable shape all remain `UNKNOWN`
rather than a negative-presence PASS.

The route never executes the argv and does not resolve a wrapper, an image
entrypoint, environment, Helm values, defaults, or runtime behavior. Pinned
source evidence for the existing rules is the Falco `CHANGELOG.md` and
`userspace/falco/app/options.cpp` at commits `b94cda0b12e5`, `ce4b4408988d`, and
`d8e430e35239`. Whole-upgrade safety remains `UNKNOWN`.

## Kuma removed transparent-proxy UID exclusion flags

The native Kuma argv route decides whether one caller-declared explicit
effective `kumactl install transparent-proxy` argv literally contains either
`--exclude-outbound-tcp-ports-for-uids` or
`--exclude-outbound-udp-ports-for-uids`. It covers only the reviewed `2.8.0` to
`2.9.0` transition. It is a local usability route for the existing Kuma
`kuma.deprecated-exclude-uid-flags-removed.2-8-to-2-9` rule; it does not add a
project, rule, or upgrade-pair claim.

```sh
umask 077
cat > kumactl-argv.json <<'JSON'
["kumactl","install","transparent-proxy","--exclude-outbound-tcp-ports-for-uids","3000:1000"]
JSON
chmod 600 kumactl-argv.json
./prufyx check cncf --project kuma \
  --kumactl-argv kumactl-argv.json --kuma-distribution official_upstream \
  --from 2.8.0 --to 2.9.0 --now 2026-09-18T00:00:00Z
```

The caller declares the proposed distribution. An argv containing either removed
spelling is `BLOCKED`; an argv on the reviewed command surface containing
neither is a scoped `PASS` for this one removal constraint.

Like the Falco route, the adapter models no option table and compares every
token, so absence is reported only when no token in the whole argv can be one of
the two spellings. Only the direct literal command path is resolved: a
`custom_build` declaration, an undeclared distribution, another `kumactl`
subcommand, a global option placed before the subcommand, a wrapper, an
ambiguous short token, a bare `-` or `--`, unresolved templating, and an
unparseable shape all remain `UNKNOWN` rather than a negative-presence PASS.

The route never executes the argv. Presence of the target-supported
consolidated `--exclude-outbound-ports-for-uids` form is not treated as
equivalent to either removed spelling in either direction, and no Dataplane
migration, image, default, or runtime behavior is established. Pinned source
evidence for the existing rule is `app/kumactl/cmd/install/install_transparent_proxy.go`
at commits `1110a0305eec` and `948e6a439163` and `UPGRADE.md` at commit
`948e6a439163`. Whole-upgrade safety remains `UNKNOWN`.

## Envoy direct V2 transport blocker

The Envoy native route is a blocker-only usability route for the existing
`component.envoy.xds_api_major` rule. It accepts a private, regular JSON
bootstrap no larger than 1 MiB and the caller's `--envoy-bootstrap-selected`
declaration. It emits `v2` only when a direct, uppercase `V2` witness occurs
at `dynamic_resources.ads_config.transport_api_version` (with `api_type:
GRPC`), `dynamic_resources.lds_config.api_config_source.transport_api_version`,
or `dynamic_resources.cds_config.api_config_source.transport_api_version` (the
latter two require an admitted explicit `api_type`). It supports only the
existing `1.34.14`, `1.35.13`, `1.36.10`, `1.37.6`, and `1.38.4` to `1.39.1`
pairs.

```sh
umask 077
cp bootstrap.json private-bootstrap.json
chmod 600 private-bootstrap.json
./prufyx check cncf --project envoy \
  --envoy-bootstrap private-bootstrap.json --envoy-bootstrap-selected \
  --from 1.38.4 --to 1.39.1 --now 2026-09-13T00:00:00Z
```

Absent, `AUTO`, `V3`, numeric, lowercase, lower-camel aliases, malformed
selected ConfigSource oneofs, and valid but unsupported JSON shapes remain
`UNKNOWN`; malformed JSON containers (objects or arrays), unreadable files,
invalid encoding, and oversized input are rejected. YAML and other non-JSON
text are safely bounded but not parsed, so they remain `UNKNOWN`. It does not
derive a native PASS. Static resources,
`resource_api_version`, `self`, `hds_config`, `config_sources`,
`default_config_source`, `typed_config`/Any, extensions, fetched discovery
resources, network behavior, server behavior, runtime state, and distribution
identity are outside this route. The `1.39.1` target evidence is Envoy commit
`b579d07d3ad7ee11d32b105e91a5a39ad24718d7`: bootstrap proto lines 61-90,
ConfigSource proto lines 25-75 and 182-227, and `utility.h` lines 138-155.

## cert-manager removed monitor values

```sh
umask 077
cat >values.json <<'JSON'
{"prometheus":{"servicemonitor":{"path":"/custom"}}}
JSON
./prufyx check cert-manager-values \
  --from 1.20.3 --to 1.21.1 --values ./values.json
```

The check has one claim: whether the exact merged values contain any of
`prometheus.servicemonitor.path`,
`prometheus.servicemonitor.targetPort`, or
`prometheus.podmonitor.path`. Presence is `BLOCKED`; absence is a scoped
`PASS`; a non-object parent is `UNKNOWN`. Every report keeps the aggregate
assessment `UNKNOWN`. Arbitrary unknown keys and the rest of the target Helm
schema remain outside this predicate. Run `helm template` with the exact target
chart and schema validation enabled for full schema coverage.

`--schema-validation required` is the default and permits a source-backed
`BLOCKED` when a removed key would fail Helm schema validation. If the intended
render disables that validation, pass `--schema-validation disabled`; a removed
key becomes `ATTENTION` because the target templates ignore the override.

The report displays the baked-in official chart manifest digests. The declared
versions select that reviewed source contract; they do not prove those charts
match a deployed installation. Optional `--current-chart-digest` and
`--target-chart-digest` assertions fail with exit 3 when they differ.

The additive latest target is `1.21.2`. It accepts the five reviewed chart
origins `1.20.3`, `1.19.6`, `1.18.6`, `1.17.4`, and `1.16.5`; each route keeps
the same three removed monitor-value paths. For a local synthetic check, copy
[`examples/community/cert-manager-removed.json`](../examples/community/cert-manager-removed.json)
to a private values file and select any one of those origins:

```sh
umask 077
cp examples/community/cert-manager-removed.json values.json
chmod 600 values.json
./prufyx check cert-manager-values \
  --from 1.19.6 --to 1.21.2 --values values.json \
  --current-chart-digest sha256:5d95e81072636335b7b43fc2517e5336b93b77d41a4c87cbaf291783f03b4a0f \
  --target-chart-digest sha256:634dce9c13b56677a2c05e2ab76c312d0be2664022d5dd05815da67e1fd5f610
```

The target chart identity is pinned to the official OCI manifest digest. The
historical `1.20.3` to `1.21.1` route remains available with its original
contract; neither route proves full Helm schema, rendering, runtime behavior,
or whole-upgrade safety.

To retain and replay a deterministic JSON receipt, bind the original input by
its SHA-256 digest:

```sh
digest="sha256:$(shasum -a 256 values.json | awk '{print $1}')"
./prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 \
  --values ./values.json --values-digest "$digest" --format json >receipt.json
./prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 \
  --values ./values.json --values-digest "$digest" \
  --replay-receipt ./receipt.json --format json
```

Replay requires the original local values file, its explicit digest, and the
receipt. It compares deterministic canonical output. This detects local drift;
the receipt's self-consistency does not authenticate its author.

Exit codes are bound to this named predicate: 0 `PASS`, 10 `BLOCKED`, 11
`ATTENTION` or `UNKNOWN`, 2 invalid input, and 3 integrity mismatch.

## Prometheus agent mode

The synthetic demonstration exercises the pinned PASS, ATTENTION, and UNKNOWN
vectors without observation or compatibility authority:

```sh
./prufyx check prometheus-mode --demo --format json
```

For an actual local observation and proposed workload, use:

```sh
./prufyx check prometheus-mode \
  --observation-root ./observation \
  --proposed-workload ./proposed.json \
  --proposed-digest sha256:... \
  --captured-at 2026-09-07T10:00:00Z \
  --now 2026-09-07T10:00:00Z \
  --max-age 24h
```

The new command exits 0 only when the agent-mode preservation claim is `PASS`;
`ATTENTION` and `UNKNOWN` exit 11. The aggregate remains `UNKNOWN`. The legacy
`community-preview validate-prometheus-mode` route retains its aggregate exit
11 behavior.

## SPIFFE X.509-SVID public-leaf URI-SAN subset

Use `prufyx check spiffe-x509-svid --certificate FILE --now RFC3339` for the
embedded standards profile. This command has no from/to versions. It returns
`PASS`, `FAIL`, or `UNKNOWN` for one named subset and leaves complete SPIFFE ID,
X.509-SVID, trust, possession, issuance and runtime checks unresolved. Private
input, exact replay, explicit local profile selection and exit semantics are in
the [SPIFFE conformance guide](spiffe-x509-svid.md).

## CloudEvents structured JSON core-envelope subset

Use `prufyx check cloudevents-structured-json --event FILE --now RFC3339` for
the embedded standards profile. This command has no from/to versions. It
returns `PASS`, `FAIL`, or `UNKNOWN` for one staged CloudEvents edition 1.0
core-envelope subset. Payload schemas, source URI semantics, extensions,
transport, SDK/runtime behavior, delivery, signing, and authentication remain
unresolved. Private input, Unicode and duplicate-key handling, selected local
profile metadata, exact replay, and exit semantics are in the [CloudEvents
conformance guide](cloudevents-structured-json.md).

## TiKV 8.5.8 GCS WIF full-backup planned-operation preflight

Use `prufyx check tikv-gcp-v2-wif-backup --config FILE --target-version
8.5.8 --operation gcs-full-backup-wif --now RFC3339` for the embedded target
profile. The check reads one proposed native TiKV TOML file and evaluates only
whether exactly one supported `[backup]` spelling explicitly sets the GCP v2
backend Boolean to `true` for the caller-declared plan. A scoped `PASS` does not
establish effective configuration, credentials, GCS access, backup execution or
completion, restore or log-backup behavior, runtime behavior, or data safety.
Private input, the exact `BLOCKED` remediation, selected local profile metadata,
raw-byte pinning, historical replay, and exit semantics are in the [TiKV target
preflight guide](tikv-gcp-v2-wif-backup.md).
