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
