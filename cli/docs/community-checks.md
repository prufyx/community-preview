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
