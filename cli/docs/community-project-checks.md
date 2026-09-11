# Community project checks

`prufyx check project` is a separate, embedded-only source-rule preview for a
small maintainer-reviewed registry outside the CNCF Landscape. It does not
assert CNCF membership and does not use the CNCF knowledge profile or store.

From the repository root, build the preview with the validated offline
toolchain settings and keep its binary and private inputs outside the checkout:

```sh
set -eu
umask 077
PREVIEW_DIR="$(mktemp -d)"
trap 'rm -rf "$PREVIEW_DIR"' EXIT
test "$(go env GOVERSION)" = go1.26.8
(cd cli && GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o "$PREVIEW_DIR/prufyx-community" ./cmd/prufyx-community)
```

Three checks inspect native effective-configuration files locally:

- Grafana `10.4.0` → `11.0.0`: whether a proposed `grafana.ini` explicitly
  sets `[alerting] enabled=true`, which Grafana 11 rejects during settings
  loading. Passing this predicate does not prove that alert data was migrated.
- Kibana `8.18.0` → `9.0.0`: whether a proposed `kibana.yml` retains
  `xpack.reporting.roles.allow`, which Kibana 9 no longer supports. Passing
  this predicate does not validate feature privileges or reporting access.
- Fluent Bit `3.2.0` → `4.0.0`: whether a complete proposed classic
  configuration preserves an enabled OpenTelemetry `http2` setting after
  Fluent Bit changed its default from `on` to `off`. This requires the
  caller to declare that the current default was used and that preservation
  is intended. It checks only the enabled setting; protocol negotiation,
  TLS, connectivity, collector behavior, and whole-upgrade compatibility
  remain UNKNOWN. Fluent Bit is a neutral community-project identity; CNCF
  membership is not asserted.

The Fluent Bit example files are native classic configuration snippets. Copy
one to a private file and declare the current default and preservation intent:

```sh
cp cli/examples/projects/fluent-bit/broken.conf "$PREVIEW_DIR/fluent-bit.conf"
"$PREVIEW_DIR/prufyx-community" check project \
  --project fluent-bit \
  --effective-config "$PREVIEW_DIR/fluent-bit.conf" \
  --from 3.2.0 --to 4.0.0 \
  --effective-config-complete --current-default-was-used \
  --preserve-http2-enabled \
  --now 2026-09-12T00:00:00Z
```

The bounded parser admits one `[OUTPUT]` section with an exact `Name
opentelemetry` row and selected `http2 on|off|force` or `grpc off` values.
It requires consistently space-indented key/value rows separated by an ASCII
space. Includes, environment substitutions, duplicate keys, case aliases,
tabs, Unicode whitespace, continuations, other sections, and unresolved
`grpc on|auto` forms remain UNKNOWN. Values for unrelated rows are discarded.
Use `fixed.conf` for a scoped PASS and `unknown.conf` for an unsupported
configuration shape; `broken.conf` is BLOCKED under the preservation intent.

The Argo Workflows `3.5.0` → `3.6.0` check inspects one caller-supplied native
Kubernetes Deployment. It selects the unique `argo-server` container bound to
the reviewed `quay.io/argoproj/argocli:v3.6.0` image and either explicit
`command: ["argo"]` or that exact image's reviewed `ENTRYPOINT ["argo"]`
default. A literal `server --basehref` option is BLOCKED because
3.6 renamed it to `--base-href`; absence is a scoped argv PASS only when the
caller declares the selected argv complete. This does not verify the image,
deployment, cluster, or server runtime.

The Ceph Quincy `17.2.7` → Reef `18.2.0` preflight inspects one private,
caller-selected **current** native per-OSD `ceph osd metadata ID` JSON output
containing exact `id` and `osd_objectstore` fields. A matching `filestore`
backend is BLOCKED because
the reviewed Reef object-store factory rejects FileStore; `bluestore` is a
scoped PASS for this selected-current-object predicate. This input is not a
whole `ceph report`, OSD inventory, target deployment observation, or cluster
safety assessment. The reviewed Quincy selected-OSD command establishes the
numeric-id metadata-object projection; the reviewed Reef factory supplies the
target FileStore rejection.

Copy a public fixture to a private file before checking it:

```sh
umask 077
cp cli/examples/projects/grafana/broken.ini "$PREVIEW_DIR/grafana-proposed.ini"
"$PREVIEW_DIR/prufyx-community" check project \
  --project grafana \
  --effective-config "$PREVIEW_DIR/grafana-proposed.ini" \
  --from 10.4.0 --to 11.0.0 \
  --effective-config-complete --precedence-resolved \
  --now 2026-09-11T20:00:00Z
```

Input must be a regular `0600` file without symlinks. The completeness and
precedence flags are explicit caller declarations: use them only after the
file represents all effective settings, including environment and CLI
overrides. Without either declaration the relevant fact remains UNKNOWN.

For the workload check, copy a public example to a private file from the `cli`
directory, then evaluate the same file locally:

```sh
umask 077
cp cli/examples/projects/argo-workflows/broken.json "$PREVIEW_DIR/argo-server-proposed.json"
"$PREVIEW_DIR/prufyx-community" check project \
  --project argo-workflows \
  --workload "$PREVIEW_DIR/argo-server-proposed.json" \
  --from 3.5.0 --to 3.6.0 \
  --workload-complete \
  --now 2026-09-11T21:00:00Z
```

The workload parser accepts only an `apps/v1` Deployment, the exact reviewed
image and command binding, a literal `server` argv, and empty or absent `env`
and `envFrom`. It recognizes `--basehref` and `--base-href`; unrelated options
are admitted only in literal self-contained `--lowercase-name=value` form.
Sidecars are discarded. Custom images, wrappers, bare unrelated options,
positional or dynamic values, duplicate selected names or inspected options,
argument-file markers, shell expansion, and `--` remain UNKNOWN. Raw workload
fields and argument values are discarded. An omitted `command` is labeled as
source-derived from the reviewed exact-image entrypoint, not an observed value.

For the Ceph preflight, copy one selected metadata object to a private file and
bind its decimal OSD id explicitly:

```sh
umask 077
cp cli/examples/projects/ceph/filestore.json "$PREVIEW_DIR/ceph-osd-7-current.json"
"$PREVIEW_DIR/prufyx-community" check project \
  --project ceph \
  --selected-osd-metadata "$PREVIEW_DIR/ceph-osd-7-current.json" \
  --selected-osd-id 7 \
  --from 17.2.7 --to 18.2.0 \
  --selected-osd-metadata-complete \
  --now 2026-09-11T21:00:00Z
```

The completeness flag declares only that this selected per-OSD output contains
the selected current OSD identity and backend. The id must be an exact nonnegative
JSON integer within the reviewed command's signed 64-bit range and match
`--selected-osd-id`; only lowercase `filestore` and
`bluestore` are admitted. Missing, mismatched, ambiguous, or unsupported forms
remain UNKNOWN. Unrelated fields are discarded, and the id, backend value,
path, and other raw fields never enter the canonical input or report.

Grafana input is native INI. The parser reads only the exact `alerting.enabled`
key and rejects duplicate relevant sections or keys. Kibana input is native
YAML in the documented dotted-key form or a plain nested mapping; JSON object
syntax is also accepted because it is a YAML subset. YAML aliases, anchors,
tags, merge keys, flow maps, and ambiguous relevant structures remain UNKNOWN.
Unrelated values are discarded, and raw configuration, paths, member names,
and values do not enter reports.

`prepare project` exposes the same minimizer and can emit the canonical
operator-declared input with `--format input`. `check project` evaluates that
input in memory. Both commands use packaged reviewed references only. External
updates, signed bundles, historical replay, network access, runtime checks,
and whole-upgrade conclusions are unavailable in this first neutral profile.
Unsupported project identities and conflicting knowledge/replay selectors are
rejected instead of falling back to CNCF behavior.

Project identity and rule evidence live in a closed data registry and rule
pack, while all checks reuse the existing typed constraint evaluator. The
pack can contain multiple uniquely identified rules for one project and exact
transition. Evaluation selects only rules matching the requested project and
endpoints, so another reviewed transition cannot turn a supported result into
UNKNOWN. An exact transition using one of the compiled Boolean facts can be
added as reviewed embedded metadata. A new native setting, parser grammar, or
fact type still requires a reviewed binary release. Signed external updates
for this neutral registry are not implemented.

Exit status is `0` for a scoped PASS, `10` for a scoped BLOCKED result, `11`
for UNKNOWN, `2` for invalid input, and `3` for integrity failure. The report's
aggregate remains UNKNOWN for every result.
