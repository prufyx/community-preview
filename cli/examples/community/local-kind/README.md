# Local kind declaration proof

This fixture exercises the real Kubernetes API collection path without
starting Prometheus. `current-prometheus-agent.yaml` creates one Deployment
with `replicas: 0`; the evidence is therefore a declaration observation only.
It does not show that Prometheus starts, applies Agent mode, preserves data or
remote-write behavior, or supports a whole upgrade.

Use kind v0.31.0 and the reviewed native node image:

```text
kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f
```

The proof runner requires Bash, kind with a Docker-compatible provider,
kubectl, jq 1.7 or newer, Python 3, the
local tools listed in [local-collection.md](../../../docs/local-collection.md),
and an already-built `prufyx` Community binary. Give it an absolute binary path
and a new absolute evidence-directory path:

```sh
bash cli/examples/community/local-kind/run.sh \
  /absolute/path/to/prufyx \
  /absolute/new/local-kind-evidence
```

The runner generates an unpredictable name, proves it was absent, creates one
disposable cluster, and supplies a task-specific kubeconfig to every kind and
kubectl operation. It copies the shipped read-only proposal fixtures to private
mode-0600 files before admission. Its exit trap deletes only the run-owned
cluster and task directory, makes cleanup failure visible, and never changes
the ordinary user kubectl context.

The runner refuses before cluster creation when an ambient proxy variable is
present. Review the local routing policy and deliberately unset that variable,
or run the collector separately and opt in to the exact required proxy name
with `--exec-env`. The runner does not make that choice automatically.

The evidence receipt binds the SHA-256 digest and path-free `prufyx version`
identity of the exact binary used. The runner hashes the binary again after all
evaluations and fails if it changed.

The collector performs only the fixed GET/LIST footprint in
[local-collection.md](../../../docs/local-collection.md). Missing APIs and
denied reads stay as explicit omissions. The bare kind proof does not install
cert-manager APIs or convert their absence into successful evidence.

Evaluate each proposed fixture with the same admitted observation and explicit
clock. Compute each `--proposed-digest` from the exact file bytes as shown in
[prometheus-mode.md](../../../docs/prometheus-mode.md). Expected scoped results
are:

| Proposed fixture | Scoped result | Process exit | Aggregate |
| --- | --- | --- | --- |
| `proposed-preserve-agent.json` | `PASS` | `0` | `UNKNOWN` |
| `proposed-change-to-server.json` | `ATTENTION` | `11` | `UNKNOWN` |
| `proposed-ambiguous.json` | `UNKNOWN` | `11` | `UNKNOWN` |

Running the same binary twice with the same observation bytes, proposal bytes,
`--captured-at`, `--now`, and `--max-age` must produce byte-identical reports.
Delete the cluster through the task-specific kubeconfig and verify its unique
name is absent from `kind get clusters` before retaining a cleanup receipt.
