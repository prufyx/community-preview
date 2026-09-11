# Contributing to Prufyx

Thank you for helping improve Prufyx. Spas Atanasov is the maintainer for this
release.

## Before you start

For a bug or a small documentation fix, open a focused pull request. For a new
compatibility claim, collection field, command, or larger change, open an issue
first so its evidence and data boundary can be reviewed.

Never submit credentials, Kubernetes Secrets, production snapshots, raw
customer objects, private configuration, sensitive logs, or source material
you do not have permission to redistribute. Examples and tests must use public
synthetic fixtures and label them as non-authoritative.

Compatibility work should state:

- the exact component versions, platform, deployment mode, and relevant
  configuration predicates;
- the immutable public sources and exact spans supporting the rule;
- what was reproduced, approximated, stubbed, or omitted;
- the expected `PASS`, `ATTENTION`, `BLOCKED`, or `UNKNOWN` behavior and a
  falsifiable test;
- whether collection, permissions, retained data, network access, or mutation
  authority changes.

`UNKNOWN` is a valid result. Do not turn absent, nearby, synthetic, or stale
evidence into a safety claim.

For a public upstream identity or transition proposal, use the closed offline
[evidence-packet workflow](cli/docs/upstream-contributions.md). A validation
receipt proves packet consistency only; it does not authenticate a reviewer,
verify an upstream source, authorize a rule, or publish data.

## Develop locally

Use Go 1.26.8. Go dependencies are pinned in `cli/vendor`; use the vendored,
offline dependency set for every local check. From the repository root:

```sh
cd cli
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go test ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go vet ./...
CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  GOFLAGS='-mod=vendor -buildvcs=false' go build -trimpath -o ../prufyx ./cmd/prufyx-community
```

Run relevant race tests on a native supported host with a C toolchain using
`CGO_ENABLED=1 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' go test -race ./...`.
Published binaries use `CGO_ENABLED=0`.
Collector tests also need Python 3, Bash and jq; they use synthetic local input
and do not require a cluster. Follow the exact staged-source instructions in
[the source gate](cli/release/COMMUNITY-SOURCE-GATE.md).

Keep changes focused. Add a regression test when behavior changes, and include
the exact commands and outcomes in the pull request description. Changes to
collection fields need a compatibility-predicate justification and disclosure
review.

## Sign off commits (DCO 1.1)

All contributions are made under the [Apache License 2.0](LICENSE) and must be
signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
Add a sign-off using your real name and an email address you are authorized to
use:

```sh
git commit -s -m "docs: clarify the Prometheus mode example"
```

The commit message must contain:

```text
Signed-off-by: Your Name <you@example.com>
```

By adding that line, you certify the DCO 1.1 for that contribution. The DCO is
not a copyright assignment.

## Review

The maintainer may ask for narrower scope, clearer evidence, a data-boundary
review, or a reproducible test. A contribution is merged only after its tests,
license, provenance, security, and product-truth checks pass.
