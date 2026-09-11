# Community source authority

`community-shipping-policy-v2.json` is the sole human-maintained authority for
the Community source package. `community-release-gate.py` derives its exact
contents from that policy and Go 1.26.8 package metadata. Generated manifests
are content-addressed release receipts. Historical manifests and package lists
are retained records and do not authorize files in this package.

The gate retains support for the v1 policy, which admits only a module with no
external dependencies. The active v2 policy admits one exact vendored module
profile. It binds every module version and `go.sum` identity, the canonical
vendor tree as sorted path/mode/length/SHA-256 records, exact notice copies,
and every binary vendor resource. A modified, missing, or extra vendor file,
module replacement, unknown module, notice mismatch, or binary-resource drift
fails before a source manifest can be issued. Builds use `-mod=vendor` with the
module proxy and checksum service disabled.
The gate recomputes the vendor-tree digest from the final captured manifest
bytes and requires the captured v2 policy bytes to equal the policy used for
derivation, closing changes between preliminary validation and staging.

The policy selects the focused `./cmd/prufyx-community` entrypoint for the
cert-manager removed-monitor-values check and the Prometheus declared Agent
mode check. It explicitly selects the public documentation, examples, legal
notices, CI definitions, release tools, local collection tools, offline test
suites, and their fixtures. The gate derives the entrypoint's complete
in-module production closure across every source-build tuple, including
architecture-specific Go files and embedded contracts. It also derives direct
tests and testdata for every production package, tagged parity tests, their
in-module dependency closure, and module metadata. Every production package,
including the main package, must have a direct test.

Every selected file is opened without following symlinks, must be a regular
single-link file, is bounded by size, and is recorded by path, mode, length,
role, and SHA-256. Text is required except for the exact binary vendor resource
pinned by the v2 policy. Private-key blocks are rejected. CI adds Gitleaks
over the derived stage; there are no target, customer, backend, or brand names
in exclusion rules.

`buildTargets` permits Linux amd64 and arm64 release binaries.
`sourceBuildTargets` additionally includes Darwin arm64 so the source closure
contains the variants required by the supported development host. This does
not make a Darwin binary-release claim. The policy pins the official Go archive
SHA-256 for each source-build tuple; CI verifies the applicable archive before
invoking the gate.

The policy requires `./cmd/prufyx-community` and its focused
`internal/communityapp` closure. The gate fails closed if that entrypoint or
any selected production source, direct test, tagged parity test, embedded
contract, operator fixture, or required document is absent.

Generate a receipt outside the source tree without overwriting an existing
file:

```sh
python3 cli/release/community-release-gate.py \
  --source-root . \
  --policy cli/release/community-shipping-policy-v2.json \
  --go /absolute/path/to/go1.26.8/bin/go \
  generate --output /tmp/SOURCE-MANIFEST.json
```

After generation succeeds, `verify` recomputes the receipt from source and
`stage` copies only those exact bytes. On any declared native source-build
target, `stage --run-native-checks` runs `go vet ./...`, ordinary and tagged Go
tests, the release-gate regression suite, both offline collector suites, and
Linux amd64 and arm64 cross-builds inside the staged tree. Release CI also runs
the full race suite natively on both Linux release architectures, reachable
source and binary vulnerability checks, a secret scan of the exact staged
source, and a separate secret scan of the complete Git history before
publication can run.

## Protected staging contract

The `community-release.yml` workflow is a protected, non-publishing staging
workflow for the exact `v0.1.0-alpha.5` tag. It requires the expected public
repository visibility before any staging provenance can run. Its native build,
source manifest, archive-only smoke, and final checksum verification must succeed
before the final bundle is uploaded. It has no GitHub release-write
permission and contains no release-creation command.

The staging receipt is created only as `STAGING-RECEIPT.json` inside the
exact verified bundle after `community-release.sh verify`. It is canonical JSON
and records the exact repository identity, exact workflow path and workflow SHA, push
event, first run attempt, run ID, protected tag/ref, source SHA, version, the
fixed artifact name, every fixed asset name and SHA-256 digest, and the
SHA-256 digest of `SHA256SUMS`. The receipt is deliberately excluded from
`SHA256SUMS`; `actions/attest` treats the assets *listed by* that checksum file
as subjects, not the checksum file itself. Before creation and after download,
the helper requires the exact regular single-link directory set, canonical
checksums and receipt JSON, rehashes every named subject, and rejects missing,
extra, duplicate, non-canonical, tampered, or identity-mismatched inputs.

Only the staging provenance job may request OIDC and attestation-write
permissions. It validates the fixed `community-staging-bundle` container from
the Actions REST response after upload, but the receipt does not self-bind the
container ID or digest. A future separately authorized publisher must fetch
that exact first-attempt run, obtain and validate the container identity again
from Actions REST, rerun the same bundle verifier, verify the existing
attestations, and alone use release-write permission. The staging workflow
itself never creates a tag, release, feed, or public asset.

## Future manual publisher

`community-publish.yml` is an activated but fail-closed manual boundary:
`PUBLICATION_ENABLED=true` has no dispatch override and does not itself authorize
a release. A dispatch still requires the expected public repository, protected
`main` ref, exact current publisher workflow SHA, and the fixed first-attempt
staging run, artifact ID/digest, source SHA, and staging-workflow SHA. Its
read-only verifier validates that exact staging container, checksum subjects, and
existing attestations before a separate write job can run. The write job must not
check out, build, sign, attest, or execute downloaded files. Missing, changed, or
unverifiable identities fail closed; this source state creates no tag, release,
or public asset.
