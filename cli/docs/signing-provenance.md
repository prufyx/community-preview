# Release provenance and local check evidence

The Community release workflow produces SHA-256 checksums and GitHub Actions
artifact attestations. Verify a supplied archive before executing it.
Attestation verification establishes the repository, workflow and source
revision that produced an artifact. A checksum alone detects changed bytes;
it does not authenticate their origin.

Artifact provenance is separate from the compatibility claim. The focused
checks embed reviewed source contracts and deterministic predicates. Their
whole-upgrade aggregate remains `UNKNOWN`. This release has no downloaded
knowledge database, evidence-signing service, plugin loader or background
refresh. The build identity reports `trustRootDigest: UNPINNED` and
`candidateOnly: true`; those fields do not turn local reports into signed
Prufyx compatibility evidence.

## Verify a supplied archive

Use GitHub CLI with artifact attestation support. The following example uses the
artifact layout produced by the release workflow. Public downloads are not
available during the current private preview. When the release owner supplies a
specific archive, checksum asset and tag, substitute those exact values below;
do not infer them from a historical alpha archive.

```sh
VERSION=v0.1.0-alpha.5
ARCHIVE="prufyx-cli_${VERSION#v}_linux_amd64.tar.gz"
RELEASE_TAG="$VERSION"
SOURCE_COMMIT="<independently-reviewed-40-character-release-commit>"
sha256sum -c SHA256SUMS
gh attestation verify "$ARCHIVE" \
  --repo prufyx/prufyx-cli \
  --signer-workflow prufyx/prufyx-cli/.github/workflows/community-release.yml \
  --source-ref "refs/tags/$RELEASE_TAG" \
  --source-digest "$SOURCE_COMMIT" \
  --deny-self-hosted-runners
```

The release owner's Go `release verify` workflow checks the archive layout,
metadata and `SOURCE-REVISION` binding before a formal bundle is finalized.
Do not replace that validation with an ad-hoc JSON parser.

Release assembly uses a dedicated output directory owned by the current user
with mode `0700`. Use a separate directory for each release version. Versioned
archives and `SHA256SUMS` refuse overwrite; repeatable source sidecars and
finalization metadata replace only safe regular files through atomic local
updates. Finalization rejects links, hard links and unexpected output members.

Use the archive matching the host architecture. Every checksum and attestation
verification must succeed before execution. GitHub verification needs network
access unless you separately prepare and manage offline trust inputs. The
Prufyx evaluator itself remains offline. Do not take `SOURCE_COMMIT` from the
archive and then treat it as an independent expected identity. A private CI
rehearsal has no OIDC-backed release attestation and is explicitly unsigned; use
its commit only as an input to review, not as published provenance.

## Inspect and reproduce the selected source

The release assets include `SOURCE-REVISION`, `SOURCE-MANIFEST.json`,
`SOURCE-TREE.sha256` and `SBOM.spdx.json`. The source manifest records each
selected file's content digest, size, mode and role. It is derived from the
single shipping policy and the focused entrypoint's Go dependency closure.
It is delivered beside the archive to avoid hashing itself into its own input.

`SOURCE-TREE.sha256` identifies the uncompressed canonical tar of the selected
source tree before the versioned archive prefix or gzip layer. Recreate it
from the extracted source directory using GNU tar:

```sh
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  --mode='u+rwX,go+rX,go-w' -cf source-tree.tar \
  -C prufyx-cli_<version>_source .
sha256sum -c SOURCE-TREE.sha256
```

This digest differs from the source download's checksum. In binary metadata,
`releaseManifestDigest` and the retained compatibility field `allowlistDigest`
are SHA-256 of the complete canonical `SOURCE-MANIFEST.json` bytes. The
manifest's internal digest is a separate field and must not be substituted.
The binary's `version` output binds the source revision, selected source digest,
manifest digest, target and Go version.

See [Community source authority](../release/COMMUNITY-SOURCE-GATE.md) for
receipt generation, verification and tests. Published binaries target native
Linux amd64 and Linux arm64. Selected source variants additionally cover
Darwin arm64. The SPDX inventory describes Prufyx, its Go runtime/standard
library; it is not a
file-level inventory of the entire build environment. `LICENSES` and
`THIRD-PARTY.md` preserve the included notices.
