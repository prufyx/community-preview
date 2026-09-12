# Offline CNCF knowledge publisher preparation

`prufyx-maintainer knowledge-publish` prepares and finalizes one externally
signed CNCF knowledge package. It is an offline maintainer tool. It
does not generate or load private keys, call a signer, fetch metadata, publish
bytes, choose a trust authority, or change the CLI's `OPERATOR_PROVISIONED` and
`CANDIDATE_ONLY` report labels.

The input target must be a canonical `operator_provided` replacement snapshot
for `knowledge/constraints.v1.json` and the exact capability compiled into this
source tree. Replacement means the selected feed target stands on its own and
is never merged with an installed snapshot. Its reviewed rules may differ from
the embedded set, including data-only additions, removals, or an empty snapshot
that intentionally supplies no coverage. The separately reviewed CNCF exporter
can produce the current complete 158-rule embedded snapshot. Supply a signed
public TUF root and its SHA-256 through an independent trusted process. The root
stays separate from the target and package.

TUF signing is sequential. Snapshot metadata hashes the finalized targets
metadata, including its signatures; timestamp metadata hashes the finalized
snapshot. A signer therefore cannot sign all three payloads in parallel.

Use a private working directory and absolute paths:

```sh
umask 077
mkdir -m 700 /absolute/publisher

prufyx-maintainer knowledge-publish prepare-targets \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --version 1 --expires 2026-12-01T00:00:00Z \
  --output /absolute/publisher/targets-step
```

The new step directory contains mode-`0600` files:

- `targets.payload.json`: exact OLPC-canonical JSON bytes to sign;
- `targets.request.json`: payload/root/target digests, authorized key IDs,
  threshold, role version, and expiry;
- `targets.unsigned.json`: the exact unsigned TUF metadata envelope.

Give the payload and request to the external targets-role signer. It returns
one canonical signature envelope:

```json
{"schema":"prufyx.io/external-tuf-signatures/v1","role":"targets","payloadDigest":"sha256:<payload>","signatures":[{"keyid":"<64-lowercase-hex>","sig":"<lowercase-hex-ed25519-signature>"}]}
```

Signature entries are sorted by key ID and contain enough authorized distinct
keys to satisfy the public root's threshold. The signature is over the payload
file's exact bytes. Finalize the role:

```sh
prufyx-maintainer knowledge-publish finalize-role \
  --root /absolute/root.json --root-digest sha256:<root> --role targets \
  --unsigned /absolute/publisher/targets-step/targets.unsigned.json \
  --signatures /absolute/targets-signatures.json \
  --output /absolute/publisher/1.targets.json
```

Role finalization rejects the wrong TUF role type, extra fields, unexpected
targets or metadata entries, and signatures that do not meet the supplied
root's authorization threshold. It validates the exact closed role shape for
this repository. Cross-role byte identities and expiry at the current clock are
checked again before a package can be emitted.

Prepare and externally finalize snapshot next:

```sh
prufyx-maintainer knowledge-publish prepare-snapshot \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --version 1 --expires 2026-11-15T00:00:00Z \
  --output /absolute/publisher/snapshot-step

prufyx-maintainer knowledge-publish finalize-role \
  --root /absolute/root.json --root-digest sha256:<root> --role snapshot \
  --unsigned /absolute/publisher/snapshot-step/snapshot.unsigned.json \
  --signatures /absolute/snapshot-signatures.json \
  --output /absolute/publisher/1.snapshot.json
```

Then prepare and externally finalize timestamp:

```sh
prufyx-maintainer knowledge-publish prepare-timestamp \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --snapshot /absolute/publisher/1.snapshot.json \
  --version 1 --expires 2026-10-01T00:00:00Z \
  --output /absolute/publisher/timestamp-step

prufyx-maintainer knowledge-publish finalize-role \
  --root /absolute/root.json --root-digest sha256:<root> --role timestamp \
  --unsigned /absolute/publisher/timestamp-step/timestamp.unsigned.json \
  --signatures /absolute/timestamp-signatures.json \
  --output /absolute/publisher/timestamp.json
```

Close the package only after every role is finalized:

```sh
prufyx-maintainer knowledge-publish finalize-package \
  --root /absolute/root.json --root-digest sha256:<root> \
  --target /absolute/constraints.v1.json \
  --targets /absolute/publisher/1.targets.json \
  --snapshot /absolute/publisher/1.snapshot.json \
  --timestamp /absolute/publisher/timestamp.json \
  --output /absolute/publisher/cncf-1.tar \
  > /absolute/publisher/finalization-receipt.json
```

Finalization reconstructs the fixed content-addressed repository, packages it
canonically, and invokes the same `knowledge.VerifyConstraints` path used by
`prufyx db verify`. Verification uses the actual UTC clock and must authenticate
the root, role thresholds, metadata chain, target digest, complete external
envelope, revision, capability, and evidence admission before the new package
file is created. The JSON receipt records those exact identities and states
that no network or private key was used.

The output parent and every step parent must already be owned by the current
user with mode `0700`. Outputs are new mode-`0600` files or a new mode-`0700`
step directory; overwrite is rejected. If a create, write, close, or sync step
fails, the publisher leaves the incomplete new file or directory in place for
explicit operator inspection or cleanup and returns a generic failure. Retry
with a different new path. A successful finalization does not publish the
package. Hosting, root bootstrap, key custody, expiry policy, source review,
and release authority remain separate gates.
