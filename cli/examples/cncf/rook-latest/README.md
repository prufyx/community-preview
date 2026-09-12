# Rook 1.20.7 exact-source examples

This offline walkthrough checks only the source-stated Kubernetes minimum for
the exact Rook `1.15.9`, `1.16.9`, `1.17.9`, `1.18.11`, and `1.19.11`
origins proposed directly to `1.20.7`. For every origin it checks Kubernetes
`1.30.9` as scoped `BLOCKED`, `1.31.0` as scoped `PASS`, and a missing
proposed Kubernetes component as `UNKNOWN`. The aggregate whole-upgrade
assessment remains `UNKNOWN` in every report. The checked-in fixtures show the
same three states for the adjacent `1.19.11` origin.

Run the Go-owned walkthrough with an already-built Community executable:

```sh
/absolute/path/to/prufyx-community community-preview example cncf-rook-latest
```

The `run.sh` file is a thin compatibility shim for that native command. The Go
walkthrough creates private `0600` temporary inputs, binds each exact digest,
uses the pinned review clock, removes its temporary tree, and uses no network
or cluster access. The checked-in JSON files show the corresponding synthetic
blocked, fixed, and unknown declarations.

These target-only constraints do not assert that a direct route from any listed
origin is supported and do not require an intermediate Rook version. The source
audit found no explicit universal Rook minor-skip prohibition in the retained
immutable upgrade guides or target source. Versions outside these five exact
current endpoints remain `UNKNOWN`.

These examples do not inspect Ceph state or health, CSI migration, CRDs, Helm
ordering, startup, rollout, rollback, or runtime behavior. A scoped `PASS`
establishes only the cited numerical Kubernetes minimum.
