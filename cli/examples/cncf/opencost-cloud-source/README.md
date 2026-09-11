# OpenCost cloud-cost source selection

These inputs are operator declarations for the exact OpenCost `1.119.0` to
`1.120.0` source-selection check. They are not native OpenCost configuration
files. Build `prufyx` as described in the repository README, then run from the
repository root:

```sh
umask 077
cp cli/examples/cncf/opencost-cloud-source/provider-only-broken.json ./opencost-source.json
chmod 600 ./opencost-source.json
./prufyx prepare cncf --project opencost --input ./opencost-source.json \
  --from 1.119.0 --to 1.120.0 --format input >./opencost-facts.json
chmod 600 ./opencost-facts.json
./prufyx check cncf --project opencost --input ./opencost-facts.json \
  --input-digest "sha256:$(shasum -a 256 ./opencost-facts.json | awk '{print $1}')" \
  --now 2026-09-11T22:00:00Z --format human
```

The broken input declares continued provider-derived configuration for enabled
cloud-cost collection. The fixed input declares a selected cloud-integration
file present. That declaration can pass only the reviewed source-kind
predicate: the command does not open that file, inspect its schema or
credentials, validate a mount, contact a provider, or establish startup or
runtime behavior. The unresolved input remains `UNKNOWN`.
