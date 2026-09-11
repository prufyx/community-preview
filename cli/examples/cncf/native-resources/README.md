# Native CNCF resource checks

These are small JSON-only examples for the reviewed predicate in each exact
transition. They do not connect to a cluster, apply a resource, infer defaults,
or establish runtime or whole-upgrade compatibility. Each `broken` input is a
scoped blocker, each `fixed` input clears that predicate only, and each
`unknown` input remains unresolved.

From `cli/`, build the local command once with the accepted offline vendor set:

```sh
go build -mod=vendor -buildvcs=false -o ./prufyx-community ./cmd/prufyx-community
```

Run the MetalLB example directly from its native resource:

```sh
umask 077
work=$(mktemp -d)
chmod 700 "$work"
cp examples/cncf/native-resources/metallb/broken.json "$work/resource.json"
chmod 600 "$work/resource.json"
./prufyx-community check cncf --project metallb \
  --native-resource "$work/resource.json" \
  --from 0.12.1 --to 0.13.2 --now 2026-09-11T18:00:00Z --format human
```

Use the same command with `fixed.json` or `unknown.json`. Contour and KubeVirt
also take one `--native-resource`; use their exact pairs `1.19.0 -> 1.20.0` and
`1.8.4 -> 1.9.0` respectively. A raw `--native-resource-digest sha256:...`
option can bind the exact supplied bytes.

CloudNativePG needs a selected current and proposed resource, not a custom
Prufyx envelope:

```sh
cp examples/cncf/native-resources/cloudnativepg/current-broken.json "$work/current.json"
cp examples/cncf/native-resources/cloudnativepg/proposed-broken.json "$work/proposed.json"
chmod 600 "$work/current.json" "$work/proposed.json"
./prufyx-community check cncf --project cloudnativepg \
  --current-resource "$work/current.json" --resource "$work/proposed.json" \
  --from 1.29.0 --to 1.30.0 --now 2026-09-11T18:00:00Z --format human
```

For CloudNativePG, bind both raw files separately when identity matters. The
check compares only same-object identity and `spec.cluster.name`. With an
external signed knowledge store, that store is authoritative and has no
embedded fallback; historical replay requires every raw digest and all selected
knowledge pins.
