# Synthetic offline etcd example

This walkthrough demonstrates the bounded etcd `3.5.17` to `3.6.0` source
constraint using a private, synthetic `EtcdEffectiveArguments` declaration. It
uses only a complete, direct effective argument vector. It does not read a
Deployment, wrapper, environment variable, config file, response file, live
etcd process, cluster, or customer configuration.

Run it with an already-built Community executable from this source checkout:

```sh
prufyx community-preview example cncf-etcd
```

The Go command creates all temporary input and output files with mode `0600`,
uses no network, and removes its temporary directory. The retained `run.sh`
entrypoint is a compatibility shim for an already-built Community executable. The input contains the known atom `--enable-v2=false`. The value
`false` does not mean that the removed option is absent: the atom itself is
present in the complete effective argv, so preparation emits
`component.etcd.removed_v2_proxy_flags_present=true`. The subsequent check
returns the scoped `BLOCKED` result with exit `10`; the aggregate assessment
remains `UNKNOWN`.

The parser accepts only self-contained `--name=value` atoms for this slice. It
does not resolve wrappers, environment or config sources, or execute etcd. The
second input deliberately separates `--initial-cluster` from
`--enable-v2=true`; that incomplete and ambiguous vector returns preparation
exit `11`, emits the existing `missing` fact, and checks as `UNKNOWN` with exit
`11`. A complete vector without a removed option also cannot prove absence and
remains `UNKNOWN`.

The declaration is synthetic operator input, not a live observation. The
source-backed rule does not prove API admission, startup, traffic, runtime
behavior, quorum or whole-upgrade safety. Review the generated canonical input
and report before using them.
