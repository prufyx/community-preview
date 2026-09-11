# Prufyx Community CLI

Build the Community binary from this module with Go 1.26.8:

```sh
GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o ../prufyx ./cmd/prufyx-community
../prufyx --help
```

The Community entrypoint exposes focused cert-manager values and Prometheus mode
checks, plus an unreleased [CNCF source-constraint preview](docs/CNCF-SOURCE-PREVIEW.md)
over minimized operator declarations. Optional `prepare cncf` derives only its
documented exact-pair facts from one private local JSON input. The
[generated support inventory](docs/generated/community-support-inventory.md)
is the complete current list of preparer-capable projects and their limits. It
retains no raw workload data and performs no live observation or upgrade check.
The exact external Go module closure is included under `vendor/` and
bound by the Community v2 source policy, so builds do not fetch modules. It has
no hosted account requirement or model invocation. See the [quickstart](../README.md),
[command guide](docs/community-checks.md),
[cert-manager knowledge database](docs/knowledge-database.md),
[CNCF knowledge database](docs/cncf-knowledge-database.md),
[Buildpacks Lifecycle Platform API plan walkthrough](examples/cncf/README.md#review-a-buildpacks-lifecycle-platform-api-plan),
[in-toto-run key argument walkthrough](examples/cncf/README.md#review-an-in-toto-run-key-argument-plan),
[TUF Updater source-call walkthrough](examples/cncf/README.md#review-a-tuf-updater-source-call),
[KFP Python SDK component-authoring walkthrough](examples/cncf/README.md#review-a-kfp-python-sdk-component-authoring-change),
[CubeFS MetaNode planned-upgrade walkthrough](examples/cncf/README.md#review-a-cubefs-metanode-planned-upgrade-guard),
[CRI-O ArtifactStore named-reference walkthrough](examples/cncf/README.md#review-a-cri-o-artifactstore-named-reference-plan),
[SPIFFE X.509-SVID public-leaf URI-SAN subset](docs/spiffe-x509-svid.md),
[CloudEvents structured JSON core-envelope subset](docs/cloudevents-structured-json.md),
[TiKV 8.5.8 GCS WIF full-backup planned-operation preflight](docs/tikv-gcp-v2-wif-backup.md),
[Distribution and CNI native format preflights](docs/native-format-preflights.md),
[community-project native configuration and workload checks](docs/community-project-checks.md),
[product contract](docs/product-contract.md) and
[data handling](docs/data-handling.md).

Run all tests in this staged Community module with `go test -mod=vendor ./...`, and
run `go vet -mod=vendor ./...`. Native release and collector checks are specified by the
[source gate](release/COMMUNITY-SOURCE-GATE.md).
