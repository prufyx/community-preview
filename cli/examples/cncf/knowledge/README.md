# Synthetic offline CNCF knowledge example

This walkthrough demonstrates a local, disconnected `cncf` knowledge profile. It generates two public synthetic TUF packages with ephemeral signing keys, verifies revision 1 without a store, imports both revisions into a separate temporary store, and runs the same candidate binary against both revisions.

Run it from this source checkout with the actual executable path:

```sh
./examples/cncf/knowledge/run.sh /absolute/path/to/prufyx-community
```

The runner requires Bash, Go 1.26.8, vendored dependencies, `jq` 1.7 or later, `awk`, `mktemp`, and either `sha256sum` or `shasum`. Its generator command is explicitly offline:

```sh
go run ./examples/community/knowledge/generate-synthetic-packages.go \
  --profile cncf --output NEW_PRIVATE_TEMP_DIRECTORY
```

The input is a private `0600` minimized Kyverno declaration for the exact `1.12.5` to `1.13.0` transition. This synthetic scenario explicitly declares the official-upstream `reports_controller` surface and `component.kyverno.reports_chunk_size_flag_present=true`; these are fixture facts, not inferred facts for arbitrary Kyverno users. Revision 1 is an empty external pack and therefore returns `UNKNOWN` with exit `11`. Revision 2 contains the synthetic Kyverno rule and returns `BLOCKED` with exit `10`. Missing or unsupported applicability facts remain `UNKNOWN`.

The runner then replays the exact revision 1 JSON report after revision 2 is selected. Replay supplies the original input digest, revision, bundle digest, trust receipt digest, and report path; it must return a historical `MATCH` with exit `11`. Current external checks omit `--now` and use the verifier clock.

The package-only verification uses the generated synthetic root and manifest
digest as an explicitly test-only trust input. Production use must obtain the
root identity independently. The verification receipt states that no store was
used, rollback against a store was not checked, and import eligibility was not
evaluated; the subsequent import performs its own verification.

The JSON checks assert `synthetic_test_only`, `external_declared`, `DECLARED_RULE_SOURCE_REFERENCES`, and an `UNKNOWN` aggregate. The fixture’s source references are borrowed from the packaged test data, while its evidence dates are generated fixture data. This example records no new maintainer review, official Prufyx signing root, production feed, runtime compatibility proof, or whole-upgrade result.

All generated work is confined to an owned `mktemp` directory and removed on success or failure. The signing keys are process-local and never persisted. The command reads no cluster or customer data, makes no network calls, leaves no database behind, and checks that the candidate binary digest is unchanged. The canary input filename is also checked to ensure private names and values do not cross retained report or status output.
