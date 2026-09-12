# Cloud Custodian IAM access-key filter preflight

For the reviewed Cloud Custodian 0.9.50 to 0.9.51 transition, the `json-diff`
filter is removed from the `iam-access-key` resource. This local check reads one
private JSON policy, projects only the selected filter fact, and never runs
Cloud Custodian or contacts AWS.

From the `cli` directory, build or use the local `prufyx` binary and prepare the
examples:

```sh
prufyx prepare cncf --project cloud-custodian \
  --input examples/cncf/cloud-custodian-json-diff/blocked-policy.json \
  --from 0.9.50 --to 0.9.51 --format input > /tmp/cloud-custodian-prepared.json
prufyx check cncf --project cloud-custodian \
  --input /tmp/cloud-custodian-prepared.json \
  --now 2026-09-11T22:38:05Z --format human
```

The blocked example returns exit 10. The fixed example has an explicitly empty
filter list and returns a scoped PASS (exit 0) for absence of this one removed
filter in this one complete selected policy. Missing filters, variables,
includes, dynamic selection, nested or unsupported filters, malformed JSON, and
other resources remain UNKNOWN or are rejected as invalid input. Policy names,
paths, values, and arbitrary filters are not retained in the minimized input or
report. This does not assess AWS Config, policy execution, runtime behavior, or
whole-upgrade safety.
