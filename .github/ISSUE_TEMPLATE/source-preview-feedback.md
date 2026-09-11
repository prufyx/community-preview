---
name: Development source-preview feedback
about: Report a focused technical-review observation from the development/source preview
labels: source-preview, feedback
---

## Five-minute path

- [ ] I used Go 1.26.8 with `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`,
  and `GOFLAGS='-mod=vendor -buildvcs=false'`.
- [ ] I ran the cert-manager example from the README and observed the scoped
  `BLOCKED` result before rechecking after the documented setting removal.
- [ ] I understand that the example does not prove a full Helm schema, deployed
  chart, runtime, or whole-upgrade result.

## What helped or blocked review?

Describe only the build, report, source-link, or bounded correction experience.
Which exact configuration-aware, non-sensitive input would be most useful next?
Which result should remain `UNKNOWN` without more evidence?

## Data boundary

Do **not** include credentials, Secrets, customer configuration, Kubernetes
objects, private paths, logs, production snapshots, or proprietary source.
Use a synthetic minimal example instead.

## Contribution boundary

This feedback does not approve a compatibility rule or authorize publication.
Proposed source changes follow [CONTRIBUTING.md](https://github.com/prufyx/community-preview/blob/main/CONTRIBUTING.md) in the proposed
preview repository; the offline bundle includes `CONTRIBUTING.md` at its root.
Contributions are Apache-2.0 and require DCO sign-off.
