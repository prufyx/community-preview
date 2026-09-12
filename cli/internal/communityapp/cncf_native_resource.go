package communityapp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prufyx/prufyx-cli/internal/cncfcheck"
	"github.com/prufyx/prufyx-cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx-cli/internal/cncfprepare"
	"github.com/prufyx/prufyx-cli/internal/knowledge"
)

// cncfNativeResourceCheck makes the native-resource adapters useful without
// making an operator save a canonical Prufyx envelope. The supplied resources
// remain private source data; only their minimized canonical observation is
// evaluated or persisted in a report.
func (r runtime) cncfNativeResourceCheck(project, nativePath, nativePin, currentPath, currentPin, proposedPath, proposedPin, selectedJob string, complete, precedenceResolved bool, from, to, nowText, storeRoot, revision, bundle, receipt, replayPath, format string, resourceScopeComplete bool, args []string) int {
	allowed := []string{"native-resource", "native-resource-digest"}
	if project == "cloudnativepg" {
		allowed = []string{"current-resource", "current-resource-digest", "resource", "resource-digest"}
	} else if project == "nats" {
		allowed = []string{"nats-config", "nats-config-digest"}
	} else if project == "flux" {
		allowed = []string{"native-resource", "native-resource-digest", "resource-scope-complete"}
	} else if project == "prometheus" {
		allowed = []string{"scrape-config", "scrape-config-digest", "scrape-job", "scrape-config-complete", "scrape-config-precedence-resolved"}
	}
	if from == "" || to == "" || cncfUnexpectedModeFlag(args, allowed...) {
		return r.usage("invalid native CNCF resource check arguments; use --help")
	}
	var prepared cncfprepare.Prepared
	var rawDigests []string
	var expectedSourceDigest string
	var err error
	switch project {
	case "metallb", "contour", "kubevirt", "thanos", "cortex", "nats", "flux", "prometheus":
		if nativePath == "" || anyFlagProvided(args, "current-resource", "current-resource-digest", "resource", "resource-digest") {
			return r.usage("invalid native CNCF resource check arguments; use --help")
		}
		if project == "prometheus" && selectedJob == "" {
			return r.usage("invalid Prometheus selected scrape configuration arguments; use --help")
		}
		raw, readErr := readCNCFPrivate(nativePath, 1<<20)
		if readErr != nil {
			return r.fail("NATIVE_CNCF_RESOURCE_INPUT_INVALID", ExitUsage)
		}
		digest := digestCommunityBytes(raw)
		if nativePin != "" && nativePin != digest {
			return r.fail("NATIVE_CNCF_RESOURCE_INTEGRITY_FAILURE", ExitIntegrity)
		}
		if project == "kubevirt" {
			prepared, err = cncfprepare.PrepareKubeVirt(raw, from, to)
		} else if project == "thanos" {
			prepared, err = cncfprepare.PrepareThanos(raw, from, to)
		} else if project == "cortex" {
			prepared, err = cncfprepare.PrepareCortex(raw, from, to)
		} else if project == "nats" {
			prepared, err = cncfprepare.PrepareNATS(raw, from, to)
		} else if project == "flux" {
			prepared, err = cncfprepare.PrepareFlux(raw, from, to, resourceScopeComplete)
		} else if project == "prometheus" {
			prepared, err = cncfprepare.PreparePrometheusScrapeConfig(raw, selectedJob, from, to, complete, precedenceResolved)
		} else {
			prepared, err = cncfprepare.PrepareNativeMigration(raw, project, from, to)
		}
		rawDigests = []string{digest}
		expectedSourceDigest = digest
	case "cloudnativepg":
		if anyFlagProvided(args, "native-resource", "native-resource-digest") || nativePath != "" || currentPath == "" || proposedPath == "" {
			return r.usage("invalid CloudNativePG resource check arguments; use --help")
		}
		current, currentErr := readCNCFPrivate(currentPath, 1<<20)
		proposed, proposedErr := readCNCFPrivate(proposedPath, 1<<20)
		if currentErr != nil || proposedErr != nil {
			return r.fail("CLOUDNATIVEPG_RESOURCE_INPUT_INVALID", ExitUsage)
		}
		currentDigest, proposedDigest := digestCommunityBytes(current), digestCommunityBytes(proposed)
		if (currentPin != "" && currentPin != currentDigest) || (proposedPin != "" && proposedPin != proposedDigest) {
			return r.fail("CLOUDNATIVEPG_RESOURCE_INTEGRITY_FAILURE", ExitIntegrity)
		}
		envelope, marshalErr := json.Marshal(struct {
			Current  json.RawMessage `json:"current"`
			Proposed json.RawMessage `json:"proposed"`
		}{Current: current, Proposed: proposed})
		if marshalErr != nil {
			return r.fail("CLOUDNATIVEPG_RESOURCE_INPUT_INVALID", ExitUsage)
		}
		prepared, err = cncfprepare.PrepareCloudNativePG(envelope, from, to)
		rawDigests = []string{currentDigest, proposedDigest}
		expectedSourceDigest = digestCommunityBytes(envelope)
	default:
		return r.usage("invalid native CNCF project; use --help")
	}
	if err != nil || prepared.SourceDigest != expectedSourceDigest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("NATIVE_CNCF_RESOURCE_INPUT_INVALID", ExitUsage)
	}
	if _, err := cncfcheck.Catalog(false, project); err != nil {
		return r.cncfError("CNCF project selection failed", err)
	}
	if storeRoot != "" {
		if nowText != "" || (replayPath != "" && (revision == "" || bundle == "" || receipt == "" || (project != "cloudnativepg" && nativePin == "") || (project == "cloudnativepg" && (currentPin == "" || proposedPin == "")))) {
			return r.usage("external native CNCF replay requires every raw resource digest and all knowledge pins")
		}
		return r.externalCNCF(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: storeRoot, ExpectedRevision: revision, ExpectedBundleDigest: bundle, ExpectedTrustReceiptDigest: receipt}, Project: project, Input: prepared.CanonicalInputJSON, InputDigest: prepared.InputDigest}, replayPath, format)
	}
	if revision != "" || bundle != "" || receipt != "" || nowText == "" || replayPath != "" {
		return r.usage("native CNCF resource checks require canonical --now or an explicit signed knowledge selection")
	}
	now, err := parseUTC(nowText)
	if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != nowText {
		return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
	}
	report, err := cncfcheck.Check(project, prepared.CanonicalInputJSON, now)
	if err != nil {
		return r.cncfError("CNCF source-constraint check failed", err)
	}
	encoded, err := cncfcheck.MarshalReport(report)
	if err != nil {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	if format == "json" {
		if _, err := fmt.Fprintln(r.stdout, string(encoded)); err != nil {
			return ExitIntegrity
		}
	} else {
		if _, err := fmt.Fprintf(r.stdout, "%s native input review\nraw input digests: %s\nprepared input digest: %s\naggregate: UNKNOWN\nnetwork used: false\nwhole-upgrade compatibility: UNKNOWN\n", project, joinNativeDigests(rawDigests), prepared.InputDigest); err != nil {
			return ExitIntegrity
		}
		for _, claim := range report.Check.Claims {
			if _, err := fmt.Fprintf(r.stdout, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction); err != nil {
				return ExitIntegrity
			}
			for _, source := range claim.Sources {
				if _, err := fmt.Fprintf(r.stdout, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest); err != nil {
					return ExitIntegrity
				}
			}
		}
	}
	return cncfcheck.ClaimExit(report)
}

func joinNativeDigests(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return values[0] + "," + values[1]
}
