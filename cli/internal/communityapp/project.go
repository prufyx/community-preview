package communityapp

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/prufyx/prufyx-cli/internal/projectcheck"
	"github.com/prufyx/prufyx-cli/internal/projectprepare"
)

var projectDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type projectArguments struct {
	project, config, schemaConfig, workload, osdMetadata, selectedOSDID, from, to, configPin, schemaConfigPin, workloadPin, osdMetadataPin, now, format string
	complete, precedenceResolved, useReviewedTargetDefault, workloadComplete, osdMetadataComplete, currentDefaultWasUsed, preserveHTTP2Enabled          bool
}

func parseProjectArguments(args []string, check bool) (projectArguments, bool) {
	fs := flag.NewFlagSet("community project", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var result projectArguments
	fs.StringVar(&result.project, "project", "", "reviewed project slug")
	fs.StringVar(&result.config, "effective-config", "", "native effective configuration")
	fs.StringVar(&result.schemaConfig, "loki-schema-config", "", "native Loki schema configuration")
	fs.StringVar(&result.workload, "workload", "", "native Kubernetes workload JSON")
	fs.StringVar(&result.osdMetadata, "selected-osd-metadata", "", "caller-selected current OSD metadata JSON object")
	fs.StringVar(&result.selectedOSDID, "selected-osd-id", "", "explicit selected current OSD id")
	fs.StringVar(&result.from, "from", "", "current version")
	fs.StringVar(&result.to, "to", "", "target version")
	fs.StringVar(&result.configPin, "effective-config-digest", "", "optional exact configuration SHA-256")
	fs.StringVar(&result.schemaConfigPin, "loki-schema-config-digest", "", "optional exact Loki schema configuration SHA-256")
	fs.StringVar(&result.workloadPin, "workload-digest", "", "optional exact workload SHA-256")
	fs.StringVar(&result.osdMetadataPin, "selected-osd-metadata-digest", "", "optional exact selected metadata SHA-256")
	fs.StringVar(&result.now, "now", "", "explicit UTC evaluation time")
	fs.StringVar(&result.format, "format", "human", "human, json, or input")
	fs.BoolVar(&result.complete, "effective-config-complete", false, "declare complete effective configuration")
	fs.BoolVar(&result.precedenceResolved, "precedence-resolved", false, "declare environment and CLI precedence resolved")
	fs.BoolVar(&result.useReviewedTargetDefault, "use-reviewed-target-default", false, "explicitly use the reviewed target default for an omitted Loki setting")
	fs.BoolVar(&result.currentDefaultWasUsed, "current-default-was-used", false, "declare that the reviewed current default was used")
	fs.BoolVar(&result.preserveHTTP2Enabled, "preserve-http2-enabled", false, "declare intent to preserve an enabled HTTP/2 setting")
	fs.BoolVar(&result.workloadComplete, "workload-complete", false, "declare complete selected workload argv")
	fs.BoolVar(&result.osdMetadataComplete, "selected-osd-metadata-complete", false, "declare complete selected current OSD metadata object")
	if duplicateFlags(args) || fs.Parse(args) != nil {
		return projectArguments{}, false
	}
	modes := 0
	for _, path := range []string{result.config, result.schemaConfig, result.workload, result.osdMetadata} {
		if path != "" {
			modes++
		}
	}
	if fs.NArg() != 0 || result.project == "" || result.from == "" || result.to == "" || modes != 1 || (flagProvided(args, "effective-config-digest") && !projectDigestRE.MatchString(result.configPin)) || (flagProvided(args, "loki-schema-config-digest") && !projectDigestRE.MatchString(result.schemaConfigPin)) || (flagProvided(args, "workload-digest") && !projectDigestRE.MatchString(result.workloadPin)) || (flagProvided(args, "selected-osd-metadata-digest") && !projectDigestRE.MatchString(result.osdMetadataPin)) {
		return projectArguments{}, false
	}
	if result.schemaConfig != "" {
		if result.project != projectprepare.LokiProject || anyFlagProvided(args, "effective-config", "effective-config-digest", "workload", "workload-digest", "workload-complete", "selected-osd-metadata", "selected-osd-metadata-digest", "selected-osd-id", "selected-osd-metadata-complete", "current-default-was-used", "preserve-http2-enabled") {
			return projectArguments{}, false
		}
	} else if result.config != "" {
		if result.project == projectprepare.ArgoWorkflowsProject || result.project == projectprepare.CephProject || anyFlagProvided(args, "loki-schema-config", "loki-schema-config-digest", "use-reviewed-target-default", "workload", "workload-digest", "workload-complete", "selected-osd-metadata", "selected-osd-metadata-digest", "selected-osd-id", "selected-osd-metadata-complete") {
			return projectArguments{}, false
		}
	} else if result.workload != "" {
		if result.project != projectprepare.ArgoWorkflowsProject || anyFlagProvided(args, "effective-config", "effective-config-digest", "effective-config-complete", "precedence-resolved", "loki-schema-config", "loki-schema-config-digest", "use-reviewed-target-default", "selected-osd-metadata", "selected-osd-metadata-digest", "selected-osd-id", "selected-osd-metadata-complete") {
			return projectArguments{}, false
		}
	} else {
		if result.project != projectprepare.CephProject || result.selectedOSDID == "" || anyFlagProvided(args, "effective-config", "effective-config-digest", "effective-config-complete", "precedence-resolved", "loki-schema-config", "loki-schema-config-digest", "use-reviewed-target-default", "workload", "workload-digest", "workload-complete") {
			return projectArguments{}, false
		}
	}
	if result.project != projectprepare.FluentBitProject && result.schemaConfig == "" && anyFlagProvided(args, "current-default-was-used", "preserve-http2-enabled") {
		return projectArguments{}, false
	}
	if result.schemaConfig == "" && anyFlagProvided(args, "use-reviewed-target-default") {
		return projectArguments{}, false
	}
	if check {
		if result.now == "" || (result.format != "human" && result.format != "json") {
			return projectArguments{}, false
		}
	} else if result.now != "" || (result.format != "human" && result.format != "json" && result.format != "input") {
		return projectArguments{}, false
	}
	return result, true
}

func (r runtime) prepareProject(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx prepare project --project grafana|kibana|loki --effective-config FILE --from VERSION --to VERSION --effective-config-complete --precedence-resolved [--effective-config-digest SHA256] [--format human|json|input]")
		fmt.Fprintln(r.stdout, "   or: prufyx prepare project --project loki --loki-schema-config FILE --from 2.9.8 --to 3.0.0 --effective-config-complete --precedence-resolved [--use-reviewed-target-default] [--loki-schema-config-digest SHA256] [--format human|json|input]")
		fmt.Fprintln(r.stdout, "   or: prufyx prepare project --project fluent-bit --effective-config FILE --from 3.2.0 --to 4.0.0 --effective-config-complete --current-default-was-used --preserve-http2-enabled [--effective-config-digest SHA256] [--format human|json|input]")
		fmt.Fprintln(r.stdout, "   or: prufyx prepare project --project argo-workflows --workload FILE --from 3.5.0 --to 3.6.0 --workload-complete [--workload-digest SHA256] [--format human|json|input]")
		fmt.Fprintln(r.stdout, "   or: prufyx prepare project --project ceph --selected-osd-metadata FILE --selected-osd-id ID --from 17.2.7 --to 18.2.0 --selected-osd-metadata-complete [--selected-osd-metadata-digest SHA256] [--format human|json|input]")
		return ExitOK
	}
	request, ok := parseProjectArguments(args, false)
	if !ok {
		return r.usage("invalid prepare project arguments; use --help")
	}
	prepared, exit := r.prepareProjectInput(request)
	if exit != ExitOK && exit != ExitUnknown {
		return exit
	}
	switch request.format {
	case "input":
		_, _ = r.stdout.Write(prepared.CanonicalInputJSON)
	case "json":
		authority := "CALLER_SUPPLIED_NATIVE_EFFECTIVE_CONFIG"
		if request.schemaConfig != "" {
			authority = "CALLER_SUPPLIED_NATIVE_LOKI_SCHEMA_CONFIG"
		}
		if request.workload != "" {
			authority = "CALLER_SUPPLIED_NATIVE_KUBERNETES_WORKLOAD"
		} else if request.osdMetadata != "" {
			authority = "CALLER_SUPPLIED_SELECTED_CURRENT_OSD_METADATA"
		}
		_ = json.NewEncoder(r.stdout).Encode(map[string]any{
			"schema": "prufyx.io/community-project-preparation/v1alpha1", "project": request.project,
			"state": prepared.State, "reasonCode": prepared.Reason, "sourceDigest": prepared.SourceDigest,
			"inputDigest": prepared.InputDigest, "authority": authority,
			"knowledgeOrigin": "embedded_only", "omissions": prepared.Omissions,
		})
	default:
		inputRole := "effective-config"
		if request.schemaConfig != "" {
			inputRole = "Loki schema configuration"
		}
		if request.workload != "" {
			inputRole = "Kubernetes workload"
		} else if request.osdMetadata != "" {
			inputRole = "selected current OSD metadata"
		}
		fmt.Fprintf(r.stdout, "%s native %s preparation\nstate: %s\nreason: %s\nsource digest: %s\ncanonical input digest: %s\nknowledge: embedded only; external updates unavailable\nwhole-upgrade assessment: UNKNOWN\n", request.project, inputRole, prepared.State, prepared.Reason, prepared.SourceDigest, prepared.InputDigest)
		for _, omission := range prepared.Omissions {
			if omission == "OMITTED_ALLOW_USES_SOURCE_DERIVED_TARGET_DEFAULT_AUTHORIZED_BY_EXPLICIT_FLAG" {
				fmt.Fprintln(r.stdout, "input qualification: omitted allow_structured_metadata used the reviewed target default under an explicit opt-in; this is source-derived, not observed")
			}
		}
	}
	return exit
}

func (r runtime) project(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx check project --project grafana|kibana|loki --effective-config FILE --from VERSION --to VERSION --effective-config-complete --precedence-resolved --now RFC3339 [--effective-config-digest SHA256] [--format human|json]")
		fmt.Fprintln(r.stdout, "   or: prufyx check project --project loki --loki-schema-config FILE --from 2.9.8 --to 3.0.0 --effective-config-complete --precedence-resolved --now RFC3339 [--use-reviewed-target-default] [--loki-schema-config-digest SHA256] [--format human|json]")
		fmt.Fprintln(r.stdout, "   or: prufyx check project --project fluent-bit --effective-config FILE --from 3.2.0 --to 4.0.0 --effective-config-complete --current-default-was-used --preserve-http2-enabled --now RFC3339 [--effective-config-digest SHA256] [--format human|json]")
		fmt.Fprintln(r.stdout, "   or: prufyx check project --project argo-workflows --workload FILE --from 3.5.0 --to 3.6.0 --workload-complete --now RFC3339 [--workload-digest SHA256] [--format human|json]")
		fmt.Fprintln(r.stdout, "   or: prufyx check project --project ceph --selected-osd-metadata FILE --selected-osd-id ID --from 17.2.7 --to 18.2.0 --selected-osd-metadata-complete --now RFC3339 [--selected-osd-metadata-digest SHA256] [--format human|json]")
		fmt.Fprintln(r.stdout, "This preview is embedded-only. --knowledge-db, --profile, and replay flags are not supported for community projects.")
		return ExitOK
	}
	request, ok := parseProjectArguments(args, true)
	if !ok {
		return r.usage("invalid check project arguments; embedded-only route; use --help")
	}
	now, err := parseUTC(request.now)
	if err != nil || now.Nanosecond() != 0 {
		return r.usage("invalid check project UTC time; use --help")
	}
	prepared, exit := r.prepareProjectInput(request)
	if exit != ExitOK && exit != ExitUnknown {
		return exit
	}
	ruleID := ""
	if request.schemaConfig != "" {
		ruleID = projectprepare.LokiStructuredMetadataRuleID
	} else if request.config != "" && request.project == projectprepare.LokiProject {
		ruleID = projectprepare.LokiCompactorRuleID
	}
	var report projectcheck.Report
	if ruleID != "" {
		report, err = projectcheck.CheckRule(request.project, prepared.CanonicalInputJSON, now, ruleID)
	} else {
		report, err = projectcheck.Check(request.project, prepared.CanonicalInputJSON, now)
	}
	if err != nil {
		if err == projectcheck.ErrIntegrity {
			return r.fail("community project check integrity failure", ExitIntegrity)
		}
		return r.fail("community project check input failed admission", ExitUsage)
	}
	encoded, err := projectcheck.MarshalReport(report)
	if err != nil {
		return r.fail("community project report integrity failure", ExitIntegrity)
	}
	if request.format == "json" {
		fmt.Fprintln(r.stdout, string(encoded))
	} else {
		fmt.Fprintf(r.stdout, "%s community-project source preview\naggregate: UNKNOWN\nknowledge: embedded only; external updates unavailable\n", request.project)
		if request.osdMetadata != "" {
			fmt.Fprintln(r.stdout, "input qualification: caller-selected current OSD metadata; not a target deployment or cluster inventory observation")
		}
		if slices.Contains(prepared.Omissions, "COMMAND_DEFAULT_DERIVED_FROM_REVIEWED_IMAGE_ENTRYPOINT_SOURCE") {
			fmt.Fprintln(r.stdout, "input qualification: omitted command resolved from the reviewed exact-image ENTRYPOINT source; not observed at runtime")
		}
		for _, omission := range prepared.Omissions {
			if omission == "OMITTED_ALLOW_USES_SOURCE_DERIVED_TARGET_DEFAULT_AUTHORIZED_BY_EXPLICIT_FLAG" {
				fmt.Fprintln(r.stdout, "input qualification: omitted allow_structured_metadata used the reviewed target default under an explicit opt-in; this is source-derived, not observed")
			}
		}
		for _, claim := range report.Check.Claims {
			fmt.Fprintf(r.stdout, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction)
			for _, source := range claim.Sources {
				fmt.Fprintf(r.stdout, "pinned source: %s lines %d-%d; revision %s; digest %s\n", source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest)
			}
		}
		if len(report.Check.Claims) == 0 {
			fmt.Fprintf(r.stdout, "next action: %s\n", report.NextAction)
		}
		fmt.Fprintf(r.stdout, "source digest: %s\ncanonical input digest: %s\nnetwork used: false\nwhole-upgrade assessment: UNKNOWN\n", prepared.SourceDigest, prepared.InputDigest)
	}
	return projectcheck.ClaimExit(report)
}

func (r runtime) prepareProjectInput(request projectArguments) (projectprepare.Prepared, int) {
	path, pin := request.config, request.configPin
	if request.schemaConfig != "" {
		path, pin = request.schemaConfig, request.schemaConfigPin
	} else if request.workload != "" {
		path, pin = request.workload, request.workloadPin
	} else if request.osdMetadata != "" {
		path, pin = request.osdMetadata, request.osdMetadataPin
	}
	raw, err := readCNCFPrivate(path, 1<<20)
	if err != nil {
		return projectprepare.Prepared{}, r.fail("community project input failed private-file admission", ExitUsage)
	}
	var prepared projectprepare.Prepared
	if request.schemaConfig != "" {
		prepared, err = projectprepare.PrepareLokiStructuredMetadata(raw, request.from, request.to, request.complete, request.precedenceResolved, request.useReviewedTargetDefault)
	} else if request.workload != "" {
		prepared, err = projectprepare.PrepareWorkload(request.project, raw, request.from, request.to, request.workloadComplete)
	} else if request.osdMetadata != "" {
		prepared, err = projectprepare.PrepareSelectedOSDMetadata(request.project, raw, request.selectedOSDID, request.from, request.to, request.osdMetadataComplete)
	} else {
		if request.project == projectprepare.FluentBitProject {
			prepared, err = projectprepare.PrepareFluentBit(raw, request.from, request.to, request.complete, request.currentDefaultWasUsed, request.preserveHTTP2Enabled)
		} else {
			prepared, err = projectprepare.PrepareEffectiveConfig(request.project, raw, request.from, request.to, request.complete, request.precedenceResolved)
		}
	}
	if err != nil {
		return projectprepare.Prepared{}, r.fail("community project native input unsupported or invalid", ExitUsage)
	}
	if pin != "" && pin != prepared.SourceDigest {
		return projectprepare.Prepared{}, r.fail("community project input digest mismatch", ExitIntegrity)
	}
	if !json.Valid(prepared.CanonicalInputJSON) || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) {
		return projectprepare.Prepared{}, r.fail("community project preparation integrity failure", ExitIntegrity)
	}
	if prepared.State == "UNKNOWN" {
		return prepared, ExitUnknown
	}
	return prepared, ExitOK
}
