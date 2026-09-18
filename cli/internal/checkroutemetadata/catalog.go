// Package checkroutemetadata exposes compiled rule identities and a small,
// declarative index of native public routes. It never reads caller files or
// evaluates rules.
package checkroutemetadata

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx-cli/internal/cncfcheck"
	"github.com/prufyx/prufyx-cli/internal/projectcheck"
)

const Schema = "prufyx.io/check-route-catalog/v1alpha1"

const (
	FamilyCNCF      = "cncf_embedded_source_rule"
	FamilyCommunity = "community_project_embedded_source_rule"
	RouteExposed    = "EXPOSED_CANONICAL_INPUT"
	RouteNotExposed = "NOT_EXPOSED_BY_PUBLIC_CLI"
	DescriptorExact = "EXACT_PAIR_NATIVE_ROUTE"
	DescriptorNone  = "NO_NATIVE_DESCRIPTOR"
)

var ErrIntegrity = errors.New("check-route metadata integrity failure")

type Scope struct {
	IncludedFamilies        []string `json:"includedFamilies"`
	ExcludedFamilies        []string `json:"excludedFamilies"`
	CoverageMeaning         string   `json:"coverageMeaning"`
	SourceEvidenceFreshness string   `json:"sourceEvidenceFreshness"`
}

type Query struct {
	Project string `json:"project"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

type NamedCheckHint struct {
	Command  []Argument `json:"command"`
	HelpOnly bool       `json:"helpOnly"`
}

type Argument struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	Literal       string   `json:"literal,omitempty"`
	AllowedValues []string `json:"allowedValues,omitempty"`
}

type Route struct {
	State      string     `json:"state"`
	Command    []Argument `json:"command,omitempty"`
	Limit      string     `json:"limit,omitempty"`
	NativePass string     `json:"nativePass,omitempty"`
}

type Check struct {
	Family                  string `json:"family"`
	Project                 string `json:"project"`
	Component               string `json:"component"`
	RuleID                  string `json:"ruleId"`
	From                    string `json:"from"`
	To                      string `json:"to"`
	GenericDeclarationRoute Route  `json:"genericDeclarationRoute"`
	NativeDescriptor        Route  `json:"nativeDescriptor"`
}

type Result struct {
	Schema            string           `json:"schema"`
	MetadataSource    string           `json:"metadataSource"`
	SourceOnlyState   string           `json:"sourceOnlyState"`
	RuleCoverageState string           `json:"ruleCoverageState"`
	Scope             Scope            `json:"scope"`
	Query             Query            `json:"query"`
	NamedCheckHints   []NamedCheckHint `json:"namedCheckHints"`
	Checks            []Check          `json:"checks"`
}

type descriptor struct {
	family, project, component, ruleID, from, to string
	command                                      []Argument
	limit, nativePass                            string
}

// LegacyInventoryRoute is a lossless adapter for the published support
// inventory records that describe the exact Prometheus and Envoy routes above.
// It keeps that inventory's v1 shape outside the public catalog schema.
type LegacyInventoryRoute struct {
	Command       []any
	MetadataState string
	Limit         string
}

// LegacyInventoryRoutes returns the unchanged support-inventory route records
// for the two projects whose public native routes are also mechanically bound
// in this package. Other inventory routes intentionally remain local to the
// maintainer-only generator.
func LegacyInventoryRoutes(project string) ([]LegacyInventoryRoute, bool) {
	routes := make([]LegacyInventoryRoute, 0, 3)
	for _, item := range descriptorSet() {
		if item.project != project {
			continue
		}
		state := ""
		switch item.ruleID {
		case "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4":
			state = "implemented_native_selected_envoy_bootstrap_minimizer"
		case "prometheus.alertmanager-api-v1-removed.3-1":
			state = "implemented_native_selected_alertmanager_config_minimizer"
		case "prometheus.scrape-classic-histograms-key-renamed.3-1":
			state = "implemented_native_selected_scrape_config_minimizer"
		case "prometheus.remote-write-http2-default.2-55-1-to-3-14-0":
			state = "implemented_native_selected_remote_write_http2_minimizer"
		}
		if state != "" {
			routes = append(routes, LegacyInventoryRoute{Command: legacyCommandFor(item.ruleID, item.command), MetadataState: state, Limit: legacyLimit(item.ruleID)})
		}
	}
	return routes, len(routes) != 0
}

// LegacyCommunityInventoryRoute supplies the existing MariaDB Operator
// preparer record from the same exact descriptor used by catalog checks.
func LegacyCommunityInventoryRoute(project string) (LegacyInventoryRoute, bool) {
	if project != "mariadb-operator" {
		return LegacyInventoryRoute{}, false
	}
	for _, item := range descriptorSet() {
		if item.project != project || item.ruleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite" {
			continue
		}
		command := legacyCommandFor(item.ruleID, item.command)
		if len(command) > 0 {
			command[0] = "prepare"
		}
		return LegacyInventoryRoute{Command: command, MetadataState: "implemented_native_mariadb_operator_resource_minimizer", Limit: "Requires one caller-selected complete native apiVersion k8s.mariadb.com/v1alpha1, kind MariaDB resource, explicit Galera-only scope, and the pre-operator-update declaration. It checks only the documented autoUpdateDataPlane prerequisite; admission, cluster state, runtime behavior, controller progress, data-plane completion, and whole-upgrade safety remain UNKNOWN."}, true
	}
	return LegacyInventoryRoute{}, false
}

func legacyCommand(args []Argument) []any {
	result := make([]any, 0, len(args)*2)
	for _, arg := range args {
		switch arg.Kind {
		case "literal":
			result = append(result, arg.Literal)
		case "file_placeholder":
			result = append(result, arg.Name, "FILE")
		case "name_placeholder":
			result = append(result, arg.Name, "NAME")
		case "boolean_operator_declaration":
			result = append(result, arg.Name+"=true|false")
		case "timestamp_placeholder":
			continue
		}
	}
	return result
}

func legacyCommandFor(ruleID string, args []Argument) []any {
	values := legacyCommand(args)
	if ruleID == "prometheus.scrape-classic-histograms-key-renamed.3-1" {
		return withoutOption(values, "--from", "--to")
	}
	if ruleID != "prometheus.alertmanager-api-v1-removed.3-1" && ruleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite" {
		return values
	}
	deferred := make([]any, 0, 2)
	kept := make([]any, 0, len(values))
	for _, value := range values {
		if value == "--alertmanager-config-complete" || value == "--alertmanager-config-precedence-resolved" || value == "--resource-complete" || value == "--pre-operator-update" {
			deferred = append(deferred, value)
			continue
		}
		kept = append(kept, value)
	}
	return append(kept, deferred...)
}

func withoutOption(values []any, names ...string) []any {
	drop := map[string]bool{}
	for _, name := range names {
		drop[name] = true
	}
	result := make([]any, 0, len(values))
	for index := 0; index < len(values); index++ {
		value, _ := values[index].(string)
		if drop[value] {
			index++
			continue
		}
		result = append(result, values[index])
	}
	return result
}

func legacyLimit(ruleID string) string {
	switch ruleID {
	case "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4":
		return "Blocker-only route checking direct V2 transport_api_version at ADS, LDS, or CDS api_config_source paths in one caller-selected directly loaded JSON bootstrap. It is limited to origins 1.34.14, 1.35.13, 1.36.10, 1.37.6, or 1.38.4 to target 1.39.1. V3, AUTO, absence, and unsupported structure remain UNKNOWN; there is no native PASS or historical 1.18 native route. Bootstrap completeness, distribution identity, xDS behavior, runtime state, and whole-upgrade safety remain UNKNOWN."
	case "prometheus.alertmanager-api-v1-removed.3-1":
		return "Checks only literal api_version in one caller-selected complete native alerting.alertmanagers entry; an omitted key uses the exact target source-derived v2 default. Addresses, credentials, paths, full configuration, Alertmanager compatibility, reachability, alert delivery, runtime behavior, and whole-upgrade safety remain unresolved."
	case "prometheus.scrape-classic-histograms-key-renamed.3-1":
		return "Checks only the reviewed old/new key in one caller-selected complete native scrape_config; job names, targets, full configuration, startup, scraping, native-histogram behavior, and whole-upgrade safety remain unresolved."
	default:
		return "Checks one literal-name remote_write entry's direct inline enable_http2 value or exact reviewed omitted default against an explicit endpoint requirement. It does not validate the whole configuration, runtime flags, endpoint support, protocol negotiation, delivery, startup, or whole-upgrade safety."
	}
}

func literal(value string) Argument  { return Argument{Kind: "literal", Literal: value} }
func file(name string) Argument      { return Argument{Name: name, Kind: "file_placeholder"} }
func name(name string) Argument      { return Argument{Name: name, Kind: "name_placeholder"} }
func timestamp(name string) Argument { return Argument{Name: name, Kind: "timestamp_placeholder"} }
func boolean(name string) Argument {
	return Argument{Name: name, Kind: "boolean_operator_declaration", AllowedValues: []string{"true", "false"}}
}

func cncfBase(project string) []Argument {
	return []Argument{literal("check"), literal("cncf"), literal("--project"), literal(project)}
}

func extend(base []Argument, values ...Argument) []Argument {
	return append(append([]Argument(nil), base...), values...)
}

func exactPair(base []Argument, from, to string) []Argument {
	return extend(base, literal("--from"), literal(from), literal("--to"), literal(to), timestamp("--now"))
}

func descriptorSet() []descriptor {
	result := make([]descriptor, 0, 22)
	alertPairs := []struct{ from, id string }{
		{"2.55.1", "prometheus.alertmanager-api-v1-removed.3-1"},
		{"3.9.1", "prometheus.alertmanager-api-v1.target-config.3-9-1-to-3-14-0"},
		{"3.10.0", "prometheus.alertmanager-api-v1.target-config.3-10-0-to-3-14-0"},
		{"3.11.3", "prometheus.alertmanager-api-v1.target-config.3-11-3-to-3-14-0"},
		{"3.12.0", "prometheus.alertmanager-api-v1.target-config.3-12-0-to-3-14-0"},
		{"3.13.3", "prometheus.alertmanager-api-v1.target-config.3-13-3-to-3-14-0"},
	}
	for _, pair := range alertPairs {
		to := "3.14.0"
		if pair.from == "2.55.1" {
			to = "3.1.0"
		}
		result = append(result, descriptor{family: FamilyCNCF, project: "prometheus", component: "pkg:github/prometheus/prometheus", ruleID: pair.id, from: pair.from, to: to, command: exactPair(extend(cncfBase("prometheus"), file("--alertmanager-config"), literal("--alertmanager-config-complete"), literal("--alertmanager-config-precedence-resolved")), pair.from, to), limit: "Selected Alertmanager mapping only; completeness and precedence remain caller declarations."})
	}
	scrapePairs := []struct{ from, id string }{
		{"2.55.1", "prometheus.scrape-classic-histograms-key-renamed.3-1"},
		{"3.9.1", "prometheus.scrape-classic-histograms.target-config.3-9-1-to-3-14-0"},
		{"3.10.0", "prometheus.scrape-classic-histograms.target-config.3-10-0-to-3-14-0"},
		{"3.11.3", "prometheus.scrape-classic-histograms.target-config.3-11-3-to-3-14-0"},
		{"3.12.0", "prometheus.scrape-classic-histograms.target-config.3-12-0-to-3-14-0"},
		{"3.13.3", "prometheus.scrape-classic-histograms.target-config.3-13-3-to-3-14-0"},
	}
	for _, pair := range scrapePairs {
		to := "3.14.0"
		if pair.from == "2.55.1" {
			to = "3.1.0"
		}
		result = append(result, descriptor{family: FamilyCNCF, project: "prometheus", component: "pkg:github/prometheus/prometheus", ruleID: pair.id, from: pair.from, to: to, command: exactPair(extend(cncfBase("prometheus"), file("--scrape-config"), name("--scrape-job"), literal("--scrape-config-complete"), literal("--scrape-config-precedence-resolved")), pair.from, to), limit: "One selected scrape_config only; completeness and precedence remain caller declarations."})
	}
	result = append(result, descriptor{family: FamilyCNCF, project: "prometheus", component: "pkg:github/prometheus/prometheus", ruleID: "prometheus.remote-write-http2-default.2-55-1-to-3-14-0", from: "2.55.1", to: "3.14.0", command: exactPair(extend(cncfBase("prometheus"), file("--prometheus-config"), literal("--prometheus-config-complete"), literal("--prometheus-config-precedence-resolved"), literal("--prometheus-rule"), literal("remote-write-http2-default"), name("--prometheus-remote-write-name"), boolean("--prometheus-remote-write-http2-required")), "2.55.1", "3.14.0"), limit: "One selected remote_write entry only; endpoint behavior remains unassessed."})
	for _, from := range []string{"1.34.14", "1.35.13", "1.36.10", "1.37.6", "1.38.4"} {
		result = append(result, descriptor{family: FamilyCNCF, project: "envoy", component: "pkg:github/envoyproxy/envoy", ruleID: "envoy.xds-v2-unsupported-at-1-39-1-from-" + strings.ReplaceAll(from, ".", "-"), from: from, to: "1.39.1", command: exactPair(extend(cncfBase("envoy"), file("--envoy-bootstrap"), literal("--envoy-bootstrap-selected")), from, "1.39.1"), limit: "Direct V2 transport blocker only; dynamic xDS and runtime behavior are unassessed.", nativePass: "NOT_AVAILABLE_BLOCKER_ONLY"})
	}
	result = append(result, descriptor{family: FamilyCNCF, project: "strimzi", component: "pkg:github/strimzi/strimzi-kafka-operator", ruleID: "strimzi.kafka-v1beta2-api-removed.1-0", from: "0.51.0", to: "1.0.0", command: exactPair(extend(cncfBase("strimzi"), file("--kafka-resource"), name("--strimzi-distribution"), literal("--target-kafka-crd-admission-required")), "0.51.0", "1.0.0"), limit: "One caller-selected rendered kind Kafka resource, or one flat v1 List of rendered resources, only; CRD installation, admission, conversion, and runtime behavior are unassessed."})
	for _, to := range []string{"0.41.0", "0.42.0"} {
		result = append(result, descriptor{family: FamilyCNCF, project: "falco", component: "pkg:github/falcosecurity/falco", ruleID: "falco.deprecated-cli-flags-removed.0-40-to-" + strings.ReplaceAll(strings.TrimSuffix(to, ".0"), ".", "-"), from: "0.40.0", to: to, command: exactPair(extend(cncfBase("falco"), file("--falco-argv"), name("--falco-distribution")), "0.40.0", to), limit: "One caller-declared explicit effective Falco argv only; wrappers, entrypoints, images, environment, defaults, and runtime behavior are unassessed."})
	}
	result = append(result, descriptor{family: FamilyCommunity, project: "mariadb-operator", component: "pkg:github/mariadb-operator/mariadb-operator", ruleID: "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite", from: "26.3.0", to: "26.6.0", command: exactPair([]Argument{literal("check"), literal("project"), literal("--project"), literal("mariadb-operator"), file("--mariadb-resource"), literal("--resource-complete"), literal("--pre-operator-update")}, "26.3.0", "26.6.0"), limit: "One complete selected MariaDB resource before the operator update; controller and data-plane behavior are unassessed."})
	return result
}

func identityKey(family, project, component, ruleID, from, to string) string {
	return family + "\x00" + project + "\x00" + component + "\x00" + ruleID + "\x00" + from + "\x00" + to
}

func genericRoute(family, project, from, to string) Route {
	if family == FamilyCommunity {
		return Route{State: RouteNotExposed, Limit: "Community embedded rules have no generic public canonical-input command."}
	}
	return Route{State: RouteExposed, Command: []Argument{literal("check"), literal("cncf"), literal("--project"), literal(project), file("--input"), timestamp("--now")}, Limit: "The canonical minimized declaration itself binds this exact identity's from/to pair; generic CLI --from/--to flags are not admitted."}
}

// Discover returns all compiled source-rule identities, optionally narrowed by
// project and exact from/to pair. It neither reads inputs nor evaluates rules.
func Discover(selectedProject, selectedFrom, selectedTo string) (Result, error) {
	cncf, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		return Result{}, fmt.Errorf("load CNCF identities: %w", err)
	}
	community, err := projectcheck.EmbeddedRuleIdentities()
	if err != nil {
		return Result{}, fmt.Errorf("load community identities: %w", err)
	}
	descriptors := map[string]descriptor{}
	for _, item := range descriptorSet() {
		key := identityKey(item.family, item.project, item.component, item.ruleID, item.from, item.to)
		if _, found := descriptors[key]; found || !validDescriptor(item) {
			return Result{}, ErrIntegrity
		}
		descriptors[key] = item
	}
	knownProjects := map[string]bool{}
	known := map[string]bool{}
	for _, item := range cncf {
		knownProjects[item.Project] = true
		known[identityKey(FamilyCNCF, item.Project, item.Component, item.RuleID, item.From, item.To)] = true
	}
	for _, item := range community {
		knownProjects[item.Project] = true
		known[identityKey(FamilyCommunity, item.Project, item.Component, item.RuleID, item.From, item.To)] = true
	}
	if len(descriptors) != 22 {
		return Result{}, fmt.Errorf("%w: descriptor count=%d", ErrIntegrity, len(descriptors))
	}
	for key := range descriptors {
		if !known[key] {
			return Result{}, fmt.Errorf("%w: descriptor does not bind an embedded identity", ErrIntegrity)
		}
	}
	coverage := "MATCHED"
	if !knownProjects[selectedProject] {
		coverage = "PROJECT_NOT_IN_EMBEDDED_RULE_PACK"
	} else if selectedFrom != "" && selectedTo != "" {
		coverage = "NO_MATCHING_EMBEDDED_RULE"
	}
	result := Result{Schema: Schema, MetadataSource: "EMBEDDED_COMPILED_BUNDLES_ONLY", SourceOnlyState: "NOT_ENUMERATED", RuleCoverageState: coverage, Scope: Scope{IncludedFamilies: []string{FamilyCNCF, FamilyCommunity}, ExcludedFamilies: []string{"named_check", "standards_conformance", "target_preflight"}, CoverageMeaning: "exact embedded source-rule identity discovery only", SourceEvidenceFreshness: "NOT_EVALUATED"}, Query: Query{Project: selectedProject, From: selectedFrom, To: selectedTo}, NamedCheckHints: namedHints(selectedProject), Checks: make([]Check, 0, len(cncf)+len(community))}
	appendIdentity := func(family, project, component, ruleID, from, to string) {
		if projectFilter(selectedProject, selectedFrom, selectedTo, project, from, to) {
			return
		}
		item := Check{Family: family, Project: project, Component: component, RuleID: ruleID, From: from, To: to, GenericDeclarationRoute: genericRoute(family, project, from, to), NativeDescriptor: Route{State: DescriptorNone}}
		if descriptor, found := descriptors[identityKey(family, project, component, ruleID, from, to)]; found {
			item.NativeDescriptor = Route{State: DescriptorExact, Command: descriptor.command, Limit: descriptor.limit, NativePass: descriptor.nativePass}
		}
		result.Checks = append(result.Checks, item)
	}
	for _, item := range cncf {
		appendIdentity(FamilyCNCF, item.Project, item.Component, item.RuleID, item.From, item.To)
	}
	for _, item := range community {
		appendIdentity(FamilyCommunity, item.Project, item.Component, item.RuleID, item.From, item.To)
	}
	sort.Slice(result.Checks, func(i, j int) bool {
		if result.Checks[i].Project != result.Checks[j].Project {
			return result.Checks[i].Project < result.Checks[j].Project
		}
		if result.Checks[i].To != result.Checks[j].To {
			return result.Checks[i].To < result.Checks[j].To
		}
		if result.Checks[i].From != result.Checks[j].From {
			return result.Checks[i].From < result.Checks[j].From
		}
		return result.Checks[i].RuleID < result.Checks[j].RuleID
	})
	if len(result.Checks) != 0 {
		result.RuleCoverageState = "MATCHED"
	}
	return result, nil
}

func validDescriptor(item descriptor) bool {
	if item.family == "" || item.project == "" || item.component == "" || item.ruleID == "" || item.from == "" || item.to == "" || item.limit == "" || len(item.command) == 0 {
		return false
	}
	if len(item.command) < 8 || !isLiteral(item.command[0], "check") || item.command[1].Kind != "literal" || (item.command[1].Literal != "cncf" && item.command[1].Literal != "project") || !isLiteral(item.command[2], "--project") || !isLiteral(item.command[3], item.project) {
		return false
	}
	seen := map[string]bool{}
	for _, arg := range item.command {
		switch arg.Kind {
		case "literal":
			if arg.Literal == "" || strings.ContainsAny(arg.Literal, "\t\r\n") {
				return false
			}
		case "file_placeholder", "name_placeholder", "timestamp_placeholder":
			if !strings.HasPrefix(arg.Name, "--") || seen[arg.Name] {
				return false
			}
			seen[arg.Name] = true
		case "boolean_operator_declaration":
			if !strings.HasPrefix(arg.Name, "--") || seen[arg.Name] || len(arg.AllowedValues) != 2 || arg.AllowedValues[0] != "true" || arg.AllowedValues[1] != "false" {
				return false
			}
			seen[arg.Name] = true
		default:
			return false
		}
	}
	return containsLiteralSequence(item.command, "--from", item.from) && containsLiteralSequence(item.command, "--to", item.to) && containsTimestamp(item.command, "--now")
}

func containsLiteralSequence(args []Argument, first, second string) bool {
	for index := 0; index+1 < len(args); index++ {
		if isLiteral(args[index], first) && isLiteral(args[index+1], second) {
			return true
		}
	}
	return false
}

func isLiteral(arg Argument, value string) bool {
	return arg.Kind == "literal" && arg.Literal == value && arg.Name == "" && len(arg.AllowedValues) == 0
}

func containsTimestamp(args []Argument, name string) bool {
	for _, arg := range args {
		if arg.Kind == "timestamp_placeholder" && arg.Name == name {
			return true
		}
	}
	return false
}

func namedHints(project string) []NamedCheckHint {
	switch project {
	case "cert-manager":
		return []NamedCheckHint{{Command: []Argument{literal("check"), literal("cert-manager-values"), literal("--help")}, HelpOnly: true}}
	case "prometheus":
		return []NamedCheckHint{{Command: []Argument{literal("check"), literal("prometheus-mode"), literal("--help")}, HelpOnly: true}}
	default:
		return []NamedCheckHint{}
	}
}

func projectFilter(selectedProject, selectedFrom, selectedTo, project, from, to string) bool {
	return selectedProject != "" && selectedProject != project || selectedFrom != "" && selectedFrom != from || selectedTo != "" && selectedTo != to
}
