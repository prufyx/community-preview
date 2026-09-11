package cncfprepare

import "strings"

// Thanos 0.42 removes one literal flag from each of its Receive and Store
// subcommands. This adapter reads one caller-supplied Kubernetes workload JSON
// object. It neither contacts Kubernetes nor infers generated arguments,
// image provenance, Query compatibility, compaction, storage, or runtime
// behavior.
const (
	ThanosComponent = "pkg:github/thanos-io/thanos"
	ThanosFact      = "component.thanos.removed_subcommand_flags_present"
	ThanosFrom      = "0.41.0"
	ThanosTo        = "0.42.0"
)

const (
	ReasonThanosRemovedFlagPresent  Reason = "THANOS_REMOVED_RECEIVE_OR_STORE_FLAG_PRESENT"
	ReasonThanosRemovedFlagAbsent   Reason = "THANOS_REMOVED_RECEIVE_OR_STORE_FLAG_ABSENT"
	ReasonThanosWorkloadUnsupported Reason = "THANOS_WORKLOAD_INPUT_UNSUPPORTED"
)

// PrepareThanos accepts only apps/v1 Deployment, StatefulSet, or DaemonSet
// objects with one explicitly named "thanos" container. That container must
// explicitly declare command:["thanos"] and an admitted upstream Thanos image
// tagged for the target
// endpoint. Its args must begin with the literal Receive or Store subcommand
// and have no argument delimiter or Kingpin @file expansion: opaque expanded
// arguments are never used to conclude that an option is absent. Sidecars are
// allowed when their names make the Thanos selection unambiguous.
func PrepareThanos(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	present, ok := thanosRemovedFlagFact(value, to)
	fact := inputFact{ID: ThanosFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonThanosWorkloadUnsupported
	if ok {
		fact.State = "declared"
		fact.BoolValue = &present
		state = StatePrepared
		if present {
			reason = ReasonThanosRemovedFlagPresent
		} else {
			reason = ReasonThanosRemovedFlagAbsent
		}
	}
	canonical, err := marshalComponentInput(ThanosComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"NATIVE_WORKLOAD_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"GENERATED_ARGUMENT_SOURCES_IMAGE_PROVENANCE_AND_RUNTIME_NOT_EVALUATED",
			"QUERY_STORAGE_COMPACTION_AND_WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func thanosRemovedFlagFact(value any, to string) (bool, bool) {
	root, ok := value.(map[string]any)
	if !ok || root["apiVersion"] != "apps/v1" || !oneOfString(root["kind"], "Deployment", "StatefulSet", "DaemonSet") {
		return false, false
	}
	metadata, ok := root["metadata"].(map[string]any)
	if !ok || !nonemptyString(metadata["name"]) || !nonemptyString(metadata["namespace"]) {
		return false, false
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return false, false
	}
	template, ok := spec["template"].(map[string]any)
	if !ok {
		return false, false
	}
	templateSpec, ok := template["spec"].(map[string]any)
	if !ok {
		return false, false
	}
	containers, ok := templateSpec["containers"].([]any)
	if !ok || len(containers) == 0 {
		return false, false
	}
	var args []any
	found := 0
	names := make(map[string]struct{}, len(containers))
	for _, item := range containers {
		container, ok := item.(map[string]any)
		name, named := container["name"].(string)
		if !ok || !named || name == "" {
			return false, false
		}
		if _, duplicate := names[name]; duplicate {
			return false, false
		}
		names[name] = struct{}{}
		if name != "thanos" {
			continue
		}
		found++
		var argsOK, commandOK bool
		args, argsOK = container["args"].([]any)
		command, commandOK := container["command"].([]any)
		if !argsOK || len(args) == 0 || !commandOK || len(command) != 1 || !thanosCommand(command[0]) || !targetImage(container["image"], to) {
			return false, false
		}
	}
	if found != 1 {
		return false, false
	}
	words := make([]string, len(args))
	for i, item := range args {
		word, ok := item.(string)
		if !ok || word == "" || strings.ContainsRune(word, '\x00') || strings.Contains(word, "$") || strings.HasPrefix(word, "@") {
			return false, false
		}
		words[i] = word
	}
	if words[0] != "receive" && words[0] != "store" {
		return false, false
	}
	for _, word := range words[1:] {
		if word == "--" {
			return false, false
		}
	}
	if words[0] == "receive" {
		return literalFlagPresent(words[1:], "--shipper.ignore-unequal-block-size"), true
	}
	return literalFlagPresent(words[1:], "--debug.advertise-compatibility-label"), true
}

func oneOfString(value any, choices ...string) bool {
	text, ok := value.(string)
	return ok && oneOf(text, choices...)
}

func literalFlagPresent(words []string, flag string) bool {
	negative := "--no-" + strings.TrimPrefix(flag, "--")
	for _, word := range words {
		// This rule covers removal of the option itself, not an inferred
		// historical Boolean value. Empty, false, negative-alias, and duplicate
		// appearances still retain the removed spelling in the supplied argv.
		if word == flag || strings.HasPrefix(word, flag+"=") || word == negative || strings.HasPrefix(word, negative+"=") {
			return true
		}
	}
	return false
}

// targetImage recognizes the two image locations documented in the retained
// Thanos changelog source (quay.io/thanos/thanos and the thanosio/thanos
// Docker Hub mirror). It binds a supplied target manifest to an upstream image
// identity and target tag without claiming that it was pulled or deployed.
func targetImage(value any, to string) bool {
	image, ok := value.(string)
	if !ok || strings.Contains(image, "@") {
		return false
	}
	for _, repository := range []string{"quay.io/thanos/thanos", "thanosio/thanos", "docker.io/thanosio/thanos"} {
		if image == repository+":v"+to {
			return true
		}
	}
	return false
}

func thanosCommand(value any) bool { command, ok := value.(string); return ok && command == "thanos" }
