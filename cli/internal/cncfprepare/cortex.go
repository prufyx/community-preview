package cncfprepare

import "strings"

// Cortex 1.21.1 removes the literal querier.at-modifier-enabled option. This
// adapter reads one caller-supplied proposed Kubernetes workload JSON object.
// It does not contact Kubernetes or infer default entrypoints, environment,
// files, generated configuration, image digests, query behavior, storage, or
// runtime state.
const (
	CortexComponent        = "pkg:github/cortexproject/cortex"
	CortexDistributionFact = "component.cortex.distribution"
	CortexSurfaceFact      = "component.cortex.execution_surface"
	CortexFact             = "component.cortex.removed_at_modifier_flag_present"
	CortexFrom             = "1.17.2"
	CortexTo               = "1.21.1"
)

const (
	ReasonCortexRemovedFlagPresent  Reason = "CORTEX_REMOVED_AT_MODIFIER_FLAG_PRESENT"
	ReasonCortexRemovedFlagAbsent   Reason = "CORTEX_REMOVED_AT_MODIFIER_FLAG_ABSENT"
	ReasonCortexWorkloadUnsupported Reason = "CORTEX_WORKLOAD_INPUT_UNSUPPORTED"
)

// PrepareCortex accepts only apps/v1 Deployment, StatefulSet, or DaemonSet
// objects with one explicitly named "cortex" container. The selected container
// must explicitly declare command:["/bin/cortex"] and the source-documented
// upstream target image tag. Its args are a caller-supplied literal argv
// vector limited to an empty list, self-contained -name=value options, and
// the exact removed option spelling. A missing command, default entrypoint,
// shell wrapper, custom image, delimiter, positional token, bare unrelated
// option, dynamic token, or ambiguous selection remains UNKNOWN. Sidecars are
// allowed only when container names make Cortex selection unambiguous.
func PrepareCortex(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	present, ok := cortexRemovedFlagFact(value, to)
	facts := []inputFact{
		{ID: CortexDistributionFact, State: "unsupported"},
		{ID: CortexSurfaceFact, State: "unsupported"},
		{ID: CortexFact, State: "unsupported"},
	}
	state, reason := StateUnknown, ReasonCortexWorkloadUnsupported
	if ok {
		facts[0] = inputFact{ID: CortexDistributionFact, State: "declared", EnumValue: "official_upstream"}
		facts[1] = inputFact{ID: CortexSurfaceFact, State: "declared", EnumValue: "cortex"}
		facts[2] = inputFact{ID: CortexFact, State: "declared", BoolValue: &present}
		state = StatePrepared
		if present {
			reason = ReasonCortexRemovedFlagPresent
		} else {
			reason = ReasonCortexRemovedFlagAbsent
		}
	}
	canonical, err := marshalComponentInput(CortexComponent, from, to, facts)
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
			"DEFAULT_ENTRYPOINT_GENERATED_ARGUMENTS_AND_RUNTIME_NOT_EVALUATED",
			"QUERY_STORAGE_TENANCY_AND_WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func cortexRemovedFlagFact(value any, to string) (bool, bool) {
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
		if name != "cortex" {
			continue
		}
		found++
		var argsOK, commandOK bool
		args, argsOK = container["args"].([]any)
		command, commandOK := container["command"].([]any)
		if !argsOK || !commandOK || len(command) != 1 || !cortexCommand(command[0]) || !cortexTargetImage(container["image"], to) {
			return false, false
		}
	}
	if found != 1 {
		return false, false
	}
	return cortexLiteralAtModifierFlag(args)
}

func cortexLiteralAtModifierFlag(args []any) (present bool, admitted bool) {
	for _, item := range args {
		word, ok := item.(string)
		if !ok || word == "" || strings.ContainsRune(word, '\x00') || strings.ContainsAny(word, "\r\n") || strings.Contains(word, "$") || word == "--" {
			return false, false
		}
		if word == "-"+cortexRemovedAtModifierOption || word == "--"+cortexRemovedAtModifierOption ||
			strings.HasPrefix(word, "-"+cortexRemovedAtModifierOption+"=") ||
			strings.HasPrefix(word, "--"+cortexRemovedAtModifierOption+"=") {
			present = true
			continue
		}
		// Without exact Cortex option arity evidence, only self-contained
		// options are admitted. A following token might be a value rather
		// than another option, so bare flags and positional tokens are unknown.
		if !strings.HasPrefix(word, "-") || !strings.Contains(word, "=") {
			return false, false
		}
	}
	return present, true
}

const cortexRemovedAtModifierOption = "querier.at-modifier-enabled"

func cortexTargetImage(value any, to string) bool {
	image, ok := value.(string)
	return ok && image == "quay.io/cortexproject/cortex:v"+to
}

func cortexCommand(value any) bool {
	command, ok := value.(string)
	return ok && command == "/bin/cortex"
}
