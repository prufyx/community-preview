package cncfprepare

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	FluentDComponent    = "pkg:github/fluent/fluentd"
	FluentDFrom         = "1.17.1"
	FluentDTo           = "1.18.0"
	FluentDRiskFact     = "component.fluentd.literal_treatment_change_risk"
	FluentDCompleteFact = "component.fluentd.selected_value_complete"
	FluentDDefaultFact  = "component.fluentd.current_default_used"
	FluentDPreserveFact = "component.fluentd.preserve_literal_treatment"
)

const (
	ReasonFluentDBlocked     Reason = "FLUENTD_LITERAL_TREATMENT_MAY_CHANGE"
	ReasonFluentDPass        Reason = "FLUENTD_LITERAL_TREATMENT_PRESERVED"
	ReasonFluentDIncomplete  Reason = "FLUENTD_LITERAL_DECLARATION_INCOMPLETE"
	ReasonFluentDUnsupported Reason = "FLUENTD_LITERAL_DECLARATION_UNSUPPORTED"
	ReasonFluentDPair        Reason = "FLUENTD_UNSUPPORTED_VERSION_PAIR"
)

// PrepareFluentDLiteral accepts a deliberately small declaration around two
// selected classic-config literal values. It does not parse a Fluentd file or
// Ruby and retains only the marker-presence fact.
func PrepareFluentDLiteral(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 5 {
		return Prepared{}, ErrInvalid
	}
	for key := range object {
		if key != "current" && key != "proposed" && key != "selectedValueComplete" && key != "currentDefaultUsed" && key != "preserveLiteralTreatment" {
			return Prepared{}, ErrInvalid
		}
	}
	current, ok1 := object["current"].(string)
	proposed, ok2 := object["proposed"].(string)
	complete, ok3 := object["selectedValueComplete"].(bool)
	defaultUsed, ok4 := object["currentDefaultUsed"].(bool)
	preserve, ok5 := object["preserveLiteralTreatment"].(bool)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return Prepared{}, ErrInvalid
	}
	canonicalFacts := []inputFact{
		{ID: FluentDDefaultFact, State: "unsupported"},
		{ID: FluentDRiskFact, State: "unsupported"},
		{ID: FluentDPreserveFact, State: "unsupported"},
		{ID: FluentDCompleteFact, State: "unsupported"},
	}
	state, reason := StateUnknown, ReasonFluentDUnsupported
	if !complete || !defaultUsed || !preserve {
		reason = ReasonFluentDIncomplete
	} else {
		currentMarker, currentOK := fluentDLiteralMarker(current)
		_, proposedOK := fluentDLiteralMarker(strings.Trim(proposed, "'"))
		wrapper := len(proposed) == len(current)+2 && strings.HasPrefix(proposed, "'") && strings.HasSuffix(proposed, "'") && proposed[1:len(proposed)-1] == current
		if !currentOK || (!proposedOK && !wrapper) || (proposedOK && !wrapper && proposed != current) {
			reason = ReasonFluentDUnsupported
		} else if from != FluentDFrom || to != FluentDTo {
			reason = ReasonFluentDPair
		} else {
			state = StatePrepared
			for _, i := range []int{0, 2, 3} {
				canonicalFacts[i].State = "declared"
				v := true
				canonicalFacts[i].BoolValue = &v
			}
			risk := currentMarker > 0 && !wrapper
			canonicalFacts[1] = inputFact{ID: FluentDRiskFact, State: "declared", BoolValue: &risk}
			if risk {
				reason = ReasonFluentDBlocked
			} else {
				reason = ReasonFluentDPass
			}
		}
	}
	canonical, err := marshalComponentInput(FluentDComponent, from, to, canonicalFacts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"SELECTED_CLASSIC_CONFIG_LITERAL_VALUES_NOT_RETAINED",
		"ONLY_ONE_SELECTED_LITERAL_DECLARATION_IS_SUPPORTED",
		"RUBY_INTERPOLATION_IS_NOT_PARSED_OR_EXECUTED",
		"INCLUDES_ENVIRONMENT_VARIABLES_AND_RUNTIME_BEHAVIOR_REMAIN_UNRESOLVED",
	}}, nil
}

// fluentDLiteralMarker validates the complete selected JSON literal and
// returns the number of simple interpolation markers found (0 or 1).
func fluentDLiteralMarker(raw string) (int, bool) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\\'$\uFFFD") || !utf8.ValidString(raw) || !json.Valid([]byte(raw)) {
		return 0, false
	}
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return 0, false
	}
	if _, ok := strictLiteralJSON([]byte(raw)); !ok {
		return 0, false
	}
	markers := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for i < len(raw) && raw[i] != '"' {
			if raw[i] == '#' && i+1 < len(raw) && raw[i+1] == '{' {
				end := strings.IndexByte(raw[i+2:], '}')
				if end < 1 {
					return 0, false
				}
				body := raw[i+2 : i+2+end]
				for _, c := range body {
					if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_ +*/().-", c)) {
						return 0, false
					}
				}
				markers++
				if markers > 1 {
					return 0, false
				}
				i += 2 + end
			}
			i++
		}
		if i >= len(raw) {
			return 0, false
		}
	}
	return markers, true
}

func strictLiteralJSON(raw []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() (any, bool)
	walk = func() (any, bool) {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		switch d := token.(type) {
		case json.Delim:
			if d == '{' {
				obj := map[string]any{}
				seen := map[string]bool{}
				for decoder.More() {
					kt, e := decoder.Token()
					if e != nil {
						return nil, false
					}
					key, ok := kt.(string)
					if !ok || seen[key] {
						return nil, false
					}
					seen[key] = true
					v, ok := walk()
					if !ok {
						return nil, false
					}
					obj[key] = v
				}
				if _, err := decoder.Token(); err != nil {
					return nil, false
				}
				return obj, true
			}
			if d == '[' {
				var arr []any
				for decoder.More() {
					v, ok := walk()
					if !ok {
						return nil, false
					}
					arr = append(arr, v)
				}
				if _, err := decoder.Token(); err != nil {
					return nil, false
				}
				return arr, true
			}
			return nil, false
		default:
			return token, true
		}
	}
	v, ok := walk()
	if !ok {
		return nil, false
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return nil, false
	}
	return v, true
}
