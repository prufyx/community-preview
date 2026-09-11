// Package projectprepare derives minimized facts from native configuration
// files for the closed, maintainer-reviewed community-project registry.
package projectprepare

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	InputSchema    = "prufyx.io/operator-declared-constraint-input/v1alpha1"
	InputAuthority = "OPERATOR_DECLARED_MINIMIZED"

	GrafanaProject   = "grafana"
	GrafanaComponent = "pkg:github/grafana/grafana"
	GrafanaFrom      = "10.4.0"
	GrafanaTo        = "11.0.0"
	GrafanaFact      = "component.grafana.legacy_alerting_explicitly_enabled"

	KibanaProject   = "kibana"
	KibanaComponent = "pkg:github/elastic/kibana"
	KibanaFrom      = "8.18.0"
	KibanaTo        = "9.0.0"
	KibanaFact      = "component.kibana.reporting_roles_allow_present"

	CephProject   = "ceph"
	CephComponent = "pkg:github/ceph/ceph"
	CephFrom      = "17.2.7"
	CephTo        = "18.2.0"
	CephFact      = "component.ceph.selected_current_osd_filestore"

	maxInputBytes = 1 << 20
)

var (
	ErrInvalid = errors.New("invalid community project preparation input")
	versionRE  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

type Prepared struct {
	CanonicalInputJSON []byte
	SourceDigest       string
	InputDigest        string
	State              string
	Reason             string
	Omissions          []string
}

type inputEnvelope struct {
	Schema, Authority string
	Current, Proposed inputSide
}
type inputSide struct {
	Components []inputComponent `json:"components"`
}
type inputComponent struct {
	Component string      `json:"component"`
	Version   string      `json:"version"`
	Facts     []inputFact `json:"facts"`
}
type inputFact struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	BoolValue *bool  `json:"boolValue,omitempty"`
}

func (d inputEnvelope) MarshalJSON() ([]byte, error) {
	type wire struct {
		Schema    string    `json:"schema"`
		Authority string    `json:"authority"`
		Current   inputSide `json:"current"`
		Proposed  inputSide `json:"proposed"`
	}
	return json.Marshal(wire{d.Schema, d.Authority, d.Current, d.Proposed})
}

// PrepareEffectiveConfig inspects one native config. complete means every
// effective setting is represented; precedenceResolved means environment and
// CLI overrides have already been applied by the caller. Neither is inferred.
func PrepareEffectiveConfig(project string, raw []byte, from, to string, complete, precedenceResolved bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !versionRE.MatchString(from) || !versionRE.MatchString(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	component, factID := "", ""
	found, supported := false, false
	var err error
	switch project {
	case GrafanaProject:
		component, factID = GrafanaComponent, GrafanaFact
		found, supported, err = grafanaLegacyAlerting(raw)
	case KibanaProject:
		component, factID = KibanaComponent, KibanaFact
		found, supported, err = kibanaReportingRolesAllow(raw)
	default:
		return Prepared{}, ErrInvalid
	}
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	fact := inputFact{ID: factID, State: "unsupported"}
	state, reason := "UNKNOWN", "EFFECTIVE_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"
	if complete && precedenceResolved && supported {
		value := found
		fact = inputFact{ID: factID, State: "declared", BoolValue: &value}
		state, reason = "PREPARED", "NATIVE_EFFECTIVE_CONFIG_RELEVANT_KEY_INSPECTED"
	}
	canonical, err := marshalInput(component, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SUPPLIED_CONFIG_NOT_LIVE_OBSERVATION",
			"ENVIRONMENT_AND_CLI_PRECEDENCE_DECLARED_NOT_OBSERVED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func marshalInput(component, from, to string, facts []inputFact) ([]byte, error) {
	return marshalInputSides(component, from, to, nil, facts)
}

func marshalInputSides(component, from, to string, currentFacts, proposedFacts []inputFact) ([]byte, error) {
	if currentFacts == nil {
		currentFacts = []inputFact{}
	}
	if proposedFacts == nil {
		proposedFacts = []inputFact{}
	}
	sort.Slice(currentFacts, func(i, j int) bool { return currentFacts[i].ID < currentFacts[j].ID })
	sort.Slice(proposedFacts, func(i, j int) bool { return proposedFacts[i].ID < proposedFacts[j].ID })
	doc := inputEnvelope{
		Schema: InputSchema, Authority: InputAuthority,
		Current:  inputSide{Components: []inputComponent{{Component: component, Version: from, Facts: currentFacts}}},
		Proposed: inputSide{Components: []inputComponent{{Component: component, Version: to, Facts: proposedFacts}}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// grafanaLegacyAlerting parses the native INI surface far enough to inspect
// [alerting] enabled. Duplicate relevant sections/keys and malformed relevant
// values are input errors; unrelated settings are not retained.
func grafanaLegacyAlerting(raw []byte) (found, supported bool, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxInputBytes)
	section := ""
	seenSection, seenKey, enabled := false, false, false
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.Contains(line[1:len(line)-1], "[") {
				return false, false, ErrInvalid
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if strings.EqualFold(section, "alerting") && section != "alerting" {
				return false, false, nil
			}
			if section == "alerting" {
				if seenSection {
					return false, false, ErrInvalid
				}
				seenSection = true
			}
			continue
		}
		if section != "alerting" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false, false, ErrInvalid
		}
		key = strings.TrimSpace(key)
		if strings.EqualFold(key, "enabled") && key != "enabled" {
			return false, false, nil
		}
		if key != "enabled" {
			continue
		}
		if seenKey {
			return false, false, ErrInvalid
		}
		seenKey = true
		value = stripInlineComment(strings.TrimSpace(value))
		switch strings.ToLower(value) {
		case "true":
			enabled = true
		case "false":
			enabled = false
		case "":
			return false, false, nil
		default:
			return false, false, ErrInvalid
		}
	}
	if scanner.Err() != nil {
		return false, false, ErrInvalid
	}
	return seenKey && enabled, true, nil
}

func stripInlineComment(value string) string {
	for i, r := range value {
		if (r == '#' || r == ';') && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
			return strings.TrimSpace(value[:i])
		}
	}
	return strings.TrimSpace(value)
}

// kibanaReportingRolesAllow accepts native kibana.yml in either documented
// dotted-key form or a plain nested mapping. It deliberately declines YAML
// features whose key identity cannot be established without a full YAML model.
func kibanaReportingRolesAllow(raw []byte) (found, supported bool, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return kibanaJSON(trimmed)
	}
	return kibanaYAML(trimmed)
}

func kibanaJSON(raw []byte) (bool, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return false, false, ErrInvalid
	}
	if token, e := decoder.Token(); e != io.EOF || token != nil {
		return false, false, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok {
		return false, false, ErrInvalid
	}
	if hasKibanaMixedJSONPrefix(root) {
		return false, false, nil
	}
	if hasCaseVariant(root, "xpack.reporting.roles.allow") {
		return false, false, nil
	}
	_, dotted := root["xpack.reporting.roles.allow"]
	value = any(root)
	nested := false
	for _, key := range []string{"xpack", "reporting", "roles"} {
		object, ok := value.(map[string]any)
		if !ok || hasCaseVariant(object, key) {
			return false, false, nil
		}
		next, exists := object[key]
		if !exists {
			break
		}
		if key == "roles" {
			roles, ok := next.(map[string]any)
			if !ok || hasCaseVariant(roles, "allow") {
				return false, false, nil
			}
			_, nested = roles["allow"]
			break
		}
		if _, ok := next.(map[string]any); !ok {
			return false, false, nil
		}
		value = next
	}
	if dotted && nested {
		return false, false, ErrInvalid
	}
	return dotted || nested, true, nil
}

// hasKibanaMixedJSONPrefix rejects hybrid encodings such as
// {"xpack.reporting":{"roles":{"allow":[]}}}. Supporting either the full
// dotted key or the full nested object does not make partial dotted parents
// unambiguous.
func hasKibanaMixedJSONPrefix(root map[string]any) bool {
	if hasKibanaDottedDescendant(root, "") {
		return true
	}
	for _, key := range []string{"xpack.reporting", "xpack.reporting.roles"} {
		if _, ok := root[key]; ok || hasCaseVariant(root, key) {
			return true
		}
	}
	xpack, ok := root["xpack"].(map[string]any)
	if !ok {
		return false
	}
	if hasKibanaDottedDescendant(xpack, "xpack") {
		return true
	}
	for _, key := range []string{"reporting.roles", "reporting.roles.allow"} {
		if _, ok := xpack[key]; ok || hasCaseVariant(xpack, key) {
			return true
		}
	}
	reporting, ok := xpack["reporting"].(map[string]any)
	if !ok {
		return false
	}
	if hasKibanaDottedDescendant(reporting, "xpack.reporting") {
		return true
	}
	if _, ok := reporting["roles.allow"]; ok || hasCaseVariant(reporting, "roles.allow") {
		return true
	}
	roles, ok := reporting["roles"].(map[string]any)
	return ok && hasKibanaDottedDescendant(roles, "xpack.reporting.roles")
}

func hasKibanaDottedDescendant(object map[string]any, prefix string) bool {
	const selected = "xpack.reporting.roles.allow"
	for key := range object {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if strings.HasPrefix(strings.ToLower(path), selected+".") {
			return true
		}
	}
	return false
}

func hasCaseVariant(object map[string]any, expected string) bool {
	for key := range object {
		if key != expected && strings.EqualFold(key, expected) {
			return true
		}
	}
	return false
}

func decodeJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, ErrInvalid
			}
			if _, duplicate := object[key]; duplicate {
				return nil, ErrInvalid
			}
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalid
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalid
		}
		return array, nil
	default:
		return nil, ErrInvalid
	}
}

func kibanaYAML(raw []byte) (bool, bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxInputBytes)
	stack := map[int]string{}
	seen := map[string]bool{}
	found := false
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if trim == "---" || trim == "..." {
			return false, false, nil
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if strings.Contains(line[:indent], "\t") || indent%2 != 0 {
			return false, false, nil
		}
		content := strings.TrimSpace(line)
		if hasYAMLSpecialToken(content) {
			return false, false, nil
		}
		if strings.HasPrefix(content, "-") {
			parentPath, complete := yamlStackPath(stack, indent)
			if complete && parentPath == "xpack.reporting.roles.allow" {
				continue
			}
			if strings.HasPrefix(parentPath, "xpack") {
				return false, false, nil
			}
			continue
		}
		key, value, ok := strings.Cut(content, ":")
		key = strings.TrimSpace(key)
		if !ok || key == "" || strings.ContainsAny(key, "'\"") {
			return false, false, nil
		}
		for depth := range stack {
			if depth >= indent {
				delete(stack, depth)
			}
		}
		path := key
		if indent > 0 {
			parts := make([]string, 0)
			for depth := 0; depth < indent; depth += 2 {
				parent, ok := stack[depth]
				if !ok {
					return false, false, nil
				}
				parts = append(parts, parent)
			}
			parts = append(parts, key)
			path = strings.Join(parts, ".")
		}
		if ambiguousKibanaPath(path) {
			return false, false, nil
		}
		relevant := path == "xpack" || strings.HasPrefix(path, "xpack.") || strings.HasPrefix(key, "xpack.reporting.roles")
		plainValue := strings.TrimSpace(stripYAMLComment(value))
		if (path == "xpack" || path == "xpack.reporting" || path == "xpack.reporting.roles") && plainValue != "" {
			return false, false, nil
		}
		if relevant && path != "xpack.reporting.roles.allow" && strings.ContainsAny(trim, "{}") {
			return false, false, nil
		}
		if seen[path] {
			return false, false, ErrInvalid
		}
		seen[path] = true
		if path == "xpack.reporting.roles.allow" {
			found = true
		}
		if strings.TrimSpace(stripYAMLComment(value)) == "" {
			stack[indent] = key
		}
	}
	if scanner.Err() != nil {
		return false, false, ErrInvalid
	}
	return found, true, nil
}

// hasYAMLSpecialToken recognizes anchors, aliases, tags, and merge keys without
// treating those characters inside quoted or ordinary scalar text as syntax.
// These features are rejected document-wide because they can inject a selected
// setting from outside the visibly inspected mapping.
func hasYAMLSpecialToken(content string) bool {
	if key, _, ok := strings.Cut(content, ":"); ok && strings.TrimSpace(key) == "<<" {
		return true
	}
	quoted := rune(0)
	for i, current := range content {
		if quoted != 0 {
			if current == quoted && (i == 0 || content[i-1] != '\\') {
				quoted = 0
			}
			continue
		}
		if current == '\'' || current == '"' {
			quoted = current
			continue
		}
		if current == '#' && (i == 0 || content[i-1] == ' ' || content[i-1] == '\t') {
			break
		}
		if current != '&' && current != '*' && current != '!' {
			continue
		}
		boundary := i == 0 || strings.ContainsRune(" \t[{,:-", rune(content[i-1]))
		if boundary && i+1 < len(content) && content[i+1] != ' ' && content[i+1] != '\t' {
			return true
		}
	}
	return false
}

func ambiguousKibanaPath(path string) bool {
	if strings.HasPrefix(strings.ToLower(path), "xpack.reporting.roles.allow.") {
		return true
	}
	for _, expected := range []string{"xpack", "xpack.reporting", "xpack.reporting.roles", "xpack.reporting.roles.allow"} {
		if path != expected && strings.EqualFold(path, expected) {
			return true
		}
	}
	return false
}

func yamlStackPath(stack map[int]string, indent int) (string, bool) {
	parts := make([]string, 0, indent/2)
	for depth := 0; depth < indent; depth += 2 {
		part, ok := stack[depth]
		if !ok {
			return strings.Join(parts, "."), false
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "."), true
}

func stripYAMLComment(value string) string {
	if index := strings.Index(value, " #"); index >= 0 {
		return value[:index]
	}
	return value
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
