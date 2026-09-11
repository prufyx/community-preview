//go:build parityreview

package prometheusmode

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestCollectorProposedArgumentParityReview(t *testing.T) {
	type testCase struct {
		name                string
		commandSet, argsSet bool
		command, args       any
		extraRegularImage   string
		initImage           string
		want                string
	}
	wide := ""
	for i := 0; i < 257; i++ {
		wide += "é"
	}
	cases := []testCase{
		{name: "absent-command-args", want: "false"},
		{name: "null-command", commandSet: true, command: nil, want: "unknown"},
		{name: "empty-command", commandSet: true, command: []string{}, want: "unknown"},
		{name: "exact-command-absent-args", commandSet: true, command: []string{"/bin/prometheus"}, want: "false"},
		{name: "null-args", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: nil, want: "unknown"},
		{name: "empty-args", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{}, want: "false"},
		{name: "empty-token", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{""}, want: "unknown"},
		{name: "empty-split-value-before-agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--config.file", "", "--agent"}, want: "unknown"},
		{name: "utf8-over-512-bytes", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{wide}, want: "unknown"},
		{name: "duplicate-agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent", "--agent"}, want: "unknown"},
		{name: "legacy-and-agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--enable-feature=agent", "--agent"}, want: "true"},
		{name: "interpolation", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"$(MODE)"}, want: "unknown"},
		{name: "terminator", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--", "--agent"}, want: "unknown"},
		{name: "split-value", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--config.file", "/path", "--agent"}, want: "true"},
		{name: "leading-positional", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"unexpected-positional", "--agent"}, want: "unknown"},
		{name: "consecutive-positional", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--config.file", "/path", "extra", "--agent"}, want: "unknown"},
		{name: "split-agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent", "true"}, want: "unknown"},
		{name: "assigned-agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent=true"}, want: "unknown"},
		{name: "no-agent", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--no-agent"}, want: "unknown"},
		{name: "inline-unrelated", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--web.listen-address=:9090", "--agent"}, want: "true"},
		{name: "regular-public-host-alias", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, extraRegularImage: "index.docker.io/prom/prometheus:v3.1.0@" + ProposedImageDigest, want: "unknown"},
		{name: "regular-public-unsupported-tag", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, extraRegularImage: "prom/prometheus:latest", want: "unknown"},
		{name: "init-public-host-alias", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, initImage: "index.docker.io/prom/prometheus:v3.1.0@" + ProposedImageDigest, want: "unknown"},
		{name: "init-public-unprefixed-tag", commandSet: true, command: []string{"/bin/prometheus"}, argsSet: true, args: []string{"--agent"}, initImage: "prom/prometheus:3.1.0@" + ProposedImageDigest, want: "unknown"},
	}
	registry, err := os.ReadFile("../../scripts/component-configuration-adapters-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			container := map[string]any{"image": "prom/prometheus:v3.1.0@" + ProposedImageDigest}
			if tc.commandSet {
				container["command"] = tc.command
			}
			if tc.argsSet {
				container["args"] = tc.args
			}
			containers := []any{container}
			if tc.extraRegularImage != "" {
				containers = append(containers, map[string]any{"image": tc.extraRegularImage})
			}
			initContainers := []any{}
			if tc.initImage != "" {
				initContainers = append(initContainers, map[string]any{"image": tc.initImage})
			}
			workload := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": containers, "initContainers": initContainers}}}}
			raw, _ := json.Marshal(workload)
			var typed workloadDocument
			if err := json.Unmarshal(raw, &typed); err != nil {
				t.Fatal(err)
			}
			projection, err := projectWorkload(typed)
			if err != nil {
				t.Fatal(err)
			}
			goResult := "unknown"
			if projection.AgentMode != nil {
				if *projection.AgentMode {
					goResult = "true"
				} else {
					goResult = "false"
				}
			}
			jqInput, _ := json.Marshal(map[string]any{
				"items": []any{map[string]any{
					"kind": "Deployment",
					"spec": map[string]any{"template": map[string]any{
						"spec": map[string]any{"containers": containers, "initContainers": initContainers},
					}},
				}},
			})
			cmd := exec.Command("jq", "-c", "-S", "--argjson", "registry", string(registry), "--arg", "roleEvidenceVersion", "v3", "-f", "../../scripts/component-configuration-adapter-v3.jq")
			cmd.Stdin = bytes.NewReader(jqInput)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("jq: %v", err)
			}
			var result struct {
				Configuration []struct {
					Predicates map[string]json.RawMessage `json:"predicates"`
				} `json:"configuration"`
			}
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			jqResult := "unknown"
			for _, row := range result.Configuration {
				if value, ok := row.Predicates[AgentModePredicateID]; ok {
					var mode bool
					if json.Unmarshal(value, &mode) == nil {
						if mode {
							jqResult = "true"
						} else {
							jqResult = "false"
						}
					}
				}
			}
			if goResult != tc.want || jqResult != tc.want {
				t.Fatalf("go=%s jq=%s want=%s", goResult, jqResult, tc.want)
			}
		})
	}
}
