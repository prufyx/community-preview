package supportinventory

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func repositoryConfig(t *testing.T) (Config, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Rules: filepath.Join(root, "internal/cncfcheck/data/rules.json"), Landscape: filepath.Join(root, "internal/cncfcheck/data/landscape-projects.json"),
		CertContract: filepath.Join(root, "internal/certmanagervalues/source-contract-v1.json"), PrometheusContract: filepath.Join(root, "internal/prometheusmode/source-contract-v1.json"),
		SPIFFEProfile: filepath.Join(root, "internal/spiffex509svid/data/profile.json"), CloudEventsProfile: filepath.Join(root, "internal/cloudeventsstructuredjson/data/profile.json"),
		TiKVProfile: filepath.Join(root, "internal/tikvgcpv2/data/profile.json"), CNCFPrepareSource: filepath.Join(root, "internal/communityapp/cncf_prepare.go"),
		ProjectRules: filepath.Join(root, "internal/projectcheck/data/rules.json"), ProjectRegistry: filepath.Join(root, "internal/projectcheck/data/projects.json"),
		SelectedSourceManifest: filepath.Join(root, "docs/data/selected-source-records-v1.json"),
	}, root
}

func TestSupportInventory_ArgoWorkflowsUsesWorkloadPreparerMetadata(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Command []string `json:"command"`
				Rules   []struct {
					Limit string `json:"limit"`
				} `json:"rules"`
				LocalPreparer struct {
					MetadataState string `json:"metadataState"`
					Limit         string `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "argo-workflows" {
			continue
		}
		if len(project.Capabilities) != 1 || len(project.Capabilities[0].Rules) != 1 || project.Capabilities[0].LocalPreparer.MetadataState != "implemented_native_kubernetes_workload_minimizer" || strings.Contains(project.Capabilities[0].LocalPreparer.Limit, "precedence") || !strings.Contains(project.Capabilities[0].Rules[0].Limit, "workload") {
			t.Fatalf("incorrect Argo Workflows inventory metadata: %#v", project.Capabilities)
		}
		return
	}
	t.Fatal("Argo Workflows inventory entry missing")
}

func TestSupportInventory_FluentBitUsesDeclaredClassicConfigurationMetadata(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "fluent-bit" {
			continue
		}
		if len(project.Capabilities) != 1 {
			t.Fatalf("incorrect Fluent Bit capability count: %#v", project.Capabilities)
		}
		preparer := project.Capabilities[0].LocalPreparer
		for _, flag := range []string{"--effective-config-complete", "--current-default-was-used", "--preserve-http2-enabled"} {
			if !slices.Contains(preparer.Command, flag) {
				t.Fatalf("Fluent Bit declaration flag missing from discovery command %q: %#v", flag, preparer.Command)
			}
		}
		if preparer.MetadataState != "implemented_native_classic_configuration_minimizer" || strings.Contains(preparer.Limit, "environment and CLI precedence") || !strings.Contains(preparer.Limit, "only that setting") {
			t.Fatalf("incorrect Fluent Bit inventory metadata: %#v", preparer)
		}
		return
	}
	t.Fatal("Fluent Bit inventory entry missing")
}

func TestSupportInventory_NativeCNCFRoutesDescribeDirectInputs(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		flag  string
		state string
	}{
		"thanos":     {"--native-resource", "implemented_native_kubernetes_workload_minimizer"},
		"cortex":     {"--native-resource", "implemented_native_kubernetes_workload_minimizer"},
		"nats":       {"--nats-config", "implemented_native_json_configuration_minimizer"},
		"flux":       {"--native-resource", "implemented_native_rendered_resource_minimizer"},
		"prometheus": {"--scrape-config", "implemented_native_selected_scrape_config_minimizer"},
	}
	for _, project := range document.Projects {
		expected, ok := want[project.ProjectID]
		if !ok {
			continue
		}
		matched := 0
		for _, capability := range project.Capabilities {
			if capability.LocalPreparer.MetadataState == expected.state && slices.Contains(capability.LocalPreparer.Command, expected.flag) && !strings.Contains(strings.Join(capability.LocalPreparer.Command, " "), "prepare") {
				if project.ProjectID == "prometheus" && (!slices.Contains(capability.LocalPreparer.Command, "--scrape-config-complete") || !slices.Contains(capability.LocalPreparer.Command, "--scrape-config-precedence-resolved")) {
					t.Fatalf("Prometheus native route omits required declarations: %#v", capability.LocalPreparer.Command)
				}
				matched++
			}
		}
		if matched != 1 {
			t.Fatalf("incorrect native route metadata for %s: %#v", project.ProjectID, project.Capabilities)
		}
		delete(want, project.ProjectID)
	}
	if len(want) != 0 {
		t.Fatalf("missing native route metadata: %#v", want)
	}
}

func TestSupportInventory_PrometheusNamedAndCNCFRuleCapabilitiesCoexist(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Kind string `json:"kind"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "prometheus" {
			continue
		}
		seen := map[string]bool{}
		for _, capability := range project.Capabilities {
			seen[capability.Kind] = true
		}
		if !seen["embedded_cncf_source_rule"] || !seen["named_local_check"] || len(project.Capabilities) != 2 {
			t.Fatalf("Prometheus capability union = %#v", project.Capabilities)
		}
		return
	}
	t.Fatal("Prometheus inventory entry missing")
}

func TestSupportInventory_CephUsesSelectedCurrentMetadata(t *testing.T) {
	cfg, _ := repositoryConfig(t)
	raw, _, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Projects []struct {
			ProjectID    string `json:"projectID"`
			Capabilities []struct {
				Rules []struct {
					Limit string `json:"limit"`
				} `json:"rules"`
				LocalPreparer struct {
					Command       []string `json:"command"`
					MetadataState string   `json:"metadataState"`
					Limit         string   `json:"limit"`
				} `json:"localPreparer"`
			} `json:"capabilities"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, project := range document.Projects {
		if project.ProjectID != "ceph" {
			continue
		}
		if len(project.Capabilities) != 1 || len(project.Capabilities[0].Rules) != 1 || project.Capabilities[0].LocalPreparer.MetadataState != "implemented_native_selected_current_osd_metadata_minimizer" || !slices.Contains(project.Capabilities[0].LocalPreparer.Command, "prepare") || !strings.Contains(project.Capabilities[0].Rules[0].Limit, "current-backend") || !strings.Contains(project.Capabilities[0].LocalPreparer.Limit, "selected current OSD") {
			t.Fatalf("incorrect Ceph inventory metadata: %#v", project.Capabilities)
		}
		return
	}
	t.Fatal("Ceph inventory entry missing")
}

func TestSupportInventory_Generate_MatchesAcceptedInventory(t *testing.T) {
	cfg, root := repositoryConfig(t)
	jsonOutput, markdownOutput, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := os.ReadFile(filepath.Join(root, "docs/generated/community-support-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsonOutput, wantJSON) {
		t.Fatalf("generated JSON differs: got %d bytes want %d", len(jsonOutput), len(wantJSON))
	}
	wantMarkdown, err := os.ReadFile(filepath.Join(root, "docs/generated/community-support-inventory.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(string(wantMarkdown), "Generated by `scripts/generate_support_inventory.py`; do not edit by hand.", "Generated by `cmd/prufyx-maintainer`; do not edit by hand.", 1)
	if markdownOutput != want {
		t.Fatalf("generated Markdown differs: got %d bytes want %d", len(markdownOutput), len(want))
	}
}

func TestSupportInventory_DecodeStrict_RejectsDuplicateFields(t *testing.T) {
	if _, err := decodeStrict([]byte(`{"schema":"one","schema":"two"}`)); err == nil {
		t.Fatal("expected duplicate field rejection")
	}
}

func TestSupportInventory_PreparerProjects_ReadsCallableDispatchOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cncf_prepare.go")
	raw := "package communityapp\nfunc prepare(project *string, raw []byte) {\n\tswitch *project {\n\tcase \"validation-only\":\n\t}\n\tvar prepared cncfprepare.Prepared\n\tswitch *project {\n\tcase \"callable\", \"grouped\":\n\t\tprepared, err = cncfprepare.PrepareCallable(raw)\n\t}\n}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	projects, err := preparerProjects(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 || !projects["callable"] || !projects["grouped"] {
		t.Fatalf("unexpected projects: %#v", projects)
	}
}

func TestSupportInventory_ConformanceProfile_RejectsMalformedRuleWithoutPanic(t *testing.T) {
	profile := map[string]any{"rules": []any{"not-an-object"}}
	if err := requireSingleRule(profile, "expected"); err == nil {
		t.Fatal("expected malformed rule rejection")
	}
}
