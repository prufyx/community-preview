package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx-cli/internal/currentbundle"
	"github.com/prufyx/prufyx-cli/internal/observation"
)

func TestOfflineCollectorOutputsImportIntoCurrentBundle(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		args []string
	}{
		{name: "default-typed-public-images", mode: "pod-private-images"},
		{name: "producer-v3", mode: "component-v3-prom", args: []string{"--include-component-configuration", "--component-configuration-profile", "v3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliRoot, err := filepath.Abs(filepath.Join("..", ".."))
			if err != nil {
				t.Fatal(err)
			}
			work := t.TempDir()
			bin := filepath.Join(work, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			fake, err := os.ReadFile(filepath.Join(cliRoot, "scripts", "testdata", "fake-kubectl.sh"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "kubectl"), fake, 0700); err != nil {
				t.Fatal(err)
			}
			kubeconfig := filepath.Join(work, "kubeconfig")
			if err := os.WriteFile(kubeconfig, []byte("synthetic kubeconfig\n"), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(work, "output")
			args := []string{output, "--kubeconfig", kubeconfig, "--acknowledge-kubeconfig-exec-risk", "--allow-partial", "--exec-env", "FAKE_KUBECTL_MODE"}
			args = append(args, tc.args...)
			args = append(args, "synthetic-context")
			commandArgs := append([]string{filepath.Join(cliRoot, "scripts", "kubeconfig-api-snapshot.sh")}, args...)
			command := exec.Command("bash", commandArgs...)
			command.Env = collectorIntegrationEnvironment(bin, tc.mode)
			if raw, err := command.CombinedOutput(); err != nil {
				t.Fatalf("offline collector: %v\n%s", err, raw)
			}
			children, err := os.ReadDir(output)
			if err != nil || len(children) != 1 {
				t.Fatalf("output inventory: %v %v", children, err)
			}
			rootPath := filepath.Join(output, children[0].Name())
			assertCollectorTreeOmitsPrivateCanaries(t, rootPath)
			root, err := observation.OpenPath(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := currentbundle.BuildObservation(context.Background(), root, currentbundle.Options{})
			closeErr := root.Close()
			if err != nil {
				t.Fatalf("build current bundle: %v", err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			raw, err := json.Marshal(artifact.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"pkg:oci/prometheus/prometheus", `"value":"2.55.1"`} {
				if !bytes.Contains(raw, []byte(required)) {
					t.Fatalf("current bundle missing %q: %s", required, raw)
				}
			}
			if tc.name == "producer-v3" {
				for _, required := range []string{`"predicateRegistryVersion":"v2"`, `"version":"current-bundle-v3"`, `"id":"component.prometheus.agent_mode"`, `"value":true`} {
					if !bytes.Contains(raw, []byte(required)) {
						t.Fatalf("v3 current bundle missing %q: %s", required, raw)
					}
				}
			}
		})
	}
}

func collectorIntegrationEnvironment(bin, mode string) []string {
	environment := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.TempDir(),
		"FAKE_KUBECTL_MODE=" + mode,
	}
	if user := os.Getenv("USER"); user != "" {
		environment = append(environment, "USER="+user)
	}
	return environment
}

func assertCollectorTreeOmitsPrivateCanaries(t *testing.T, root string) {
	t.Helper()
	forbidden := [][]byte{
		[]byte("private.invalid"),
		[]byte("PRIVATE_OBJECT_NAME_NEVER_RETAIN"),
		[]byte("PRIVATE_COMMAND_NEVER_RETAIN"),
		[]byte("PRIVATE_ENV_NEVER_RETAIN"),
		[]byte("PRIVATE_TAG_CANARY"),
		[]byte("PRIVATE_CONTROL_CANARY"),
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, canary := range forbidden {
			if bytes.Contains(raw, canary) {
				t.Fatalf("collector retained private canary in %s", filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
