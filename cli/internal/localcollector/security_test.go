package localcollector

import (
	"strings"
	"testing"
)

func TestCollectorEnvironmentRequiresExplicitProxy(t *testing.T) {
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	t.Setenv("HTTPS_PROXY", "http://private.invalid")
	if _, err := collectorEnvironment("/private/kubeconfig", nil); err == nil {
		t.Fatal("ambient proxy accepted without explicit forwarding")
	}
	env, err := collectorEnvironment("/private/kubeconfig", proxyEnvironmentNames)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "HTTPS_PROXY=http://private.invalid") {
		t.Fatal("selected proxy missing")
	}
}

func TestCollectorEnvironmentRejectsLoaderAndPythonVariables(t *testing.T) {
	for _, name := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "BASH_ENV", "PATH"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "private")
			if _, err := collectorEnvironment("/private/kubeconfig", []string{name}); err == nil {
				t.Fatalf("controlled environment %s accepted", name)
			}
		})
	}
}

func TestContextDigestIsRunScopedAndDoesNotEchoName(t *testing.T) {
	t.Parallel()
	a := contextDigest([]byte(strings.Repeat("a", 32)), "private-context")
	b := contextDigest([]byte(strings.Repeat("b", 32)), "private-context")
	if a == b || strings.Contains(a, "private") || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("unexpected context digests %q %q", a, b)
	}
}
