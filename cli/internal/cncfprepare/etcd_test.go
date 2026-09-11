package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx-cli/internal/cncfcheck"
)

func etcdArguments(t *testing.T, declared bool, argv ...string) []byte {
	t.Helper()
	return []byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":` + map[bool]string{true: "true", false: "false"}[declared] + `,"argv":[` + quoteStrings(argv) + `]}`)
}

func quoteStrings(values []string) string {
	var b strings.Builder
	for i, value := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		encoded, _ := json.Marshal(value)
		b.Write(encoded)
	}
	return b.String()
}

func TestPrepareEtcdRemovedOptionAtoms(t *testing.T) {
	cases := []string{
		"--enable-v2=false", "--experimental-enable-v2v3=legacy", "--proxy=off",
		"--proxy-failure-wait=0", "--proxy-refresh-interval=1000", "--proxy-dial-timeout=10",
		"--proxy-write-timeout=20", "--proxy-read-timeout=30",
	}
	for _, atom := range cases {
		t.Run(atom, func(t *testing.T) {
			prepared, err := PrepareEtcd(etcdArguments(t, true, "--name=node", atom), EtcdFrom, EtcdTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonEtcdArgvWitness {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			facts := preparedFacts(t, prepared)
			fact := facts[EtcdFact]
			if fact["state"] != "declared" || fact["boolValue"] != true {
				t.Fatalf("fact=%v", fact)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), atom) || strings.Contains(string(prepared.CanonicalInputJSON), "node") {
				t.Fatal("raw argv escaped minimized declaration")
			}
			if report, err := cncfcheck.Check("etcd", prepared.CanonicalInputJSON, mustTime("2026-09-10T00:00:00Z")); err != nil || report.Check.Claims[0].Status != "BLOCKED" {
				t.Fatalf("check report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareEtcdUnknownBoundariesNeverDeclareFalse(t *testing.T) {
	cases := []struct {
		name string
		argv []string
	}{
		{"missing authority", []string{"--enable-v2=true"}},
		{"empty vector", nil},
		{"target free known atom", []string{"--name=node"}},
		{"unknown separated preceding flag", []string{"--initial-cluster", "--enable-v2=true"}},
		{"unknown equals flag", []string{"--not-registered=x", "--enable-v2=true"}},
		{"separated target", []string{"--enable-v2", "false"}},
		{"sentinel", []string{"--", "--enable-v2=true"}},
		{"positional", []string{"etcd", "--enable-v2=true"}},
		{"single dash", []string{"-enable-v2=true"}},
		{"config file", []string{"--config-file=/private/config", "--enable-v2=true"}},
		{"substitution", []string{"--enable-v2=$VALUE"}},
		{"duplicate", []string{"--enable-v2=true", "--enable-v2=false"}},
		{"bad bool", []string{"--enable-v2=1"}},
		{"bad enum", []string{"--proxy=maybe"}},
		{"bad uint", []string{"--proxy-read-timeout=-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			declared := tc.name != "missing authority"
			prepared, err := PrepareEtcd(etcdArguments(t, declared, tc.argv...), EtcdFrom, EtcdTo)
			if err != nil || prepared.State != StateUnknown || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`) {
				t.Fatalf("prepared=%+v err=%v input=%s", prepared, err, prepared.CanonicalInputJSON)
			}
		})
	}

	raw := []byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","argv":["--enable-v2=true"]}`)
	prepared, err := PrepareEtcd(raw, EtcdFrom, EtcdTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonEtcdAuthorityMissing {
		t.Fatalf("missing declaration prepared=%+v err=%v", prepared, err)
	}
}

func TestPrepareEtcdExactPairAndInputSchema(t *testing.T) {
	prepared, err := PrepareEtcd(etcdArguments(t, true, "--enable-v2=true"), "3.5.16", EtcdTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonEtcdUnsupportedPair {
		t.Fatalf("unsupported pair prepared=%+v err=%v", prepared, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":true,"argv":[1]}`),
		[]byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":true,"argv":[],"extra":true}`),
		[]byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":true,"argv":[]}{}`),
	} {
		if _, err := PrepareEtcd(raw, EtcdFrom, EtcdTo); err == nil {
			t.Fatalf("invalid input accepted: %s", raw)
		}
	}
}

func mustTime(value string) (result time.Time) {
	result, _ = time.Parse(time.RFC3339, value)
	return
}
