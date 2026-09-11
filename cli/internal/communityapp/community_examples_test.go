package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCommunityExampleRunsNativeSyntheticCNCFJourneys(t *testing.T) {

	if _, err := (runtime{}).runEtcdExample(); err != nil {
		t.Fatalf("direct etcd example: %v", err)
	}
	for _, example := range []string{"cncf-etcd", "cncf-opentelemetry", "knowledge-cert-manager", "knowledge-cncf"} {
		t.Run(example, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"community-preview", "example", example}, &stdout, &stderr, "test")
			if code != ExitOK || stderr.Len() != 0 {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr.String(), stdout.String())
			}
			if strings.Contains(stdout.String(), "synthetic-private-node") || !json.Valid(stdout.Bytes()) {
				t.Fatalf("private example data crossed output: %s", stdout.String())
			}
			var envelope struct {
				Data communityExampleResult `json:"data"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Data.Example != example || envelope.Data.Aggregate != "UNKNOWN" || envelope.Data.NetworkUsed || envelope.Data.ClusterUsed || envelope.Data.PrivateRetained || envelope.Data.RuntimeObserved || envelope.Data.ProcessExecuted || !envelope.Data.ScopedClaimOnly {
				t.Fatalf("result=%#v", envelope.Data)
			}
			if envelope.Data.BlockedExit != ExitBlocked || envelope.Data.UnknownExit != ExitUnknown || (example == "cncf-opentelemetry" && envelope.Data.CleanExit != ExitOK) {
				t.Fatalf("exit result=%#v", envelope.Data)
			}
		})
	}
}

func TestCommunityExampleRejectsUnknownName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"community-preview", "example", "unknown"}, &stdout, &stderr, "test"); code != ExitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
