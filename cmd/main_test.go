package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/oneclickvirt/gostun/stuncheck"
)

func TestMain(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"gostun", "-h"}
	defer func() { os.Args = oldArgs }()
	main()
}

func TestNormalizeBoolArgsSupportsStructuredFlags(t *testing.T) {
	got := normalizeBoolArgs([]string{"-json", "false", "-structured", "true"})
	if len(got) != 2 || got[0] != "-json=false" || got[1] != "-structured=true" {
		t.Fatalf("unexpected normalized args: %#v", got)
	}
}

func TestWriteStructuredSummaryEmitsJSONAndForwardsConfig(t *testing.T) {
	var output bytes.Buffer
	want := stuncheck.ProbeConfig{IPVersion: "ipv6", Timeout: 2 * time.Second, MaxConcurrent: 3, Servers: []string{"fixture:3478"}}
	var got stuncheck.ProbeConfig
	err := writeStructuredSummary(context.Background(), &output, want, func(_ context.Context, config stuncheck.ProbeConfig) stuncheck.NATSummary {
		got = config
		return stuncheck.NATSummary{SchemaVersion: "goecs.stun/v1", IPVersion: config.IPVersion, Status: stuncheck.CapabilityUnsupported, Results: []stuncheck.NATReport{}}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.IPVersion != want.IPVersion || got.Timeout != want.Timeout || got.MaxConcurrent != want.MaxConcurrent || len(got.Servers) != 1 {
		t.Fatalf("structured config not forwarded: got=%+v want=%+v", got, want)
	}
	var summary stuncheck.NATSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || summary.SchemaVersion != "goecs.stun/v1" {
		t.Fatalf("invalid structured JSON: err=%v output=%q", err, output.String())
	}
}
