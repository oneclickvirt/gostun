package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/oneclickvirt/gostun/model"
	"github.com/oneclickvirt/gostun/stuncheck"
)

func TestMain(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"gostun", "-h"}
	defer func() { os.Args = oldArgs }()
	main()
}

func TestValidateCLIOptionsRejectsInvalidOrIgnoredValues(t *testing.T) {
	originalType, originalTimeout, originalVerbose := model.IPVersion, model.Timeout, model.Verbose
	originalServer, originalInterface := model.AddrStr, model.Interface
	defer func() {
		model.IPVersion, model.Timeout, model.Verbose = originalType, originalTimeout, originalVerbose
		model.AddrStr, model.Interface = originalServer, originalInterface
	}()
	setDefaults := func() {
		model.IPVersion, model.Timeout, model.Verbose = "ipv4", 3, 0
		model.AddrStr, model.Interface = "stun.example:3478", ""
	}
	setDefaults()
	if err := validateCLIOptions(nil, true, 2, map[string]bool{"concurrency": true, "server": true}); err != nil {
		t.Fatalf("valid structured options failed: %v", err)
	}
	tests := []func() error{
		func() error { setDefaults(); model.IPVersion = "ipx"; return validateCLIOptions(nil, true, 0, nil) },
		func() error { setDefaults(); model.Timeout = 0; return validateCLIOptions(nil, false, 0, nil) },
		func() error { setDefaults(); model.Verbose = 4; return validateCLIOptions(nil, false, 0, nil) },
		func() error {
			setDefaults()
			return validateCLIOptions(nil, false, 2, map[string]bool{"concurrency": true})
		},
		func() error {
			setDefaults()
			return validateCLIOptions(nil, true, 0, map[string]bool{"concurrency": true})
		},
		func() error { setDefaults(); return validateCLIOptions(nil, true, 0, map[string]bool{"e": true}) },
		func() error {
			setDefaults()
			model.AddrStr = "https://private.example/key"
			return validateCLIOptions(nil, true, 0, map[string]bool{"server": true})
		},
		func() error { setDefaults(); return validateCLIOptions([]string{"extra"}, false, 0, nil) },
	}
	for index, run := range tests {
		if err := run(); err == nil {
			t.Fatalf("invalid case %d was accepted", index)
		}
	}
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
