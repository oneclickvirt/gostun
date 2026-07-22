package stuncheck

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/oneclickvirt/gostun/model"
	"github.com/pion/stun/v2"
)

func TestBuildNATReportPortPreservation(t *testing.T) {
	originalMapping, originalFiltering, originalVersion := model.NatMappingBehavior, model.NatFilteringBehavior, model.IPVersion
	defer func() {
		model.NatMappingBehavior, model.NatFilteringBehavior, model.IPVersion = originalMapping, originalFiltering, originalVersion
	}()
	model.NatMappingBehavior = "endpoint independent"
	model.NatFilteringBehavior = "address dependent"
	model.IPVersion = "ipv4"
	report := BuildNATReport("stun.example:3478", "192.0.2.1:12345", "198.51.100.1:12345", CapabilityAvailable, nil)
	if report.PortPreservation != CapabilityAvailable || report.Hairpin != CapabilityAvailable || report.NATType != "Restricted Cone" {
		t.Fatalf("unexpected report: %+v", report)
	}
	report = BuildNATReport("", "[2001:db8::1]:12345", "[2001:db8::2]:54321", "", nil)
	if report.PortPreservation != CapabilityUnavailable || report.Hairpin != CapabilityUnsupported {
		t.Fatalf("unexpected IPv6 report: %+v", report)
	}
}

func TestProbeBindingAndHairpinLocalFixture(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 2048)
		read, client, readErr := server.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:read]...)}
		if request.Decode() != nil {
			return
		}
		response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: client.IP, Port: client.Port})
		_, _ = server.WriteToUDP(response.Raw, client)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	local, mapped, hairpin, err := ProbeBindingAndHairpin(ctx, server.LocalAddr().String())
	if err != nil || local == "" || mapped == "" || hairpin != CapabilityAvailable {
		t.Fatalf("local=%q mapped=%q hairpin=%q err=%v", local, mapped, hairpin, err)
	}
}

func TestProbeNATMultiServerSummary(t *testing.T) {
	first := startSTUNFixture(t, true, true)
	second := startSTUNFixture(t, true, true)
	summary := ProbeNAT(context.Background(), ProbeConfig{
		Servers: []string{first, second, first}, IPVersion: "ipv4",
		Timeout: time.Second, MaxConcurrent: 2,
	})
	if summary.Status != CapabilityAvailable || summary.Successful != 2 || summary.Failed != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(summary.Results) != 2 {
		t.Fatalf("deduplication failed, got %d results", len(summary.Results))
	}
	if summary.PortPreservationConsistency != CapabilityAvailable || summary.HairpinConsistency != CapabilityAvailable {
		t.Fatalf("unexpected capability consistency: %+v", summary)
	}
	if summary.MappingConsistency != CapabilityAvailable || summary.MappedEndpointConsistency != CapabilityUnavailable {
		t.Fatalf("public IP should agree while per-socket endpoints differ: %+v", summary)
	}
	for _, report := range summary.Results {
		if report.IPVersion != "ipv4" || report.Status != CapabilityAvailable || report.Hairpin != CapabilityAvailable {
			t.Fatalf("unexpected report: %+v", report)
		}
	}
}

func TestMappedConsistencySeparatesIPAndEndpoint(t *testing.T) {
	reports := []NATReport{
		{Status: CapabilityAvailable, MappedAddress: "198.51.100.7:10000"},
		{Status: CapabilityAvailable, MappedAddress: "198.51.100.7:20000"},
	}
	if mappedConsistency(reports, false) != CapabilityAvailable || mappedConsistency(reports, true) != CapabilityUnavailable {
		t.Fatalf("unexpected consistency for same public IP: %+v", reports)
	}
	reports[1].MappedAddress = "[2001:db8::2]:20000"
	if mappedConsistency(reports, false) != CapabilityUnavailable {
		t.Fatalf("different public IPs must be inconsistent: %+v", reports)
	}
}

func TestProbeNATExplicitTimeout(t *testing.T) {
	server := startSTUNFixture(t, false, false)
	started := time.Now()
	summary := ProbeServers(context.Background(), ProbeConfig{
		Servers: []string{server}, IPVersion: "ipv4", Timeout: 30 * time.Millisecond,
	})
	if summary.Status != CapabilityTimeout || summary.Failed != 1 {
		t.Fatalf("expected explicit timeout: %+v", summary)
	}
	if summary.Results[0].Status != CapabilityTimeout || summary.Results[0].Hairpin != CapabilityTimeout {
		t.Fatalf("expected timeout report: %+v", summary.Results[0])
	}
	if time.Since(started) > time.Second {
		t.Fatalf("timeout was not bounded: %s", time.Since(started))
	}
}

func TestProbeNATHairpinTimeoutKeepsSuccessfulBindingAvailable(t *testing.T) {
	server := startSTUNFixtureWithMappedPort(t, true, true, 1)
	summary := ProbeNAT(context.Background(), ProbeConfig{
		Servers: []string{server}, IPVersion: "ipv4", Timeout: 30 * time.Millisecond,
	})
	if summary.Status != CapabilityAvailable || summary.Successful != 1 || summary.Results[0].Status != CapabilityAvailable || summary.Results[0].Hairpin != CapabilityTimeout {
		t.Fatalf("hairpin timeout incorrectly erased successful binding: %+v", summary)
	}
}

func TestProbeNATExplicitUnsupported(t *testing.T) {
	server := startSTUNFixture(t, true, false)
	summary := ProbeNAT(context.Background(), ProbeConfig{
		Servers: []string{server}, IPVersion: "ipv4", Timeout: time.Second,
	})
	if summary.Status != CapabilityUnsupported || summary.Results[0].Status != CapabilityUnsupported {
		t.Fatalf("expected unsupported result: %+v", summary)
	}
	if summary.Results[0].Error != "unsupported" {
		t.Fatalf("unexpected unsupported error: %q", summary.Results[0].Error)
	}
}

func TestBuildNATReportDoesNotExposeRawProbeError(t *testing.T) {
	report := BuildNATReport("fixture:3478", "", "", CapabilityError, fmt.Errorf("dial https://private.example/probe?key=secret from /private/path"))
	if report.Error != "probe_failed" {
		t.Fatalf("raw probe error was retained: %+v", report)
	}
}

func TestProbeNATCanceledContext(t *testing.T) {
	server := startSTUNFixture(t, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	summary := ProbeNAT(ctx, ProbeConfig{
		Servers: []string{server}, IPVersion: "ipv4", Timeout: time.Second,
	})
	if summary.Status != CapabilityTimeout || summary.Results[0].Status != CapabilityTimeout {
		t.Fatalf("expected canceled probe to be explicit: %+v", summary)
	}
}

func TestExpandAttemptsBothFamilies(t *testing.T) {
	attempts := expandAttempts([]string{"127.0.0.1:3478", "[::1]:3478", "[fe80::1%lo0]:3478", "stun.example:3478", "stun.example:3478"}, "both")
	if len(attempts) != 5 {
		t.Fatalf("unexpected attempts: %+v", attempts)
	}
	if attempts[0].family != "ipv4" || attempts[1].family != "ipv6" || attempts[2].family != "ipv6" || attempts[3].family != "ipv4" || attempts[4].family != "ipv6" {
		t.Fatalf("unexpected family selection: %+v", attempts)
	}
}

func TestProbeNATIPv6Fixture(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 2048)
		read, client, readErr := server.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:read]...)}
		if request.Decode() != nil {
			return
		}
		response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
			&stun.XORMappedAddress{IP: client.IP, Port: client.Port})
		_, _ = server.WriteToUDP(response.Raw, client)
	}()
	summary := ProbeNAT(context.Background(), ProbeConfig{
		Servers: []string{server.LocalAddr().String()}, IPVersion: "ipv6", Timeout: time.Second,
	})
	if summary.Status != CapabilityAvailable || summary.Results[0].IPVersion != "ipv6" {
		t.Fatalf("unexpected IPv6 summary: %+v", summary)
	}
}

func TestProbeNATInvalidIPVersion(t *testing.T) {
	summary := ProbeNAT(context.Background(), ProbeConfig{IPVersion: "ipx"})
	if summary.Status != CapabilityUnsupported || summary.Error == "" {
		t.Fatalf("expected unsupported IP version: %+v", summary)
	}
}

func startSTUNFixture(t *testing.T, respond, includeMapped bool) string {
	return startSTUNFixtureWithMappedPort(t, respond, includeMapped, 0)
}

func startSTUNFixtureWithMappedPort(t *testing.T, respond, includeMapped bool, mappedPort int) string {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			read, client, readErr := server.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if !respond {
				continue
			}
			request := &stun.Message{Raw: append([]byte(nil), buffer[:read]...)}
			if request.Decode() != nil {
				continue
			}
			attributes := []stun.Setter{stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess}
			if includeMapped {
				if mappedPort == 0 {
					mappedPort = client.Port
				}
				attributes = append(attributes, &stun.XORMappedAddress{IP: client.IP, Port: mappedPort})
			}
			response := stun.MustBuild(attributes...)
			_, _ = server.WriteToUDP(response.Raw, client)
		}
	}()
	return server.LocalAddr().String()
}
