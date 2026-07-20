package stuncheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oneclickvirt/gostun/model"
	"github.com/pion/stun/v2"
)

// CapabilityStatus is used for capabilities and for the overall outcome of a
// probe.  In particular, timeout is distinct from a server that does not
// implement the requested STUN attribute (unsupported).
type CapabilityStatus string

const (
	CapabilityAvailable   CapabilityStatus = "available"
	CapabilityUnavailable CapabilityStatus = "unavailable"
	CapabilityUnsupported CapabilityStatus = "unsupported"
	CapabilityTimeout     CapabilityStatus = "timeout"
	CapabilityError       CapabilityStatus = "error"
)

var (
	errSTUNUnsupported    = errors.New("stun server does not provide a mapped address")
	errSTUNHairpinTimeout = errors.New("stun hairpin timeout")
)

type NATReport struct {
	SchemaVersion     string           `json:"schema_version"`
	IPVersion         string           `json:"ip_version"`
	Server            string           `json:"server,omitempty"`
	Status            CapabilityStatus `json:"status"`
	NATType           string           `json:"nat_type"`
	MappingBehavior   string           `json:"mapping_behavior"`
	FilteringBehavior string           `json:"filtering_behavior"`
	LocalAddress      string           `json:"local_address,omitempty"`
	MappedAddress     string           `json:"mapped_address,omitempty"`
	PortPreservation  CapabilityStatus `json:"port_preservation"`
	Hairpin           CapabilityStatus `json:"hairpin"`
	ElapsedMillis     int64            `json:"elapsed_ms,omitempty"`
	Error             string           `json:"error,omitempty"`
}

// ProbeConfig controls a multi-server binding/hairpin probe. Servers are
// tried in stable order. IPVersion accepts ipv4, ipv6, or both; for hostname
// servers, both creates one attempt for each address family.
type ProbeConfig struct {
	Servers       []string
	IPVersion     string
	Timeout       time.Duration
	MaxConcurrent int
}

// NATSummary is the deterministic, cross-server view of a ProbeNAT run.
// Consistency fields describe only successful binding responses; no response
// is represented as unsupported, timeout, or error instead of being omitted.
type NATSummary struct {
	SchemaVersion               string           `json:"schema_version"`
	IPVersion                   string           `json:"ip_version"`
	Status                      CapabilityStatus `json:"status"`
	Partial                     bool             `json:"partial"`
	Results                     []NATReport      `json:"results"`
	Successful                  int              `json:"successful"`
	Failed                      int              `json:"failed"`
	MappedAddresses             []string         `json:"mapped_addresses,omitempty"`
	MappedIPs                   []string         `json:"mapped_ips,omitempty"`
	MappingConsistency          CapabilityStatus `json:"mapping_consistency"`
	MappedEndpointConsistency   CapabilityStatus `json:"mapped_endpoint_consistency"`
	PortPreservationConsistency CapabilityStatus `json:"port_preservation_consistency"`
	HairpinConsistency          CapabilityStatus `json:"hairpin_consistency"`
	Error                       string           `json:"error,omitempty"`
}

// BuildNATReport converts the RFC discovery results into a stable API shape.
// Hairpin is supplied by a dedicated probe; unsupported is explicit rather
// than inferred from the mapping/filtering classification.
func BuildNATReport(server, localAddress, mappedAddress string, hairpin CapabilityStatus, probeErr error) NATReport {
	report := NATReport{
		SchemaVersion: "goecs.stun/v1", IPVersion: model.IPVersion, Server: server,
		Status: CapabilityAvailable, NATType: CheckType(), MappingBehavior: model.NatMappingBehavior,
		FilteringBehavior: model.NatFilteringBehavior, LocalAddress: localAddress,
		MappedAddress: mappedAddress, Hairpin: hairpin, PortPreservation: CapabilityUnsupported,
	}
	if report.Hairpin == "" {
		report.Hairpin = CapabilityUnsupported
	}
	if localPort, ok := addressPort(localAddress); ok {
		if mappedPort, mappedOK := addressPort(mappedAddress); mappedOK {
			if localPort == mappedPort {
				report.PortPreservation = CapabilityAvailable
			} else {
				report.PortPreservation = CapabilityUnavailable
			}
		}
	}
	if probeErr != nil {
		report.Status = classifyProbeError(probeErr)
		report.Error = probeErr.Error()
		if report.MappingBehavior == "" && report.FilteringBehavior == "" {
			report.PortPreservation = report.Status
		}
	}
	return report
}

func addressPort(address string) (int, bool) {
	_, rawPort, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return 0, false
	}
	port, err := net.LookupPort("udp", rawPort)
	return port, err == nil
}

// ProbeBindingAndHairpin performs a standard STUN binding followed by a UDP
// hairpin loopback attempt on the same socket. It uses the legacy global
// model settings; new callers should prefer ProbeNAT with ProbeConfig.
func ProbeBindingAndHairpin(ctx context.Context, server string) (localAddress, mappedAddress string, hairpin CapabilityStatus, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	family := model.IPVersion
	if family == "both" {
		family = getCurrentProtocol(server)
	}
	timeout := time.Duration(model.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return probeBindingAndHairpin(ctx, server, family, timeout)
}

// ProbeNAT probes every configured STUN endpoint and returns a stable
// cross-server summary. It is safe for concurrent use and does not mutate the
// package-level model variables used by the legacy RFC APIs.
func ProbeNAT(ctx context.Context, config ProbeConfig) NATSummary {
	if ctx == nil {
		ctx = context.Background()
	}
	family, err := normalizeIPVersion(config.IPVersion)
	if err != nil {
		return NATSummary{
			SchemaVersion: "goecs.stun/v1", IPVersion: config.IPVersion,
			Status: CapabilityUnsupported, Error: err.Error(),
			MappingConsistency:          CapabilityUnsupported,
			MappedEndpointConsistency:   CapabilityUnsupported,
			PortPreservationConsistency: CapabilityUnsupported,
			HairpinConsistency:          CapabilityUnsupported,
		}
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = time.Duration(model.Timeout) * time.Second
		if timeout <= 0 {
			timeout = 3 * time.Second
		}
	}
	servers := append([]string(nil), config.Servers...)
	if len(servers) == 0 {
		servers = model.GetDefaultServers(family)
	}
	attempts := expandAttempts(servers, family)
	summary := NATSummary{
		SchemaVersion: "goecs.stun/v1", IPVersion: family,
		MappingConsistency:          CapabilityUnsupported,
		MappedEndpointConsistency:   CapabilityUnsupported,
		PortPreservationConsistency: CapabilityUnsupported,
		HairpinConsistency:          CapabilityUnsupported,
		Results:                     make([]NATReport, len(attempts)),
	}
	if len(attempts) == 0 {
		summary.Status = CapabilityUnsupported
		summary.Error = "no STUN servers configured for the requested IP version"
		return summary
	}
	workers := config.MaxConcurrent
	if workers <= 0 || workers > len(attempts) {
		workers = len(attempts)
		if workers > 4 {
			workers = 4
		}
	}
	type indexedAttempt struct {
		index  int
		server string
		family string
	}
	jobs := make(chan indexedAttempt, len(attempts))
	for index, attempt := range attempts {
		jobs <- indexedAttempt{index: index, server: attempt.server, family: attempt.family}
	}
	close(jobs)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					summary.Results[job.index] = canceledReport(job.server, job.family, ctx.Err())
					continue
				}
				summary.Results[job.index] = probeOne(ctx, job.server, job.family, timeout)
			}
		}()
	}
	wg.Wait()
	return finalizeSummary(summary)
}

// ProbeServers is an explicit alias for callers that prefer the operation
// name over the NAT terminology.
func ProbeServers(ctx context.Context, config ProbeConfig) NATSummary {
	return ProbeNAT(ctx, config)
}

type serverAttempt struct {
	server string
	family string
}

func normalizeIPVersion(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(model.IPVersion))
	}
	switch value {
	case "ipv4", "ipv6", "both":
		return value, nil
	default:
		return "", fmt.Errorf("unsupported IP version %q", value)
	}
}

func expandAttempts(servers []string, family string) []serverAttempt {
	seen := make(map[string]struct{}, len(servers))
	result := make([]serverAttempt, 0, len(servers))
	for _, raw := range servers {
		server := strings.TrimSpace(raw)
		if server == "" {
			continue
		}
		families := []string{family}
		if family == "both" {
			if literalFamily := literalServerFamily(server); literalFamily != "" {
				families = []string{literalFamily}
			} else {
				families = []string{"ipv4", "ipv6"}
			}
		}
		for _, current := range families {
			key := current + "\x00" + server
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, serverAttempt{server: server, family: current})
		}
	}
	return result
}

func literalServerFamily(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return ""
	}
	host = strings.Trim(host, "[]")
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if ip.To4() == nil {
		return "ipv6"
	}
	return "ipv4"
}

func probeOne(ctx context.Context, server, family string, timeout time.Duration) NATReport {
	started := time.Now()
	local, mapped, hairpin, hasOtherAddress, probeErr := probeBindingAndHairpinMetadata(ctx, server, family, timeout)
	report := NATReport{
		SchemaVersion: "goecs.stun/v1", IPVersion: family, Server: server,
		Status: CapabilityAvailable, NATType: "Inconclusive",
		MappingBehavior: "unsupported", FilteringBehavior: "unsupported",
		LocalAddress: local, MappedAddress: mapped, Hairpin: hairpin,
		PortPreservation: CapabilityUnsupported,
	}
	if localPort, ok := addressPort(local); ok {
		if mappedPort, mappedOK := addressPort(mapped); mappedOK {
			if localPort == mappedPort {
				report.PortPreservation = CapabilityAvailable
			} else {
				report.PortPreservation = CapabilityUnavailable
			}
		}
	}
	if probeErr != nil {
		report.Error = probeErr.Error()
		if !errors.Is(probeErr, errSTUNHairpinTimeout) || mapped == "" {
			report.Status = classifyProbeError(probeErr)
			if mapped == "" {
				report.PortPreservation = report.Status
			}
			report.ElapsedMillis = time.Since(started).Milliseconds()
			return report
		}
	}
	if !hasOtherAddress {
		report.ElapsedMillis = time.Since(started).Milliseconds()
		return report
	}
	behavior := probeRFC5780(ctx, server, family, timeout)
	report.MappingBehavior = behavior.mapping
	report.FilteringBehavior = behavior.filtering
	report.NATType = checkType(behavior.mapping, behavior.filtering)
	if behavior.err != nil && !errors.Is(behavior.err, errNoOtherAddress) && !errors.Is(behavior.err, errSTUNUnsupported) {
		behaviorStatus := classifyProbeError(behavior.err)
		if report.Status == CapabilityAvailable || behaviorStatus == CapabilityError {
			report.Status = behaviorStatus
		}
		behaviorError := fmt.Sprintf("RFC 5780 behavior probe: %v", behavior.err)
		if report.Error == "" {
			report.Error = behaviorError
		} else {
			report.Error += "; " + behaviorError
		}
	}
	report.ElapsedMillis = time.Since(started).Milliseconds()
	return report
}

func canceledReport(server, family string, err error) NATReport {
	status := classifyProbeError(err)
	return NATReport{
		SchemaVersion: "goecs.stun/v1", IPVersion: family, Server: server,
		Status: status, NATType: "Inconclusive", MappingBehavior: "unsupported",
		FilteringBehavior: "unsupported", PortPreservation: status, Hairpin: status,
		Error: err.Error(),
	}
}

func classifyProbeError(err error) CapabilityStatus {
	if err == nil {
		return CapabilityAvailable
	}
	if errors.Is(err, errSTUNUnsupported) {
		return CapabilityUnsupported
	}
	if errors.Is(err, errSTUNHairpinTimeout) {
		return CapabilityTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return CapabilityTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return CapabilityTimeout
	}
	return CapabilityError
}

func finalizeSummary(summary NATSummary) NATSummary {
	addresses := make(map[string]struct{})
	addressIPs := make(map[string]struct{})
	anyTimeout, anyUnsupported, anyError := false, false, false
	for _, report := range summary.Results {
		if report.Status == CapabilityAvailable {
			summary.Successful++
			if report.MappedAddress != "" {
				addresses[report.MappedAddress] = struct{}{}
				if host := addressHost(report.MappedAddress); host != "" {
					addressIPs[host] = struct{}{}
				}
			}
			continue
		}
		summary.Failed++
		switch report.Status {
		case CapabilityTimeout:
			anyTimeout = true
		case CapabilityUnsupported:
			anyUnsupported = true
		case CapabilityError:
			anyError = true
		}
	}
	for address := range addresses {
		summary.MappedAddresses = append(summary.MappedAddresses, address)
	}
	for address := range addressIPs {
		summary.MappedIPs = append(summary.MappedIPs, address)
	}
	sort.Strings(summary.MappedAddresses)
	sort.Strings(summary.MappedIPs)
	summary.MappingConsistency = mappedConsistency(summary.Results, false)
	summary.MappedEndpointConsistency = mappedConsistency(summary.Results, true)
	summary.PortPreservationConsistency = capabilityConsistency(summary.Results, func(r NATReport) CapabilityStatus { return r.PortPreservation })
	summary.HairpinConsistency = capabilityConsistency(summary.Results, func(r NATReport) CapabilityStatus { return r.Hairpin })
	switch {
	case summary.Successful > 0:
		summary.Status = CapabilityAvailable
	case anyTimeout:
		summary.Status = CapabilityTimeout
	case anyUnsupported && !anyError:
		summary.Status = CapabilityUnsupported
	case anyError:
		summary.Status = CapabilityError
	default:
		summary.Status = CapabilityUnavailable
	}
	summary.Partial = summary.Successful > 0 && summary.Failed > 0
	return summary
}

func mappedConsistency(results []NATReport, includePort bool) CapabilityStatus {
	var value string
	found := 0
	for _, report := range results {
		if report.Status != CapabilityAvailable || report.MappedAddress == "" {
			continue
		}
		current := report.MappedAddress
		if !includePort {
			current = addressHost(current)
		}
		if current == "" {
			continue
		}
		if found == 0 {
			value = current
			found++
			continue
		}
		found++
		if current != value {
			return CapabilityUnavailable
		}
	}
	if found == 0 {
		return consistencyFailureStatus(results)
	}
	if found == 1 {
		return CapabilityUnsupported
	}
	return CapabilityAvailable
}

func capabilityConsistency(results []NATReport, field func(NATReport) CapabilityStatus) CapabilityStatus {
	var value CapabilityStatus
	found := 0
	for _, report := range results {
		if report.Status != CapabilityAvailable {
			continue
		}
		current := field(report)
		if current == "" || current == CapabilityUnsupported || current == CapabilityTimeout || current == CapabilityError {
			continue
		}
		if found == 0 {
			value = current
			found++
			continue
		}
		found++
		if current != value {
			return CapabilityUnavailable
		}
	}
	if found == 0 {
		return consistencyFailureStatus(results)
	}
	if found == 1 {
		return CapabilityUnsupported
	}
	return CapabilityAvailable
}

func addressHost(address string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	return strings.Trim(host, "[]")
}

func consistencyFailureStatus(results []NATReport) CapabilityStatus {
	for _, report := range results {
		if report.Status == CapabilityTimeout {
			return CapabilityTimeout
		}
	}
	for _, report := range results {
		if report.Status == CapabilityError {
			return CapabilityError
		}
	}
	return CapabilityUnsupported
}

// probeBindingAndHairpin is the options-aware implementation used by both
// the legacy single-server API and ProbeNAT.
func probeBindingAndHairpin(ctx context.Context, server, family string, timeout time.Duration) (localAddress, mappedAddress string, hairpin CapabilityStatus, err error) {
	localAddress, mappedAddress, hairpin, _, err = probeBindingAndHairpinMetadata(ctx, server, family, timeout)
	return localAddress, mappedAddress, hairpin, err
}

func probeBindingAndHairpinMetadata(ctx context.Context, server, family string, timeout time.Duration) (localAddress, mappedAddress string, hairpin CapabilityStatus, hasOtherAddress bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", "", CapabilityTimeout, false, err
	}
	network := "udp4"
	if family == "ipv6" {
		network = "udp6"
	}
	remote, err := net.ResolveUDPAddr(network, server)
	if err != nil {
		return "", "", CapabilityError, false, err
	}
	local, err := getLocalAddrForInterface(network)
	if err != nil {
		return "", "", CapabilityError, false, err
	}
	conn, err := net.ListenUDP(network, local)
	if err != nil {
		return "", "", CapabilityError, false, err
	}
	defer conn.Close()
	stopWatch := watchContext(ctx, conn)
	defer stopWatch()
	localAddress = conn.LocalAddr().String()
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteToUDP(request.Raw, remote); err != nil {
		if ctx.Err() != nil {
			return localAddress, "", CapabilityTimeout, false, ctx.Err()
		}
		return localAddress, "", CapabilityError, false, err
	}
	buffer := make([]byte, 64<<10)
	read, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if ctx.Err() != nil {
			return localAddress, "", CapabilityTimeout, false, ctx.Err()
		}
		if isTimeoutError(err) {
			return localAddress, "", CapabilityTimeout, false, fmt.Errorf("stun binding timeout: %w", err)
		}
		return localAddress, "", CapabilityError, false, err
	}
	response := &stun.Message{Raw: append([]byte(nil), buffer[:read]...)}
	if err := response.Decode(); err != nil {
		return localAddress, "", CapabilityError, false, err
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil {
		return localAddress, "", CapabilityUnsupported, false, fmt.Errorf("%w: %v", errSTUNUnsupported, err)
	}
	var other stun.OtherAddress
	hasOtherAddress = other.GetFrom(response) == nil
	mappedUDP := &net.UDPAddr{IP: mapped.IP, Port: mapped.Port}
	mappedAddress = mappedUDP.String()
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return localAddress, mappedAddress, CapabilityError, hasOtherAddress, err
	}
	if _, err := conn.WriteToUDP(token, mappedUDP); err != nil {
		if ctx.Err() != nil {
			return localAddress, mappedAddress, CapabilityTimeout, hasOtherAddress, ctx.Err()
		}
		return localAddress, mappedAddress, CapabilityError, hasOtherAddress, err
	}
	for {
		read, _, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			if ctx.Err() != nil {
				return localAddress, mappedAddress, CapabilityTimeout, hasOtherAddress, ctx.Err()
			}
			if isTimeoutError(readErr) {
				return localAddress, mappedAddress, CapabilityTimeout, hasOtherAddress, errSTUNHairpinTimeout
			}
			return localAddress, mappedAddress, CapabilityError, hasOtherAddress, readErr
		}
		if bytes.Equal(buffer[:read], token) {
			return localAddress, mappedAddress, CapabilityAvailable, hasOtherAddress, nil
		}
	}
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func watchContext(ctx context.Context, conn *net.UDPConn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}
