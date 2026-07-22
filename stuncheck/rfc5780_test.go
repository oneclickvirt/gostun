package stuncheck

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/oneclickvirt/gostun/model"
	"github.com/pion/stun/v2"
)

type fixtureBehavior string

const (
	fixtureEndpointIndependent     fixtureBehavior = "endpoint independent"
	fixtureAddressDependent        fixtureBehavior = "address dependent"
	fixtureAddressAndPortDependent fixtureBehavior = "address and port dependent"
)

type fixtureEndpoint struct {
	conn      *net.UDPConn
	ipIndex   int
	portIndex int
}

type rfc5780Fixture struct {
	primary           string
	other             *net.UDPAddr
	endpoints         []fixtureEndpoint
	mappingBehavior   fixtureBehavior
	filteringBehavior fixtureBehavior
	includeOther      bool
	closeOnce         sync.Once
	wg                sync.WaitGroup
	sequential        bool
	sequenceMu        sync.Mutex
	sequenceByClient  map[string]int
}

func TestProbeNATRFC5780BehaviorMatrix(t *testing.T) {
	tests := []struct {
		name      string
		mapping   fixtureBehavior
		filtering fixtureBehavior
	}{
		{name: "endpoint-independent", mapping: fixtureEndpointIndependent, filtering: fixtureEndpointIndependent},
		{name: "address-dependent", mapping: fixtureAddressDependent, filtering: fixtureAddressDependent},
		{name: "address-and-port-dependent", mapping: fixtureAddressAndPortDependent, filtering: fixtureAddressAndPortDependent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := startRFC5780Fixture(t, test.mapping, test.filtering, true)
			summary := ProbeNAT(context.Background(), ProbeConfig{
				Servers: []string{fixture.primary}, IPVersion: "ipv4", Timeout: 30 * time.Millisecond,
			})
			if len(summary.Results) != 1 {
				t.Fatalf("unexpected result count: %+v", summary)
			}
			report := summary.Results[0]
			if report.Status != CapabilityAvailable || report.MappingBehavior != string(test.mapping) || report.FilteringBehavior != string(test.filtering) {
				t.Fatalf("unexpected RFC 5780 report: %+v", report)
			}
		})
	}
}

func TestProbeNATRFC5780OtherAddressUnsupported(t *testing.T) {
	fixture := startRFC5780Fixture(t, fixtureEndpointIndependent, fixtureEndpointIndependent, false)
	summary := ProbeNAT(context.Background(), ProbeConfig{
		Servers: []string{fixture.primary}, IPVersion: "ipv4", Timeout: time.Second,
	})
	report := summary.Results[0]
	if report.Status != CapabilityAvailable || report.MappingBehavior != behaviorUnsupported || report.FilteringBehavior != behaviorUnsupported {
		t.Fatalf("binding should remain available when OTHER-ADDRESS is unsupported: %+v", report)
	}
}

func TestProbeNATRFC5780ChangeRequestTimeoutClassifiesFiltering(t *testing.T) {
	fixture := startRFC5780Fixture(t, fixtureEndpointIndependent, fixtureAddressAndPortDependent, true)
	summary := ProbeNAT(context.Background(), ProbeConfig{
		Servers: []string{fixture.primary}, IPVersion: "ipv4", Timeout: 25 * time.Millisecond,
	})
	report := summary.Results[0]
	if report.Status != CapabilityAvailable || report.MappingBehavior != "endpoint independent" || report.FilteringBehavior != "address and port dependent" {
		t.Fatalf("CHANGE-REQUEST timeout must be a filtering classification: %+v", report)
	}
}

func TestProbeNATRFC5780ContextCancellation(t *testing.T) {
	fixture := startRFC5780Fixture(t, fixtureEndpointIndependent, fixtureAddressAndPortDependent, true)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	summary := ProbeNAT(ctx, ProbeConfig{
		Servers: []string{fixture.primary}, IPVersion: "ipv4", Timeout: 5 * time.Second,
	})
	report := summary.Results[0]
	if report.Status != CapabilityTimeout || report.MappingBehavior != "endpoint independent" || report.FilteringBehavior != behaviorTimeout {
		t.Fatalf("context cancellation must not be interpreted as restrictive filtering: %+v", report)
	}
	if report.Error != "timeout" {
		t.Fatalf("context error was not stabilized: %+v", report)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("context cancellation was not prompt: %s", time.Since(started))
	}
}

func TestProbeNATRFC5780ConcurrentMixedServersPreservesLegacyGlobals(t *testing.T) {
	endpointIndependent := startRFC5780Fixture(t, fixtureEndpointIndependent, fixtureEndpointIndependent, true)
	addressDependent := startRFC5780Fixture(t, fixtureAddressDependent, fixtureAddressDependent, true)
	unsupported := startRFC5780Fixture(t, fixtureEndpointIndependent, fixtureEndpointIndependent, false)
	originalMapping, originalFiltering := model.NatMappingBehavior, model.NatFilteringBehavior
	defer func() {
		model.NatMappingBehavior, model.NatFilteringBehavior = originalMapping, originalFiltering
	}()
	model.NatMappingBehavior = "legacy mapping sentinel"
	model.NatFilteringBehavior = "legacy filtering sentinel"
	summary := ProbeNAT(context.Background(), ProbeConfig{
		Servers:   []string{endpointIndependent.primary, addressDependent.primary, unsupported.primary},
		IPVersion: "ipv4", Timeout: 30 * time.Millisecond, MaxConcurrent: 3,
	})
	if summary.Successful != 3 || summary.Failed != 0 || len(summary.Results) != 3 {
		t.Fatalf("unexpected mixed-server summary: %+v", summary)
	}
	want := map[string][2]string{
		endpointIndependent.primary: {"endpoint independent", "endpoint independent"},
		addressDependent.primary:    {"address dependent", "address dependent"},
		unsupported.primary:         {behaviorUnsupported, behaviorUnsupported},
	}
	for _, report := range summary.Results {
		expected := want[report.Server]
		if report.MappingBehavior != expected[0] || report.FilteringBehavior != expected[1] {
			t.Fatalf("unexpected result for %s: %+v", report.Server, report)
		}
	}
	if model.NatMappingBehavior != "legacy mapping sentinel" || model.NatFilteringBehavior != "legacy filtering sentinel" {
		t.Fatalf("ProbeNAT mutated legacy globals: mapping=%q filtering=%q", model.NatMappingBehavior, model.NatFilteringBehavior)
	}
}

func TestLegacyRFC5780APIsUseInstanceProbe(t *testing.T) {
	fixture := startRFC5780Fixture(t, fixtureAddressDependent, fixtureAddressDependent, true)
	originalMapping, originalFiltering := model.NatMappingBehavior, model.NatFilteringBehavior
	originalVersion, originalTimeout := model.IPVersion, model.Timeout
	defer func() {
		model.NatMappingBehavior, model.NatFilteringBehavior = originalMapping, originalFiltering
		model.IPVersion, model.Timeout = originalVersion, originalTimeout
	}()
	model.IPVersion, model.Timeout = "ipv4", 1
	model.NatMappingBehavior, model.NatFilteringBehavior = "", ""
	if err := MappingTests(fixture.primary); err != nil {
		t.Fatalf("legacy mapping failed: %v", err)
	}
	if err := FilteringTests(fixture.primary); err != nil {
		t.Fatalf("legacy filtering failed: %v", err)
	}
	if model.NatMappingBehavior != "address dependent" || model.NatFilteringBehavior != "address dependent" {
		t.Fatalf("legacy results not populated: mapping=%q filtering=%q", model.NatMappingBehavior, model.NatFilteringBehavior)
	}
}

func startRFC5780Fixture(t *testing.T, mapping, filtering fixtureBehavior, includeOther bool) *rfc5780Fixture {
	t.Helper()
	primaryIP := net.ParseIP("127.0.0.1")
	otherIP := net.ParseIP("127.0.0.2")
	primaryPrimary := listenFixtureUDP(t, primaryIP, 0)
	primaryPort := primaryPrimary.LocalAddr().(*net.UDPAddr).Port
	otherPrimary, otherPrimaryErr := net.ListenUDP("udp4", &net.UDPAddr{IP: otherIP, Port: primaryPort})
	primaryOther := listenFixtureUDP(t, primaryIP, 0)
	otherPort := primaryOther.LocalAddr().(*net.UDPAddr).Port
	otherOther, otherOtherErr := net.ListenUDP("udp4", &net.UDPAddr{IP: otherIP, Port: otherPort})
	sequential := false
	if otherPrimaryErr != nil || otherOtherErr != nil {
		if otherPrimaryErr == nil {
			_ = otherPrimary.Close()
		}
		if otherOtherErr == nil {
			_ = otherOther.Close()
		}
		sequential = true
		otherPrimary = nil
		otherOther = primaryOther
	}
	fixture := &rfc5780Fixture{
		primary:           primaryPrimary.LocalAddr().String(),
		other:             cloneUDPAddr(otherOther.LocalAddr().(*net.UDPAddr)),
		mappingBehavior:   mapping,
		filteringBehavior: filtering,
		includeOther:      includeOther,
		sequential:        sequential,
		sequenceByClient:  make(map[string]int),
		endpoints: []fixtureEndpoint{
			{conn: primaryPrimary, ipIndex: 0, portIndex: 0},
			{conn: primaryOther, ipIndex: 0, portIndex: 1},
		},
	}
	if !sequential {
		fixture.endpoints = []fixtureEndpoint{
			{conn: primaryPrimary, ipIndex: 0, portIndex: 0},
			{conn: otherPrimary, ipIndex: 1, portIndex: 0},
			{conn: primaryOther, ipIndex: 0, portIndex: 1},
			{conn: otherOther, ipIndex: 1, portIndex: 1},
		}
	}
	for index := range fixture.endpoints {
		fixture.wg.Add(1)
		go fixture.serve(fixture.endpoints[index])
	}
	t.Cleanup(fixture.close)
	return fixture
}

func listenFixtureUDP(t *testing.T, ip net.IP, port int) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		t.Fatalf("listen UDP fixture %s:%d: %v", ip, port, err)
	}
	return conn
}

func (f *rfc5780Fixture) serve(endpoint fixtureEndpoint) {
	defer f.wg.Done()
	buffer := make([]byte, 64<<10)
	for {
		read, client, err := endpoint.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		request := &stun.Message{Raw: append([]byte(nil), buffer[:read]...)}
		if request.Decode() != nil {
			continue
		}
		change, err := request.Get(stun.AttrChangeRequest)
		if err == nil && len(change) == 4 {
			f.respondToChange(request, client, change[3])
			continue
		}
		if f.sequential {
			endpoint = f.sequenceEndpoint(client, endpoint)
		}
		f.writeBindingResponse(endpoint.conn, request, client, f.mappedPort(client.Port, endpoint))
	}
}

func (f *rfc5780Fixture) respondToChange(request *stun.Message, client *net.UDPAddr, change byte) {
	var source *net.UDPConn
	switch change {
	case 0x06:
		if f.filteringBehavior == fixtureEndpointIndependent {
			source = f.endpoints[len(f.endpoints)-1].conn
		}
	case 0x02:
		if f.filteringBehavior != fixtureAddressAndPortDependent {
			if f.sequential {
				source = f.endpoints[1].conn
			} else {
				source = f.endpoints[2].conn
			}
		}
	}
	if source != nil {
		f.writeBindingResponse(source, request, client, client.Port)
	}
}

func (f *rfc5780Fixture) sequenceEndpoint(client *net.UDPAddr, fallback fixtureEndpoint) fixtureEndpoint {
	key := client.String()
	f.sequenceMu.Lock()
	index := f.sequenceByClient[key]
	f.sequenceByClient[key] = index + 1
	f.sequenceMu.Unlock()
	if index == 0 {
		return fixtureEndpoint{conn: fallback.conn, ipIndex: 0, portIndex: 0}
	}
	if index == 1 {
		return fixtureEndpoint{conn: fallback.conn, ipIndex: 1, portIndex: 0}
	}
	return fixtureEndpoint{conn: fallback.conn, ipIndex: 1, portIndex: 1}
}

func (f *rfc5780Fixture) writeBindingResponse(source *net.UDPConn, request *stun.Message, client *net.UDPAddr, mappedPort int) {
	setters := []stun.Setter{
		stun.NewTransactionIDSetter(request.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: client.IP, Port: mappedPort},
	}
	if f.includeOther {
		setters = append(setters, &stun.OtherAddress{IP: f.other.IP, Port: f.other.Port})
	}
	response := stun.MustBuild(setters...)
	_, _ = source.WriteToUDP(response.Raw, client)
}

func (f *rfc5780Fixture) mappedPort(clientPort int, endpoint fixtureEndpoint) int {
	offset := 0
	switch f.mappingBehavior {
	case fixtureAddressDependent:
		offset = endpoint.ipIndex
	case fixtureAddressAndPortDependent:
		offset = endpoint.ipIndex*2 + endpoint.portIndex
	}
	if clientPort+offset <= 65535 {
		return clientPort + offset
	}
	return clientPort - offset
}

func (f *rfc5780Fixture) close() {
	f.closeOnce.Do(func() {
		for _, endpoint := range f.endpoints {
			_ = endpoint.conn.Close()
		}
		f.wg.Wait()
	})
}
