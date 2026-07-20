package stuncheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v2"
)

const (
	behaviorUnsupported = "unsupported"
	behaviorTimeout     = "timeout"
	behaviorError       = "error"
)

type rfc5780Result struct {
	mapping   string
	filtering string
	err       error
}

// rfc5780Probe owns all state used by one RFC 5780 discovery run. Instances
// can run concurrently because they do not use the legacy NAT result globals.
type rfc5780Probe struct {
	conn      *net.UDPConn
	primary   *net.UDPAddr
	other     *net.UDPAddr
	timeout   time.Duration
	stopWatch func()
	closeOnce sync.Once
	ioMu      sync.Mutex
}

func newRFC5780Probe(ctx context.Context, server, family string, timeout time.Duration) (*rfc5780Probe, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	network := "udp4"
	if family == "ipv6" {
		network = "udp6"
	}
	primary, err := net.ResolveUDPAddr(network, server)
	if err != nil {
		return nil, err
	}
	local, err := getLocalAddrForInterface(network)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, local)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &rfc5780Probe{
		conn:      conn,
		primary:   primary,
		timeout:   timeout,
		stopWatch: watchContext(ctx, conn),
	}, nil
}

func (p *rfc5780Probe) Close() error {
	var err error
	p.closeOnce.Do(func() {
		p.stopWatch()
		err = p.conn.Close()
	})
	return err
}

func (p *rfc5780Probe) initialBinding(ctx context.Context) (*net.UDPAddr, *net.UDPAddr, error) {
	response, err := p.bindingRequest(ctx, p.primary, 0)
	if err != nil {
		return nil, nil, err
	}
	mapped, err := xorMappedAddress(response)
	if err != nil {
		return nil, nil, err
	}
	var other stun.OtherAddress
	if err := other.GetFrom(response); err != nil {
		return nil, nil, errNoOtherAddress
	}
	p.other = &net.UDPAddr{IP: append(net.IP(nil), other.IP...), Port: other.Port}
	return mapped, cloneUDPAddr(p.other), nil
}

func (p *rfc5780Probe) mappingBehavior(ctx context.Context, firstMapped, other *net.UDPAddr) (string, error) {
	local, _ := p.conn.LocalAddr().(*net.UDPAddr)
	if udpAddrEqual(firstMapped, local) {
		return "endpoint independent (no NAT)", nil
	}
	otherIPPrimaryPort := cloneUDPAddr(other)
	otherIPPrimaryPort.Port = p.primary.Port
	response, err := p.bindingRequest(ctx, otherIPPrimaryPort, 0)
	if err != nil {
		return behaviorForError(err), err
	}
	secondMapped, err := xorMappedAddress(response)
	if err != nil {
		return behaviorForError(err), err
	}
	if udpAddrEqual(firstMapped, secondMapped) {
		return "endpoint independent", nil
	}
	response, err = p.bindingRequest(ctx, other, 0)
	if err != nil {
		return behaviorForError(err), err
	}
	thirdMapped, err := xorMappedAddress(response)
	if err != nil {
		return behaviorForError(err), err
	}
	if udpAddrEqual(secondMapped, thirdMapped) {
		return "address dependent", nil
	}
	return "address and port dependent", nil
}

func (p *rfc5780Probe) filteringBehavior(ctx context.Context) (string, error) {
	_, err := p.bindingRequest(ctx, p.primary, 0x06)
	if err == nil {
		return "endpoint independent", nil
	}
	if !errors.Is(err, errTimedOut) {
		return behaviorForError(err), err
	}
	_, err = p.bindingRequest(ctx, p.primary, 0x02)
	if err == nil {
		return "address dependent", nil
	}
	if errors.Is(err, errTimedOut) {
		return "address and port dependent", nil
	}
	return behaviorForError(err), err
}

func (p *rfc5780Probe) bindingRequest(ctx context.Context, destination *net.UDPAddr, change byte) (*stun.Message, error) {
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	expectedSource := destination
	if change != 0 {
		request.Add(stun.AttrChangeRequest, []byte{0, 0, 0, change})
		if p.other == nil {
			return nil, errNoOtherAddress
		}
		expectedSource = cloneUDPAddr(p.other)
		if change == 0x02 {
			expectedSource.IP = append(net.IP(nil), p.primary.IP...)
		}
	}
	return p.roundTrip(ctx, request, destination, expectedSource)
}

func (p *rfc5780Probe) roundTrip(ctx context.Context, request *stun.Message, destination, expectedSource *net.UDPAddr) (*stun.Message, error) {
	p.ioMu.Lock()
	defer p.ioMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(p.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := p.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := p.conn.WriteToUDP(request.Raw, destination); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	buffer := make([]byte, 64<<10)
	for {
		read, source, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if isTimeoutError(err) {
				return nil, fmt.Errorf("%w: %w", errTimedOut, err)
			}
			return nil, err
		}
		response := &stun.Message{Raw: append([]byte(nil), buffer[:read]...)}
		if err := response.Decode(); err != nil {
			continue
		}
		if response.TransactionID != request.TransactionID {
			continue
		}
		if !udpAddrEqual(source, expectedSource) {
			continue
		}
		return response, nil
	}
}

func probeRFC5780(ctx context.Context, server, family string, timeout time.Duration) rfc5780Result {
	probe, err := newRFC5780Probe(ctx, server, family, timeout)
	if err != nil {
		behavior := behaviorForError(err)
		return rfc5780Result{mapping: behavior, filtering: behavior, err: err}
	}
	defer probe.Close()
	firstMapped, other, err := probe.initialBinding(ctx)
	if err != nil {
		behavior := behaviorForError(err)
		return rfc5780Result{mapping: behavior, filtering: behavior, err: err}
	}
	mapping, mappingErr := probe.mappingBehavior(ctx, firstMapped, other)
	filtering, filteringErr := probe.filteringBehavior(ctx)
	return rfc5780Result{
		mapping:   mapping,
		filtering: filtering,
		err:       errors.Join(mappingErr, filteringErr),
	}
}

func probeRFC5780Mapping(ctx context.Context, server, family string, timeout time.Duration) (string, error) {
	probe, err := newRFC5780Probe(ctx, server, family, timeout)
	if err != nil {
		return "", err
	}
	defer probe.Close()
	firstMapped, other, err := probe.initialBinding(ctx)
	if err != nil {
		return "", err
	}
	return probe.mappingBehavior(ctx, firstMapped, other)
}

func probeRFC5780Filtering(ctx context.Context, server, family string, timeout time.Duration) (string, error) {
	probe, err := newRFC5780Probe(ctx, server, family, timeout)
	if err != nil {
		return "", err
	}
	defer probe.Close()
	_, _, err = probe.initialBinding(ctx)
	if err != nil {
		return "", err
	}
	return probe.filteringBehavior(ctx)
}

func xorMappedAddress(message *stun.Message) (*net.UDPAddr, error) {
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(message); err != nil {
		return nil, fmt.Errorf("%w: %v", errSTUNUnsupported, err)
	}
	return &net.UDPAddr{IP: append(net.IP(nil), mapped.IP...), Port: mapped.Port}, nil
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func udpAddrEqual(left, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.IP.Equal(right.IP)
}

func behaviorForError(err error) string {
	switch {
	case errors.Is(err, errNoOtherAddress), errors.Is(err, errSTUNUnsupported):
		return behaviorUnsupported
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, errTimedOut), isTimeoutError(err):
		return behaviorTimeout
	default:
		return behaviorError
	}
}
