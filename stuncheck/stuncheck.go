package stuncheck

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/oneclickvirt/gostun/model"
	"github.com/pion/stun/v2"
)

type stunServerConn struct {
	conn        net.Conn
	LocalAddr   net.Addr
	RemoteAddr  *net.UDPAddr
	OtherAddr   *net.UDPAddr
	messageChan chan *stun.Message
	protocol    string
}

func (c *stunServerConn) Close() error {
	return c.conn.Close()
}

const (
	messageHeaderSize = 20
)

var (
	errResponseMessage = errors.New("error reading from response message channel")
	errTimedOut        = errors.New("timed out waiting for response")
	errNoOtherAddress  = errors.New("no OTHER-ADDRESS in message")
)

func isIPv6Address(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

func getNetworkType(addrStr string) string {
	switch model.IPVersion {
	case "ipv6":
		if model.TransmissionProtocol == "tcp" {
			return "tcp6"
		}
		return "udp6"
	case "ipv4":
		if model.TransmissionProtocol == "tcp" {
			return "tcp4"
		}
		return "udp4"
	case "both":
		if isIPv6Address(addrStr) {
			if model.TransmissionProtocol == "tcp" {
				return "tcp6"
			}
			return "udp6"
		}
		if model.TransmissionProtocol == "tcp" {
			return "tcp4"
		}
		return "udp4"
	}
	if model.TransmissionProtocol == "tcp" {
		return "tcp4"
	}
	return "udp4"
}

func getCurrentProtocol(addrStr string) string {
	if model.IPVersion == "ipv6" {
		return "ipv6"
	} else if model.IPVersion == "ipv4" {
		return "ipv4"
	} else if isIPv6Address(addrStr) {
		return "ipv6"
	}
	return "ipv4"
}

func MappingTests(addrStr string) error {
	currentProtocol := getCurrentProtocol(addrStr)
	mapTestConn, err := connect(addrStr)
	if err != nil {
		if model.EnableLoger {
			model.Log.Warnf("[%s] Error creating STUN connection: %s", currentProtocol, err)
		}
		return err
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] Mapping Test I: Regular binding request", currentProtocol)
	}
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil {
		return err
	}
	resps1 := parse(resp)
	if resps1.xorAddr == nil || resps1.otherAddr == nil {
		if model.EnableLoger {
			model.Log.Infof("[%s] Error: NAT discovery feature not supported by this server", currentProtocol)
		}
		return errNoOtherAddress
	}
	networkType := getNetworkType(addrStr)
	addr, err := net.ResolveUDPAddr(networkType, resps1.otherAddr.String())
	if err != nil {
		if model.EnableLoger {
			model.Log.Infof("[%s] Failed resolving OTHER-ADDRESS: %v", currentProtocol, resps1.otherAddr)
		}
		return err
	}
	mapTestConn.OtherAddr = addr
	if model.EnableLoger {
		model.Log.Infof("[%s] Received XOR-MAPPED-ADDRESS: %v", currentProtocol, resps1.xorAddr)
	}
	if resps1.xorAddr.String() == mapTestConn.LocalAddr.String() {
		model.NatMappingBehavior = "endpoint independent (no NAT)"
		if model.EnableLoger {
			model.Log.Warnf("[%s] => NAT mapping behavior: endpoint independent (no NAT)", currentProtocol)
		}
		return nil
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] Mapping Test II: Send binding request to the other address but primary port", currentProtocol)
	}
	oaddr := *mapTestConn.OtherAddr
	oaddr.Port = mapTestConn.RemoteAddr.Port
	resp, err = mapTestConn.roundTrip(request, &oaddr)
	if err != nil {
		return err
	}
	resps2 := parse(resp)
	if model.EnableLoger {
		model.Log.Infof("[%s] Received XOR-MAPPED-ADDRESS: %v", currentProtocol, resps2.xorAddr)
	}
	if resps2.xorAddr.String() == resps1.xorAddr.String() {
		model.NatMappingBehavior = "endpoint independent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] => NAT mapping behavior: endpoint independent", currentProtocol)
		}
		return nil
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] Mapping Test III: Send binding request to the other address and port", currentProtocol)
	}
	resp, err = mapTestConn.roundTrip(request, mapTestConn.OtherAddr)
	if err != nil {
		return err
	}
	resps3 := parse(resp)
	if model.EnableLoger {
		model.Log.Infof("[%s] Received XOR-MAPPED-ADDRESS: %v", currentProtocol, resps3.xorAddr)
	}
	if resps3.xorAddr.String() == resps2.xorAddr.String() {
		model.NatMappingBehavior = "address dependent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] => NAT mapping behavior: address dependent", currentProtocol)
		}
	} else {
		model.NatMappingBehavior = "address and port dependent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] => NAT mapping behavior: address and port dependent", currentProtocol)
		}
	}
	return mapTestConn.Close()
}

func FilteringTests(addrStr string) error {
	currentProtocol := getCurrentProtocol(addrStr)
	mapTestConn, err := connect(addrStr)
	if err != nil {
		if model.EnableLoger {
			model.Log.Warnf("[%s] Error creating STUN connection: %s", currentProtocol, err)
		}
		return err
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] Filtering Test I: Regular binding request", currentProtocol)
	}
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil || errors.Is(err, errTimedOut) {
		return err
	}
	resps := parse(resp)
	if resps.xorAddr == nil || resps.otherAddr == nil {
		if model.EnableLoger {
			model.Log.Warnf("[%s] Error: NAT discovery feature not supported by this server", currentProtocol)
		}
		return errNoOtherAddress
	}
	networkType := getNetworkType(addrStr)
	addr, err := net.ResolveUDPAddr(networkType, resps.otherAddr.String())
	if err != nil {
		if model.EnableLoger {
			model.Log.Infof("[%s] Failed resolving OTHER-ADDRESS: %v", currentProtocol, resps.otherAddr)
		}
		return err
	}
	mapTestConn.OtherAddr = addr
	if model.EnableLoger {
		model.Log.Infof("[%s] Filtering Test II: Request to change both IP and port", currentProtocol)
	}
	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x06})
	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err == nil {
		parse(resp)
		model.NatFilteringBehavior = "endpoint independent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] => NAT filtering behavior: endpoint independent", currentProtocol)
		}
		return nil
	} else if !errors.Is(err, errTimedOut) {
		return err
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] Filtering Test III: Request to change port only", currentProtocol)
	}
	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})
	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err == nil {
		parse(resp)
		model.NatFilteringBehavior = "address dependent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] => NAT filtering behavior: address dependent", currentProtocol)
		}
	} else if errors.Is(err, errTimedOut) {
		model.NatFilteringBehavior = "address and port dependent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] => NAT filtering behavior: address and port dependent", currentProtocol)
		}
	}
	return mapTestConn.Close()
}

func MappingTestsRFC5389(addrStr string) error {
	currentProtocol := getCurrentProtocol(addrStr)
	mapTestConn, err := connect(addrStr)
	if err != nil {
		if model.EnableLoger {
			model.Log.Warnf("[%s] RFC5389: Error creating STUN connection: %s", currentProtocol, err)
		}
		return err
	}
	defer mapTestConn.Close()
	if model.EnableLoger {
		model.Log.Infof("[%s] RFC5389: Basic binding request", currentProtocol)
	}
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil {
		return err
	}
	resps := parse(resp)
	if resps.xorAddr == nil {
		if model.EnableLoger {
			model.Log.Warnf("[%s] RFC5389: No XOR-MAPPED-ADDRESS received", currentProtocol)
		}
		return errors.New("no mapped address")
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] RFC5389: Received XOR-MAPPED-ADDRESS: %v", currentProtocol, resps.xorAddr)
	}
	if resps.xorAddr.String() == mapTestConn.LocalAddr.String() {
		model.NatMappingBehavior = "endpoint independent (no NAT)"
		model.NatFilteringBehavior = "endpoint independent"
	} else {
		model.NatMappingBehavior = "address and port dependent"
		model.NatFilteringBehavior = "address and port dependent"
	}
	if model.EnableLoger {
		model.Log.Warnf("[%s] RFC5389: NAT mapping behavior: %s", currentProtocol, model.NatMappingBehavior)
		model.Log.Warnf("[%s] RFC5389: NAT filtering behavior: %s", currentProtocol, model.NatFilteringBehavior)
	}
	return nil
}

func MappingTestsRFC3489(addrStr string) error {
	currentProtocol := getCurrentProtocol(addrStr)
	mapTestConn, err := connect(addrStr)
	if err != nil {
		if model.EnableLoger {
			model.Log.Warnf("[%s] RFC3489: Error creating STUN connection: %s", currentProtocol, err)
		}
		return err
	}
	defer mapTestConn.Close()
	if model.EnableLoger {
		model.Log.Infof("[%s] RFC3489: Test I - Basic binding request", currentProtocol)
	}
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil {
		return err
	}
	resps1 := parse(resp)
	var mappedAddr *net.UDPAddr
	if resps1.xorAddr != nil {
		mappedAddr, _ = net.ResolveUDPAddr("udp", resps1.xorAddr.String())
	} else if resps1.mappedAddr != nil {
		mappedAddr, _ = net.ResolveUDPAddr("udp", resps1.mappedAddr.String())
	}
	if mappedAddr == nil {
		if model.EnableLoger {
			model.Log.Warnf("[%s] RFC3489: No mapped address received", currentProtocol)
		}
		return errors.New("no mapped address")
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] RFC3489: Received mapped address: %v", currentProtocol, mappedAddr)
	}
	localAddr := mapTestConn.LocalAddr
	if model.TransmissionProtocol == "tcp" || model.TransmissionProtocol == "tls" {
		localTCP := localAddr.(*net.TCPAddr)
		if mappedAddr.IP.Equal(localTCP.IP) && mappedAddr.Port == localTCP.Port {
			model.NatMappingBehavior = "endpoint independent (no NAT)"
			model.NatFilteringBehavior = "endpoint independent"
			if model.EnableLoger {
				model.Log.Warnf("[%s] RFC3489: No NAT detected", currentProtocol)
			}
			return nil
		}
	} else {
		localUDP := localAddr.(*net.UDPAddr)
		if mappedAddr.IP.Equal(localUDP.IP) && mappedAddr.Port == localUDP.Port {
			model.NatMappingBehavior = "endpoint independent (no NAT)"
			model.NatFilteringBehavior = "endpoint independent"
			if model.EnableLoger {
				model.Log.Warnf("[%s] RFC3489: No NAT detected", currentProtocol)
			}
			return nil
		}
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] RFC3489: Test II - Request with change IP and Port", currentProtocol)
	}
	request2 := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request2.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x06})
	resp2, err2 := mapTestConn.roundTrip(request2, mapTestConn.RemoteAddr)
	if err2 == nil && resp2 != nil {
		model.NatMappingBehavior = "endpoint independent"
		model.NatFilteringBehavior = "endpoint independent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] RFC3489: Full Cone NAT detected", currentProtocol)
		}
		return nil
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] RFC3489: Test III - Request with change Port only", currentProtocol)
	}
	request3 := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request3.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})
	resp3, err3 := mapTestConn.roundTrip(request3, mapTestConn.RemoteAddr)
	if err3 == nil && resp3 != nil {
		model.NatMappingBehavior = "endpoint independent"
		model.NatFilteringBehavior = "address dependent"
		if model.EnableLoger {
			model.Log.Warnf("[%s] RFC3489: Restricted Cone NAT detected", currentProtocol)
		}
		return nil
	}
	model.NatMappingBehavior = "address and port dependent"
	model.NatFilteringBehavior = "address and port dependent"
	if model.EnableLoger {
		model.Log.Warnf("[%s] RFC3489: Symmetric NAT detected", currentProtocol)
	}
	return nil
}

func parse(msg *stun.Message) (ret struct {
	xorAddr    *stun.XORMappedAddress
	otherAddr  *stun.OtherAddress
	respOrigin *stun.ResponseOrigin
	mappedAddr *stun.MappedAddress
	software   *stun.Software
},
) {
	ret.mappedAddr = &stun.MappedAddress{}
	ret.xorAddr = &stun.XORMappedAddress{}
	ret.respOrigin = &stun.ResponseOrigin{}
	ret.otherAddr = &stun.OtherAddress{}
	ret.software = &stun.Software{}
	if ret.xorAddr.GetFrom(msg) != nil {
		ret.xorAddr = nil
	}
	if ret.otherAddr.GetFrom(msg) != nil {
		ret.otherAddr = nil
	}
	if ret.respOrigin.GetFrom(msg) != nil {
		ret.respOrigin = nil
	}
	if ret.mappedAddr.GetFrom(msg) != nil {
		ret.mappedAddr = nil
	}
	if ret.software.GetFrom(msg) != nil {
		ret.software = nil
	}
	if model.EnableLoger {
		model.Log.Debugf("%v", msg)
		model.Log.Debugf("\tMAPPED-ADDRESS:     %v", ret.mappedAddr)
		model.Log.Debugf("\tXOR-MAPPED-ADDRESS: %v", ret.xorAddr)
		model.Log.Debugf("\tRESPONSE-ORIGIN:    %v", ret.respOrigin)
		model.Log.Debugf("\tOTHER-ADDRESS:      %v", ret.otherAddr)
		model.Log.Debugf("\tSOFTWARE: %v", ret.software)
	}
	for _, attr := range msg.Attributes {
		switch attr.Type {
		case stun.AttrXORMappedAddress, stun.AttrOtherAddress, stun.AttrResponseOrigin, stun.AttrMappedAddress, stun.AttrSoftware:
		default:
			if model.EnableLoger {
				model.Log.Debugf("\t%v (l=%v)", attr, attr.Length)
			}
		}
	}
	return ret
}

func connect(addrStr string) (*stunServerConn, error) {
	currentProtocol := getCurrentProtocol(addrStr)
	if model.EnableLoger {
		model.Log.Infof("[%s] Connecting to STUN server: %s", currentProtocol, addrStr)
	}
	networkType := getNetworkType(addrStr)
	var conn net.Conn
	var localAddr net.Addr
	var err error
	switch model.TransmissionProtocol {
	case "tcp":
		conn, err = net.Dial(networkType, addrStr)
		if err != nil {
			return nil, err
		}
		localAddr = conn.LocalAddr()
	case "tls":
		config := &tls.Config{InsecureSkipVerify: true}
		conn, err = tls.Dial(networkType[:3], addrStr, config)
		if err != nil {
			return nil, err
		}
		localAddr = conn.LocalAddr()
	default:
		_, err := net.ResolveUDPAddr(networkType, addrStr)
		if err != nil {
			if model.EnableLoger {
				model.Log.Warnf("[%s] Error resolving address: %s", currentProtocol, err)
			}
			return nil, err
		}
		udpConn, err := net.ListenUDP(networkType, nil)
		if err != nil {
			return nil, err
		}
		conn = udpConn
		localAddr = udpConn.LocalAddr()
	}
	if model.EnableLoger {
		model.Log.Infof("[%s] Local address: %s", currentProtocol, localAddr.String())
		model.Log.Infof("[%s] Remote address: %s", currentProtocol, addrStr)
	}
	remoteAddr, _ := net.ResolveUDPAddr("udp", addrStr)
	mChan := listen(conn)
	return &stunServerConn{
		conn:        conn,
		LocalAddr:   localAddr,
		RemoteAddr:  remoteAddr,
		messageChan: mChan,
		protocol:    model.TransmissionProtocol,
	}, nil
}

func (c *stunServerConn) roundTrip(msg *stun.Message, addr net.Addr) (*stun.Message, error) {
	_ = msg.NewTransactionID()
	if model.EnableLoger {
		model.Log.Infof("Sending to %v: (%v bytes)", addr, msg.Length+messageHeaderSize)
		model.Log.Debugf("%v", msg)
		for _, attr := range msg.Attributes {
			model.Log.Debugf("\t%v (l=%v)", attr, attr.Length)
		}
	}
	var err error
	switch c.protocol {
	case "tcp", "tls":
		_, err = c.conn.Write(msg.Raw)
	default:
		if udpConn, ok := c.conn.(*net.UDPConn); ok {
			_, err = udpConn.WriteTo(msg.Raw, addr)
		} else {
			_, err = c.conn.Write(msg.Raw)
		}
	}
	if err != nil {
		if model.EnableLoger {
			model.Log.Warnf("Error sending request to %v", addr)
		}
		return nil, err
	}
	select {
	case m, ok := <-c.messageChan:
		if !ok {
			return nil, errResponseMessage
		}
		return m, nil
	case <-time.After(time.Duration(model.Timeout) * time.Second):
		if model.EnableLoger {
			model.Log.Infof("Timed out waiting for response from server %v", addr)
		}
		return nil, errTimedOut
	}
}

func listen(conn net.Conn) (messages chan *stun.Message) {
	messages = make(chan *stun.Message)
	go func() {
		defer close(messages)
		for {
			buf := make([]byte, 1024)
			var n int
			var addr net.Addr
			var err error
			if udpConn, ok := conn.(*net.UDPConn); ok {
				n, addr, err = udpConn.ReadFromUDP(buf)
			} else {
				n, err = conn.Read(buf)
				addr = conn.RemoteAddr()
			}
			if err != nil {
				return
			}
			if model.EnableLoger {
				model.Log.Infof("Response from %v: (%v bytes)", addr, n)
			}
			buf = buf[:n]
			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				if model.EnableLoger {
					model.Log.Infof("Error decoding message: %v", err)
				}
				return
			}
			messages <- m
		}
	}()
	return
}
