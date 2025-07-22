package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/oneclickvirt/gostun/model"
	"github.com/oneclickvirt/gostun/stuncheck"
	"github.com/pion/logging"
)

// tryRFCMethod attempts NAT detection using specified RFC method
func tryRFCMethod(addrStr string, rfcMethod string) (bool, error) {
	currentProtocol := "ipv4"
	if model.IPVersion == "ipv6" || (model.IPVersion == "both" && strings.Contains(addrStr, "[") && strings.Contains(addrStr, "]")) {
		currentProtocol = "ipv6"
	}
	var err1, err2 error
	switch rfcMethod {
	case "RFC5780":
		if model.EnableLoger {
			model.Log.Infof("[%s] Trying RFC 5780 method with server %s", currentProtocol, addrStr)
		}
		err1 = stuncheck.MappingTests(addrStr)
		if err1 != nil {
			model.NatMappingBehavior = "inconclusive"
			if model.EnableLoger {
				model.Log.Warnf("[%s] RFC5780 NAT mapping behavior: inconclusive", currentProtocol)
			}
		}
		err2 = stuncheck.FilteringTests(addrStr)
		if err2 != nil {
			model.NatFilteringBehavior = "inconclusive"
			if model.EnableLoger {
				model.Log.Warnf("[%s] RFC5780 NAT filtering behavior: inconclusive", currentProtocol)
			}
		}
	case "RFC5389":
		if model.EnableLoger {
			model.Log.Infof("[%s] Trying RFC 5389/8489 method with server %s", currentProtocol, addrStr)
		}
		err1 = stuncheck.MappingTestsRFC5389(addrStr)
		if err1 != nil {
			model.NatMappingBehavior = "inconclusive"
			model.NatFilteringBehavior = "inconclusive"
			if model.EnableLoger {
				model.Log.Warnf("[%s] RFC5389 NAT detection: inconclusive", currentProtocol)
			}
		}
	case "RFC3489":
		if model.EnableLoger {
			model.Log.Infof("[%s] Trying RFC 3489 method with server %s", currentProtocol, addrStr)
		}
		err1 = stuncheck.MappingTestsRFC3489(addrStr)
		if err1 != nil {
			model.NatMappingBehavior = "inconclusive"
			model.NatFilteringBehavior = "inconclusive"
			if model.EnableLoger {
				model.Log.Warnf("[%s] RFC3489 NAT detection: inconclusive", currentProtocol)
			}
		}
	}
	if model.NatMappingBehavior != "inconclusive" && model.NatFilteringBehavior != "inconclusive" &&
		model.NatMappingBehavior != "" && model.NatFilteringBehavior != "" {
		if model.EnableLoger {
			model.Log.Infof("[%s] Successfully determined NAT type using %s with server %s", currentProtocol, rfcMethod, addrStr)
		}
		return true, nil
	}
	return false, nil
}

func main() {
	var showVersion, help bool
	gostunFlag := flag.NewFlagSet("gostun", flag.ContinueOnError)
	gostunFlag.BoolVar(&help, "h", false, "Display help information")
	gostunFlag.BoolVar(&showVersion, "v", false, "Display version information")
	gostunFlag.IntVar(&model.Verbose, "verbose", 0, "Set verbosity level")
	gostunFlag.IntVar(&model.Timeout, "timeout", 3, "Set timeout in seconds for STUN server response")
	gostunFlag.StringVar(&model.AddrStr, "server", "stun.voipgate.com:3478", "Specify STUN server address")
	gostunFlag.BoolVar(&model.EnableLoger, "e", true, "Enable logging functionality")
	gostunFlag.StringVar(&model.IPVersion, "type", "ipv4", "Specify ip test version: ipv4, ipv6 or both")
	gostunFlag.StringVar(&model.TransmissionProtocol, "protocol", "udp", "Specify transmission protocol: udp, tcp, or tls")
	gostunFlag.Parse(os.Args[1:])
	if help {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		gostunFlag.PrintDefaults()
		return
	}
	go func() {
		http.Get("https://hits.spiritlhl.net/gostun.svg?action=hit&title=Hits&title_bg=%23555555&count_bg=%230eecf8&edge_flat=false")
	}()
	fmt.Println("Repo:", "https://github.com/oneclickvirt/gostun")
	if showVersion {
		fmt.Println(model.GoStunVersion)
		return
	}
	if model.EnableLoger {
		var logLevel logging.LogLevel
		switch model.Verbose {
		case 0:
			logLevel = logging.LogLevelWarn
		case 1:
			logLevel = logging.LogLevelInfo
		case 2:
			logLevel = logging.LogLevelDebug
		case 3:
			logLevel = logging.LogLevelTrace
		}
		model.Log = logging.NewDefaultLeveledLoggerForScope("", logLevel, os.Stdout)
	}
	var addrStrList []string
	var originalIPVersion = model.IPVersion
	if strings.Contains(os.Args[0], "-server") || model.AddrStr != "stun.voipgate.com:3478" {
		addrStrList = []string{model.AddrStr}
	} else {
		addrStrList = model.GetDefaultServers(model.IPVersion)
	}
	// RFC methods in order of preference: 5780 -> 5389 -> 3489
	rfcMethods := []string{"RFC5780", "RFC5389", "RFC3489"}
	successfulDetection := false
	for _, rfcMethod := range rfcMethods {
		if successfulDetection {
			break
		}
		for _, addrStr := range addrStrList {
			model.NatMappingBehavior = ""
			model.NatFilteringBehavior = ""
			currentProtocol := "ipv4"
			if originalIPVersion == "both" {
				if strings.Contains(addrStr, "[") && strings.Contains(addrStr, "]") &&
					!strings.Contains(addrStr, ".") {
					currentProtocol = "ipv6"
					model.IPVersion = "ipv6"
				} else {
					currentProtocol = "ipv4"
					model.IPVersion = "ipv4"
				}
			} else {
				currentProtocol = originalIPVersion
			}
			if model.EnableLoger {
				model.Log.Infof("Testing server %s with protocol %s using %s", addrStr, currentProtocol, rfcMethod)
			}
			success, err := tryRFCMethod(addrStr, rfcMethod)
			if err != nil && model.EnableLoger {
				model.Log.Warnf("[%s] Error with %s method: %v", currentProtocol, rfcMethod, err)
			}
			if success {
				successfulDetection = true
				break
			}
			if model.EnableLoger {
				model.Log.Warnf("[%s] Server %s failed to determine NAT type using %s, trying next server", currentProtocol, addrStr, rfcMethod)
			}
		}
		if !successfulDetection && model.EnableLoger {
			model.Log.Warnf("All servers failed with %s method, trying next RFC method", rfcMethod)
		}
	}
	model.IPVersion = originalIPVersion
	res := stuncheck.CheckType()
	fmt.Printf("NAT Type: %s\n", res)
}
