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

func main() {
	var showVersion, help bool
	gostunFlag := flag.NewFlagSet("gostun", flag.ContinueOnError)
	gostunFlag.BoolVar(&help, "h", false, "Display help information")
	gostunFlag.BoolVar(&showVersion, "v", false, "Display version information")
	gostunFlag.IntVar(&model.Verbose, "verbose", 0, "Set verbosity level")
	gostunFlag.IntVar(&model.Timeout, "timeout", 3, "Set timeout in seconds for STUN server response")
	gostunFlag.StringVar(&model.AddrStr, "server", "stun.voipgate.com:3478", "Specify STUN server address")
	gostunFlag.BoolVar(&model.EnableLoger, "e", true, "Enable logging functionality")
	gostunFlag.StringVar(&model.IPVersion, "ip", "ipv4", "IP version: ipv4, ipv6, or both")
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
	if strings.Contains(os.Args[0], "-server") || model.AddrStr != "stun.voipgate.com:3478" {
		addrStrList = []string{model.AddrStr}
	} else {
		addrStrList = model.GetDefaultServers(model.IPVersion)
	}
	checkStatus := true
	for _, addrStr := range addrStrList {
		if model.IPVersion == "both" {
			if strings.Contains(addrStr, "[") && strings.Contains(addrStr, "]") &&
				!strings.Contains(addrStr, ".") {
				model.IPVersion = "ipv6"
			} else {
				model.IPVersion = "ipv4"
			}
		}
		err1 := stuncheck.MappingTests(addrStr)
		if err1 != nil {
			model.NatMappingBehavior = "inconclusive"
			if model.EnableLoger {
				model.Log.Warn("NAT mapping behavior: inconclusive")
			}
			checkStatus = false
		}
		err2 := stuncheck.FilteringTests(addrStr)
		if err2 != nil {
			model.NatFilteringBehavior = "inconclusive"
			if model.EnableLoger {
				model.Log.Warn("NAT filtering behavior: inconclusive")
			}
			checkStatus = false
		}
		if model.NatMappingBehavior == "inconclusive" || model.NatFilteringBehavior == "inconclusive" {
			checkStatus = false
		} else if model.NatMappingBehavior != "inconclusive" && model.NatFilteringBehavior != "inconclusive" {
			checkStatus = true
		}
		if checkStatus {
			break
		}
		if model.IPVersion == "both" {
			model.IPVersion = "both"
		}
	}
	res := stuncheck.CheckType()
	fmt.Printf("NAT Type: %s\n", res)
}
