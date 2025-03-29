package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

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
	gostunFlag.Parse(os.Args[1:])
	if help {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		gostunFlag.PrintDefaults()
		return
	}
	go func() {
		http.Get("https://hits.spiritlhl.net/gostun.svg?action=hit&title=Hits&title_bg=%23555555&count_bg=%230eecf8&edge_flat=false")
	}()
	fmt.Println("项目地址:", "https://github.com/oneclickvirt/gostun")
	if showVersion {
		fmt.Println(model.GoStunVersion)
		return
	}
	if model.EnableLoger {
		var logLevel logging.LogLevel
		switch model.Verbose {
		case 0:
			logLevel = logging.LogLevelWarn // default
		case 1:
			logLevel = logging.LogLevelInfo
		case 2:
			logLevel = logging.LogLevelDebug
		case 3:
			logLevel = logging.LogLevelTrace
		}
		model.Log = logging.NewDefaultLeveledLoggerForScope("", logLevel, os.Stdout)
	}
	if model.AddrStr != "stun.voipgate.com:3478" {
		if err := stuncheck.MappingTests(model.AddrStr); err != nil {
			if model.EnableLoger {
				model.NatMappingBehavior = "inconclusive"
			}
			model.Log.Warn("NAT mapping behavior: inconclusive")
		}
		if err := stuncheck.FilteringTests(model.AddrStr); err != nil {
			if model.EnableLoger {
				model.NatFilteringBehavior = "inconclusive"
			}
			model.Log.Warn("NAT filtering behavior: inconclusive")
		}
	} else {
		addrStrPtrList := []string{
			"stun.voipgate.com:3478",
			"stun.miwifi.com:3478",
			"stunserver.stunprotocol.org:3478",
		}
		checkStatus := true
		for _, addrStr := range addrStrPtrList {
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
		}
	}
	res := stuncheck.CheckType()
	fmt.Printf("NAT Type: %s\n", res)
}
