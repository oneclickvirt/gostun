package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

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

// normalizeBoolArgs converts space-separated bool flag values to the = form
// that the standard flag package requires, e.g. "-e false" → "-e=false".
// It also drops empty tokens that arise from multiple spaces.
func normalizeBoolArgs(args []string) []string {
	boolFlags := map[string]bool{
		"h": true, "v": true, "e": true, "json": true, "structured": true,
	}
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		if strings.HasPrefix(arg, "-") && !strings.Contains(arg, "=") {
			name := strings.TrimLeft(arg, "-")
			if boolFlags[name] && i+1 < len(args) {
				next := strings.ToLower(strings.TrimSpace(args[i+1]))
				if next == "true" || next == "false" {
					out = append(out, arg+"="+next)
					i++
					continue
				}
			}
		}
		out = append(out, arg)
	}
	return out
}

func main() {
	var showVersion, help, structured bool
	var concurrency int
	gostunFlag := flag.NewFlagSet("gostun", flag.ContinueOnError)
	gostunFlag.BoolVar(&help, "h", false, "Display help information")
	gostunFlag.BoolVar(&showVersion, "v", false, "Display version information")
	gostunFlag.IntVar(&model.Verbose, "verbose", 0, "Set verbosity level")
	gostunFlag.IntVar(&model.Timeout, "timeout", 3, "Set timeout in seconds for STUN server response")
	gostunFlag.StringVar(&model.AddrStr, "server", "stun.voipgate.com:3478", "Specify STUN server address")
	gostunFlag.BoolVar(&model.EnableLoger, "e", true, "Enable logging functionality")
	gostunFlag.StringVar(&model.IPVersion, "type", "ipv4", "Specify ip test version: ipv4, ipv6 or both")
	gostunFlag.StringVar(&model.Interface, "interface", "", "Bind to a specific network interface (e.g. eth0, eth1); empty means all interfaces")
	gostunFlag.BoolVar(&structured, "json", false, "Output structured NAT summary as JSON")
	gostunFlag.BoolVar(&structured, "structured", false, "Alias for -json")
	gostunFlag.IntVar(&concurrency, "concurrency", 0, "Structured mode maximum concurrent STUN probes")
	if err := gostunFlag.Parse(normalizeBoolArgs(os.Args[1:])); err != nil {
		os.Exit(2)
	}
	userSetFlags := make(map[string]bool)
	gostunFlag.Visit(func(f *flag.Flag) { userSetFlags[f.Name] = true })
	if help {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		gostunFlag.PrintDefaults()
		return
	}
	if showVersion {
		go func() {
			http.Get("https://hits.spiritlhl.net/gostun.svg?action=hit&title=Hits&title_bg=%23555555&count_bg=%230eecf8&edge_flat=false")
		}()
		fmt.Println("Repo:", "https://github.com/oneclickvirt/gostun")
		fmt.Println(model.GoStunVersion)
		return
	}
	model.IPVersion = strings.ToLower(strings.TrimSpace(model.IPVersion))
	if err := validateCLIOptions(gostunFlag.Args(), structured, concurrency, userSetFlags); err != nil {
		fmt.Fprintln(os.Stderr, sanitizeErrorText(err.Error()))
		os.Exit(2)
	}
	if structured {
		servers := []string{}
		if userSetFlags["server"] && strings.TrimSpace(model.AddrStr) != "" {
			for _, server := range strings.Split(model.AddrStr, ",") {
				if server = strings.TrimSpace(server); server != "" {
					servers = append(servers, server)
				}
			}
		}
		config := stuncheck.ProbeConfig{
			Servers:       servers,
			IPVersion:     model.IPVersion,
			Timeout:       time.Duration(model.Timeout) * time.Second,
			MaxConcurrent: concurrency,
		}
		if err := writeStructuredSummary(context.Background(), os.Stdout, config, stuncheck.ProbeNAT); err != nil {
			fmt.Fprintf(os.Stderr, "structured NAT probe failed: %s\n", sanitizeErrorText(err.Error()))
			os.Exit(1)
		}
		return
	}
	go func() {
		http.Get("https://hits.spiritlhl.net/gostun.svg?action=hit&title=Hits&title_bg=%23555555&count_bg=%230eecf8&edge_flat=false")
	}()
	fmt.Println("Repo:", "https://github.com/oneclickvirt/gostun")
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
	if userSetFlags["server"] {
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
	fmt.Printf("%s\n", indentLegacyOutput("NAT Type: "+res))
}

func validateCLIOptions(positional []string, structured bool, concurrency int, userSet map[string]bool) error {
	if len(positional) != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(positional, " "))
	}
	if model.IPVersion != "ipv4" && model.IPVersion != "ipv6" && model.IPVersion != "both" {
		return fmt.Errorf("-type only supports ipv4, ipv6, or both")
	}
	if model.Timeout <= 0 {
		return fmt.Errorf("-timeout must be positive")
	}
	if model.Verbose < 0 || model.Verbose > 3 {
		return fmt.Errorf("-verbose must be between 0 and 3")
	}
	if concurrency < 0 || (userSet["concurrency"] && concurrency == 0) {
		return fmt.Errorf("-concurrency must be positive when specified")
	}
	if userSet["concurrency"] && !structured {
		return fmt.Errorf("-concurrency requires -json or -structured")
	}
	if structured && (userSet["verbose"] || userSet["e"]) {
		return fmt.Errorf("-verbose and -e are not used with structured output")
	}
	if userSet["interface"] && strings.TrimSpace(model.Interface) == "" {
		return fmt.Errorf("-interface must not be empty when specified")
	}
	if userSet["server"] {
		servers := []string{model.AddrStr}
		if structured {
			servers = strings.Split(model.AddrStr, ",")
		} else if strings.Contains(model.AddrStr, ",") {
			return fmt.Errorf("multiple -server values require structured output")
		}
		for _, server := range servers {
			server = strings.TrimSpace(server)
			host, port, err := net.SplitHostPort(server)
			if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
				return fmt.Errorf("invalid STUN server address")
			}
			if _, err := net.LookupPort("udp", port); err != nil {
				return fmt.Errorf("invalid STUN server address")
			}
		}
	}
	return nil
}

func writeStructuredSummary(ctx context.Context, output io.Writer, config stuncheck.ProbeConfig, probe func(context.Context, stuncheck.ProbeConfig) stuncheck.NATSummary) error {
	if probe == nil {
		return fmt.Errorf("structured NAT probe is nil")
	}
	summary := probe(ctx, config)
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}
