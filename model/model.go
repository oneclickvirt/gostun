package model

import "github.com/pion/logging"

const GoStunVersion = "v0.0.4"

var (
	AddrStr              = "stun.voipgate.com:3478"
	Timeout              = 3
	Verbose              = 0
	Log                  logging.LeveledLogger
	NatMappingBehavior   string
	NatFilteringBehavior string
	EnableLoger          = true
	IPVersion            = "ipv4"
)

func GetDefaultServers(IPVersion string) []string {
	switch IPVersion {
	case "ipv6":
		return []string{
			"stun.hot-chilli.net:3478",
			"[2a01:4f8:242:56ca::2]:3478",
		}
	case "ipv4":
		return []string{
			"stun.voipgate.com:3478",
			"stun.miwifi.com:3478",
			"stunserver.stunprotocol.org:3478",
		}
	default:
		return []string{
			"stun.voipgate.com:3478",
			"stun.miwifi.com:3478",
			"stunserver.stunprotocol.org:3478",
			"stun.hot-chilli.net:3478",
			"[2a01:4f8:242:56ca::2]:3478",
		}
	}
}
