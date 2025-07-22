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
	if IPVersion == "ipv6" {
		return []string{
			"[2001:4860:4860::8888]:19302",
			"[2001:4860:4860::8844]:19302",
		}
	} else if IPVersion == "ipv4" {
		return []string{
			"stun.voipgate.com:3478",
			"stun.miwifi.com:3478",
			"stunserver.stunprotocol.org:3478",
		}
	} else {
		return []string{
			"stun.voipgate.com:3478",
			"stun.miwifi.com:3478",
			"stunserver.stunprotocol.org:3478",
			"[2001:4860:4860::8888]:19302",
			"[2001:4860:4860::8844]:19302",
		}
	}
}
