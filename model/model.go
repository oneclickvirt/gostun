package model

import "github.com/pion/logging"

const GoStunVersion = "v0.0.5"

var (
	AddrStr              = "stun.voipgate.com:3478"
	Timeout              = 5
	Verbose              = 0
	Log                  logging.LeveledLogger
	NatMappingBehavior   string
	NatFilteringBehavior string
	EnableLoger          = true
	IPVersion            = "ipv4"
	TransmissionProtocol = "udp"
)

func GetDefaultServers(IPVersion string) []string {
	switch IPVersion {
	case "ipv6":
		return []string{
			"stun.hot-chilli.net:3478",
			"stun.ipfire.org:3478",
			"stun.flashdance.cx:3478",
			"stun.cloudflare.com:3478",
			"stun.f.haeder.net:3478",
			"stun.l.google.com:19302",
		}
	case "ipv4":
		return []string{
			"stun.voipgate.com:3478",
			"stun.miwifi.com:3478",
			"stun.fitauto.ru:3478",
			"stun.internetcalls.com:3478",
			"stun.voip.aebc.com:3478",
			"stun.voipbuster.com:3478",
			"stun.voipstunt.com:3478",
			"stun.hot-chilli.net:3478",
			"stunserver.stunprotocol.org:3478",
		}
	default:
		return []string{
			"stun.voipgate.com:3478",
			"stun.miwifi.com:3478",
			"stun.fitauto.ru:3478",
			"stun.internetcalls.com:3478",
			"stun.voip.aebc.com:3478",
			"stun.voipbuster.com:3478",
			"stun.voipstunt.com:3478",
			"stun.hot-chilli.net:3478",
			"stunserver.stunprotocol.org:3478",
			"stun.l.google.com:19302",
			"stun.ipfire.org:3478",
			"stun.flashdance.cx:3478",
			"stun.cloudflare.com:3478",
			"stun.f.haeder.net:3478",
		}
	}
}
