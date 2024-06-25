package model

import "github.com/pion/logging"

const GoStunVersion = "v0.0.2"

var (
	AddrStr              = "stun.voipgate.com:3478"
	Timeout              = 3
	Verbose              = 0
	Log                  logging.LeveledLogger
	NatMappingBehavior   string
	NatFilteringBehavior string
	EnableLoger          = true
)
