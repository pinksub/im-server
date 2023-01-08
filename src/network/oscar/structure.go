package oscar

type OSCARContext struct {
	ServerSequence uint16
	ClientSequence uint16
	Challenge      []byte
	BOSCookie      []byte
	UIN            int
}

type FLAPPacket struct {
	Frame      byte
	Sequence   uint16
	DataLength uint16
	Data       []byte
}

type SNACMessage struct {
	Foodgroup uint16
	Subgroup  uint16
	Flags     uint16
	RequestID uint32
	Data      []byte
}

type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// Foodgroups
const (
	FoodgroupBUCP = 0x0017
)

// FLAP
const (
	FrameSignOn  = 0x01
	FrameData    = 0x02
	FrameError   = 0x03
	FrameSignOff = 0x04
)

// BUCP
const (
	SubgroupLoginRequest      = 0x0002
	SubgroupLoginResponse     = 0x0003
	SubgroupChallengeRequest  = 0x0006
	SubgroupChallengeResponse = 0x0007
)

var clientContexts []*OSCARContext
