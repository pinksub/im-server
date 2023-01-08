package aim

import (
	"chimera/network"
	"chimera/utility/logging"
)

const (
	SubgroupLoginRequest  = 0x0002
	SubgroupLoginResponse = 0x0003

	SubgroupChallengeRequest  = 0x006
	SubgroupChallengeResponse = 0x007
)

func BUCPIncomingSNACData(client network.Client, context AIMContext, message *SNACMessage) {
	switch message.Subgroup {
	case SubgroupChallengeRequest:
		logging.Info("AIM/BUCP", "challenge request")
	}
}
