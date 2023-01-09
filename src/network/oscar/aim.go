package oscar

import (
	"chimera/network"
	"chimera/utility/logging"
	"chimera/utility/tcp"
)

func LaunchOSCAR() {
	// cheapo method of launching multiple listeners ig
	go ListenBUCP() // Port 5190
	go ListenBOS()  // Port 5191
}

func ListenBUCP() {
	// The BUCP server listens on 5190 and handles authentication, then the client is transported to the BOS server which listens on 5191
	// Right now the BUCP server is the only one which is listening
	tcpServer := tcp.CreateListener(5190)

	for {
		err := tcpServer.AcceptClient()

		go func() {
			if err != nil {
				logging.Error("OSCAR/BUCP", "Failed to accept client! (%s)", err.Error())
				return
			}

			logging.Info("OSCAR", "Client awaiting authentication (IP: %s)", tcpServer.GetRemoteAddress())

			client := &network.Client{
				Connection: tcpServer,
			}

			context := &OSCARContext{}
			OSCARClearServerSequence(context)

			flap := OSCARNewFLAPPacket(FrameSignOn, context.ServerSequence, []byte{0x00, 0x00, 0x00, 0x01})

			client.Connection.BinaryWriteTraffic(OSCARDeserializeFLAP(flap))

			for {
				combined, err := client.Connection.BinaryReadTraffic()
				if err != nil {
					break
				}

				packets, err := OSCARSerializeFLAP(combined)
				if err != nil {
					break
				}

				for _, packet := range packets {
					if packet.Frame == FrameData {
						snac := OSCARSerializeSNAC(packet.Data)

						if snac.Foodgroup == FoodgroupBUCP {
							OSCARHandleBUCPIncomingSNACData(client, context, snac)
						}
					}
				}
			}

			client.Connection.CloseConnection()
		}()
	}
}

func ListenBOS() {

	tcpServer := tcp.CreateListener(5191)

	for {
		err := tcpServer.AcceptClient()

		go func() {
			if err != nil {
				logging.Error("OSCAR/BOS", "Failed to accept client! (%s)", err.Error())
				return
			}

			logging.Info("OSCAR", "Client awaiting connection (IP: %s)", tcpServer.GetRemoteAddress())

			client := &network.Client{
				Connection: tcpServer,
			}

			context := &OSCARContext{}
			OSCARClearServerSequence(context)

			flap := OSCARNewFLAPPacket(FrameSignOn, context.ServerSequence, []byte{0x00, 0x00, 0x00, 0x01})
			client.Connection.BinaryWriteTraffic(OSCARDeserializeFLAP(flap))

			for {
				logging.Debug("OSCAR/BOS", "step")
				combined, err := client.Connection.BinaryReadTraffic()
				if err != nil {
					break
				}

				packets, err := OSCARSerializeFLAP(combined)
				if err != nil {
					break
				}

				for _, packet := range packets {
					OSCARHandleBOSFrameDataFromFLAP(client, context, packet)
				}
			}
		}()
	}
}
