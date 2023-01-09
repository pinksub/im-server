package oscar

import (
	"bytes"
	"chimera/network"
	"chimera/utility/logging"
	"chimera/utility/tcp"
	"encoding/binary"
)

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
			ResetSequence(context)

			flap := NewFLAP(FrameSignOn, context.ServerSequence, []byte{0x00, 0x00, 0x00, 0x01})

			client.Connection.BinaryWriteTraffic(FLAPDeserialize(flap))

			for {
				combined, err := client.Connection.BinaryReadTraffic()
				if err != nil {
					break
				}

				packets, err := FLAPSerialize(combined)
				if err != nil {
					break
				}

				for _, packet := range packets {
					if packet.Frame == FrameData {
						snac := SNACSerialize(packet.Data)

						if snac.Foodgroup == FoodgroupBUCP {
							BUCPIncomingSNACData(client, context, snac)
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
			ResetSequence(context)

			flap := NewFLAP(FrameSignOn, context.ServerSequence, []byte{0x00, 0x00, 0x00, 0x01})
			client.Connection.BinaryWriteTraffic(FLAPDeserialize(flap))

			for {
				logging.Info("OSCAR/BOS", "step")
				combined, err := client.Connection.BinaryReadTraffic()
				if err != nil {
					break
				}

				packets, err := FLAPSerialize(combined)
				if err != nil {
					break
				}

				for _, packet := range packets {
					switch packet.Frame {
					case FrameSignOn:
						tlvs, err := TLVsDeserialize(packet.Data[4:])
						if err != nil {
							return
						}

						cookieTlv := FindTLV(tlvs, 0x0006)
						if cookieTlv == nil {
							return
						}

						for _, clientContext := range clientContexts {
							if bytes.Equal(clientContext.BOSCookie, cookieTlv.Value) {
								logging.Info("OSCAR/BOS", "Matching cookie attempt found")
								clientContext.ServerSequence = context.ServerSequence
								context = clientContext

								logging.Info("OSCAR/BOS", "Sending supported services")

								foodgroups := make([]byte, 0)
								for _, supportedFoodgroup := range supportedFoodgroups {
									binary.BigEndian.AppendUint16(foodgroups, supportedFoodgroup)
								}

								IncrementSequence(context)

								snac := NewSNAC(FoodgroupOSERVICE, OSERVICEHostOnline, 0, 0, foodgroups)
								flap = NewFLAP(FrameData, context.ServerSequence, SNACDeserialize(snac))
								client.Connection.BinaryWriteTraffic(FLAPDeserialize(flap))
							}
						}

						logging.Warn("OSCAR/BOS", "No matching cookie attempt?")

					case FrameData:
						//snac := SNACSerialize(packet.Data)

					}
				}
			}
		}()
	}
}
