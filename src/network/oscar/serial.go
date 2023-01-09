package oscar

import (
	"encoding/binary"
	"errors"
)

func OSCARNewFLAPPacket(frame byte, sequence uint16, data []byte) *FLAPPacket {
	return &FLAPPacket{
		Frame:      frame,
		Sequence:   sequence,
		DataLength: uint16(len(data)),
		Data:       data,
	}
}

func OSCARNewSNAC(foodgroup uint16, subgroup uint16, flags uint16, requestID uint32, data []byte) *SNACMessage {
	return &SNACMessage{
		Foodgroup: foodgroup,
		Subgroup:  subgroup,
		Flags:     flags,
		RequestID: requestID,
		Data:      data,
	}
}

func OSCARNewTLV(tlvType uint16, tlvValue []byte) *TLV {
	return &TLV{
		Type:   tlvType,
		Length: uint16(len(tlvValue)),
		Value:  tlvValue,
	}
}

func OSCARSerializeFLAP(flap []byte) ([]*FLAPPacket, error) {
	packets := make([]*FLAPPacket, 0)

	i := 0

	for i < len(flap) {
		if len(flap)-i < 6 {
			return nil, errors.New("incorrect length")
		} else if flap[i] != 0x2A {
			return nil, errors.New("invalid marker")
		}

		packet := &FLAPPacket{
			Frame:      flap[i+1],
			Sequence:   binary.BigEndian.Uint16(flap[i+2 : i+4]),
			DataLength: binary.BigEndian.Uint16(flap[i+4 : i+6]),
		}

		if int(packet.DataLength) > len(flap)-i {
			return nil, errors.New("incorrect length")
		} else if packet.Frame != FrameSignOn && packet.Frame != FrameData && packet.Frame != FrameError && packet.Frame != FrameSignOff {
			return nil, errors.New("incorrect frame")
		}

		packet.Data = make([]byte, packet.DataLength)
		copy(packet.Data, flap[i+6:i+6+int(packet.DataLength)])

		i += 6 + int(packet.DataLength)
		packets = append(packets, packet)
	}

	return packets, nil
}

func OSCARDeserializeFLAP(packet *FLAPPacket) []byte {
	flap := make([]byte, 6+len(packet.Data))

	flap[0] = 0x2A
	flap[1] = packet.Frame

	// I'm so glad I can use slicing here
	binary.BigEndian.PutUint16(flap[2:4], packet.Sequence)
	binary.BigEndian.PutUint16(flap[4:6], uint16(len(packet.Data)))

	copy(flap[6:], packet.Data)
	return flap
}

func OSCARSerializeSNAC(snac []byte) *SNACMessage {
	message := &SNACMessage{
		Foodgroup: binary.BigEndian.Uint16(snac[0:2]),
		Subgroup:  binary.BigEndian.Uint16(snac[2:4]),
		Flags:     binary.BigEndian.Uint16(snac[4:6]),
		RequestID: binary.BigEndian.Uint32(snac[6:10]),
	}
	message.Data = make([]byte, len(snac)-10)
	copy(message.Data, snac[10:])

	return message
}

func OSCARDeserializeSNAC(message *SNACMessage) []byte {
	snac := make([]byte, len(message.Data)+10)

	binary.BigEndian.PutUint16(snac[0:2], message.Foodgroup)
	binary.BigEndian.PutUint16(snac[2:4], message.Subgroup)

	binary.BigEndian.PutUint16(snac[4:6], message.Flags)
	binary.BigEndian.PutUint32(snac[6:10], message.RequestID)

	copy(snac[10:], message.Data)
	return snac
}

func OSCARSerializeTLV(data []byte) (*TLV, error) {
	if len(data) < 4 {
		return nil, errors.New("incorrect length")
	}

	tlv := &TLV{
		Type:   binary.BigEndian.Uint16(data[0:2]),
		Length: binary.BigEndian.Uint16(data[2:4]),
	}

	if len(data) < 4+int(tlv.Length) {
		return nil, errors.New("incorrect length")
	}

	tlv.Value = make([]byte, tlv.Length)
	copy(tlv.Value, data[4:4+tlv.Length])

	return tlv, nil
}

func OSCARDeserializeTLV(tlv *TLV) []byte {
	data := make([]byte, 4+tlv.Length)

	binary.BigEndian.PutUint16(data[0:2], tlv.Type)
	binary.BigEndian.PutUint16(data[2:4], tlv.Length)

	copy(data[4:4+tlv.Length], tlv.Value)

	return data
}

func OSCARDeserializeMultipleTLVs(data []byte) ([]*TLV, error) {
	tlvs := make([]*TLV, 0)

	i := 0

	for i < len(data) {
		tlv, err := OSCARSerializeTLV(data[i:])

		if err != nil {
			return nil, err
		}

		tlvs = append(tlvs, tlv)
		i += 4 + int(tlv.Length)
	}

	return tlvs, nil
}

func OSCARFindTLV(tlvs []*TLV, tlvType uint16) *TLV {
	for _, tlv := range tlvs {
		if tlv.Type == tlvType {
			return tlv
		}
	}
	return nil
}
