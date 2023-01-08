package oscar

import (
	"encoding/binary"
)

func NewSNAC(foodgroup uint16, subgroup uint16, flags uint16, requestID uint32, data []byte) *SNACMessage {
	return &SNACMessage{
		Foodgroup: foodgroup,
		Subgroup:  subgroup,
		Flags:     flags,
		RequestID: requestID,
		Data:      data,
	}
}

func SNACSerialize(snac []byte) *SNACMessage {
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

func SNACDeserialize(message *SNACMessage) []byte {
	snac := make([]byte, len(message.Data)+10)

	binary.BigEndian.PutUint16(snac[0:2], message.Foodgroup)
	binary.BigEndian.PutUint16(snac[2:4], message.Subgroup)

	binary.BigEndian.PutUint16(snac[4:6], message.Flags)
	binary.BigEndian.PutUint32(snac[6:10], message.RequestID)

	copy(snac[10:], message.Data)
	return snac
}
