package aim

import (
	"encoding/binary"
	"errors"
)

// the TLV itself
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func TLVSerialize(data []byte) (*TLV, error) {
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

func TLVDeserialize(tlv *TLV) []byte {
	data := make([]byte, 4+tlv.Length)

	binary.BigEndian.PutUint16(data[0:2], tlv.Type)
	binary.BigEndian.PutUint16(data[2:4], tlv.Length)

	copy(data[4:4+tlv.Length], tlv.Value)

	return data
}

func TLVsDeserialize(data []byte) ([]*TLV, error) {
	tlvs := make([]*TLV, 0)

	i := 0

	for i < len(data) {
		tlv, err := TLVSerialize(data[i:])

		if err != nil {
			return nil, err
		}

		tlvs = append(tlvs, tlv)
		i += 4+int(tlv.Length)
	}

	return tlvs, nil
}

func FindTLV(tlvs []*TLV, tlvType uint16) *TLV {
	for _, tlv := range tlvs {
		if tlv.Type == tlvType {
			return tlv
		}
	}
	return nil
}