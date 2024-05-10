package gtp2ie

import (
	"encoding/binary"
	"fmt"
)

// AMBR represents the AMBR values for uplink and downlink in kbps.
type AMBR struct {
	Uplink   uint32 `json:"Uplink"`
	Downlink uint32 `json:"Downlink"`
}

// DecodeAMBR decodes the AMBR from a byte slice.
func DecodeAMBR(data []byte) (interface{}, error) {
	if len(data) < 8 {
		return AMBR{}, fmt.Errorf("insufficient data for AMBR: expected at least 8 bytes, got %d", len(data))
	}

	uplink := binary.BigEndian.Uint32(data[:4])
	downlink := binary.BigEndian.Uint32(data[4:8])

	return AMBR{
		Uplink:   uplink,
		Downlink: downlink,
	}, nil
}
