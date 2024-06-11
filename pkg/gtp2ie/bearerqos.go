package gtp2ie

import (
	"fmt"
)

// BearerQoS represents the quality of service parameters for a network bearer (3GPP TS 29.274 8.15)
type BearerQoS struct {
	PCI   bool   // Pre-emption Capability
	PL    uint8  // Priority Level
	PVI   bool   // Pre-emption Vulnerability
	QCI   uint8  // QCI Label
	MBRUL uint64 // Maximum Bit Rate for Uplink
	MBRDL uint64 // Maximum Bit Rate for Downlink
	GBRUL uint64 // Guaranteed Bit Rate for Uplink
	GBRDL uint64 // Guaranteed Bit Rate for Downlink
}

// DecodeBearerQoS decodes the Bearer QoS information element from a byte slice.
func DecodeBearerQoS(data []byte) (interface{}, error) {
	if len(data) < 22 {
		return nil, fmt.Errorf("insufficient data for Bearer QoS: expected at least 22 bytes, got %d", len(data))
	}

	flags := data[0]
	pci := (flags & 0x40) == 0 // Disabled (False) if bit = 1
	pl := (flags >> 2) & 0x0F
	pvi := (flags & 0x01) == 0 // Disabled (False) if bit = 1
	label := data[1]

	uplinkMax := decodeFiveByteInteger(data[2:7])
	downlinkMax := decodeFiveByteInteger(data[7:12])
	uplinkGuaranteed := decodeFiveByteInteger(data[12:17])
	downlinkGuaranteed := decodeFiveByteInteger(data[17:22])

	return BearerQoS{
		PCI:   pci,
		PL:    pl,
		PVI:   pvi,
		QCI:   label,
		MBRUL: uplinkMax,
		MBRDL: downlinkMax,
		GBRUL: uplinkGuaranteed,
		GBRDL: downlinkGuaranteed,
	}, nil
}

// decodeFiveByteInteger decodes a 5-byte integer from a byte slice
func decodeFiveByteInteger(bytes []byte) uint64 {
	if len(bytes) < 5 {
		return 0
	}

	return uint64(bytes[0])<<32 | uint64(bytes[1])<<24 | uint64(bytes[2])<<16 | uint64(bytes[3])<<8 | uint64(bytes[4])
}
