package gtp2ie

import "fmt"

// Indication represents Indication IE (3GPPP TS 29.274 8.12)
type Indication struct {
	DAF   bool // Dual Address Bearer Flag
	DTF   bool // Direct Tunnel Flag
	HI    bool // Handover Indication
	DFI   bool // Direct Forwarding Indication
	OI    bool // Operation Indication
	ISRSI bool // Idle mode Signalling Reduction Supported Indication
	ISRAI bool // Idle mode Signalling Reduction Activation Indication
	SGWCI bool // SGW Change Indication
	SQCI  bool // Subscribed QoS Change Indication
	UIMSI bool // Unauthenticated IMSI
	CFSI  bool // Change F-TEID support indication
	CRSI  bool // Change Reporting support indication
	PS    bool // Piggybacking Supported
	PT    bool // Protocol Type
	SI    bool // Scope Indication
	MSV   bool // MS Validated
}

// DecodeIndication decodes the bits of the Indication IE to determine active flags
func DecodeIndication(data []byte) (interface{}, error) {
	if len(data) < 2 {
		return Indication{}, fmt.Errorf("insufficient data for Indication")
	}

	flags := Indication{
		DAF:   data[0]&0x80 != 0,
		DTF:   data[0]&0x40 != 0,
		HI:    data[0]&0x20 != 0,
		DFI:   data[0]&0x10 != 0,
		OI:    data[0]&0x08 != 0,
		ISRSI: data[0]&0x04 != 0,
		ISRAI: data[0]&0x02 != 0,
		SGWCI: data[0]&0x01 != 0,
		SQCI:  data[1]&0x80 != 0,
		UIMSI: data[1]&0x40 != 0,
		CFSI:  data[1]&0x20 != 0,
		CRSI:  data[1]&0x10 != 0,
		PS:    data[1]&0x08 != 0,
		PT:    data[1]&0x04 != 0,
		SI:    data[1]&0x02 != 0,
		MSV:   data[1]&0x01 != 0,
	}

	return flags, nil
}
