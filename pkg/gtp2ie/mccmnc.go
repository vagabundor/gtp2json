package gtp2ie

import "fmt"

type MCCMNC struct {
	MCC string `json:"MCC,omitempty"`
	MNC string `json:"MNC,omitempty"`
}

// DecodeMCCMNC decodes Mobile Country Code (MCC) and Mobile Network Code (MNC)
// from a 3-byte slice using Binary-Coded Decimal (BCD) format
func DecodeMCCMNC(data []byte) (MCCMNC, error) {
	if len(data) < 3 {
		return MCCMNC{}, fmt.Errorf("data is too short")
	}

	mcc := fmt.Sprintf("%d%d%d", (data[0] & 0x0F), (data[0] >> 4), (data[1] & 0x0F))

	mnc1 := (data[2] & 0x0F)
	mnc2 := (data[2] >> 4) & 0x0F
	mnc3 := (data[1] >> 4) & 0x0F

	var mnc string
	if mnc3 == 0xF {
		mnc = fmt.Sprintf("%d%d", mnc1, mnc2)
	} else {
		mnc = fmt.Sprintf("%d%d%d", mnc1, mnc2, mnc3)
	}

	return MCCMNC{
		MCC: mcc,
		MNC: mnc,
	}, nil
}
