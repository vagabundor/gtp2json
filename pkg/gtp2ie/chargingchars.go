package gtp2ie

import (
	"encoding/hex"
	"fmt"
)

// ChargingChars represents the charging characteristics
type ChargingChars struct {
	RawValue string `json:"ChargingCharacteristic"`
}

// DecodeChargingChars decodes the Charging Characteristics IE from a byte slice
func DecodeChargingChars(data []byte) (interface{}, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("insufficient data for Charging Characteristics: expected at least 2 bytes, got %d", len(data))
	}

	rawValue := fmt.Sprintf("0x%s", hex.EncodeToString(data[:2]))

	return ChargingChars{RawValue: rawValue}, nil
}
