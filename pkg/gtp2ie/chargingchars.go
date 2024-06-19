package gtp2ie

import (
	"encoding/hex"
	"fmt"
)

// ChargingCharacteristics represents the charging characteristics
type ChargingCharacteristics struct {
	RawValue string `json:"ChargingCharacteristic"`
}

// DecodeChargingCharacteristics decodes the Charging Characteristics IE from a byte slice
func DecodeChargingCharacteristics(data []byte) (interface{}, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("insufficient data for Charging Characteristics: expected at least 2 bytes, got %d", len(data))
	}

	rawValue := fmt.Sprintf("0x%s", hex.EncodeToString(data[:2]))

	return ChargingCharacteristics{RawValue: rawValue}, nil
}
