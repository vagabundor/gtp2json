package gtp2ie

import "fmt"

// DecodeEBI decodes the EBI from a single-byte slice.
func DecodeEBI(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("insufficient data for EBI: expected at least 1 byte, got %d", len(data))
	}

	ebi := data[0] & 0x0F
	if ebi < 1 || ebi > 15 {
		return nil, fmt.Errorf("invalid EBI value: %d", ebi)
	}

	return ebi, nil
}
