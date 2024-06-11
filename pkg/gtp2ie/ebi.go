package gtp2ie

import "fmt"

// EBI represents an EPS Bearer Identity
type EBI uint8

// DecodeEBI decodes the EBI from a single-byte slice.
func DecodeEBI(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("insufficient data for EBI: expected at least 1 byte, got %d", len(data))
	}

	ebi := EBI(data[0] & 0x0F)
	if ebi < 1 || ebi > 15 {
		return 0, fmt.Errorf("invalid EBI value: %d", ebi)
	}

	return ebi, nil
}
