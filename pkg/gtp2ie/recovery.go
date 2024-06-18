package gtp2ie

import (
	"fmt"
)

// Recovery represents the Recovery IE containing the restart counter.
type Recovery uint8

// DecodeRecovery decodes the Recovery IE from a single-byte slice.
func DecodeRecovery(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("insufficient data for Recovery: expected at least 1 byte, got %d", len(data))
	}

	restartCounter := Recovery(data[0])

	return restartCounter, nil
}
