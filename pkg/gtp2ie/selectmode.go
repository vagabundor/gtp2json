package gtp2ie

import (
	"fmt"
	"gtp2json/config"
)

// SelectionModeNames maps the numerical codes to detailed descriptions (3GPPP TS 29.274 8.58)
var SelectionModeNames = map[byte]string{
	0: "MS or network provided APN, subscription verified",
	1: "MS provided APN, subscription not verified",
	2: "Network provided APN, subscription not verified",
	3: "For future use (interpreted as 'Network provided APN, subscription not verified')",
}

// DecodeSelectionMode decodes the Selection Mode from a single-byte slice
func DecodeSelectionMode(data []byte) (string, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("insufficient data for Selection Mode")
	}

	modeDesc, exists := SelectionModeNames[data[0]]
	if !exists {
		return "", fmt.Errorf("unknown Selection Mode value: %d", data[0])
	}

	format := config.GetOutputFormat()
	mode := ""
	switch format {
	case "numeric":
		mode = fmt.Sprintf("%d", data[0])
	case "text":
		mode = modeDesc
	case "mixed":
		mode = fmt.Sprintf("%s (%d)", modeDesc, data[0])
	default:
		mode = fmt.Sprintf("%d", data[0])
	}

	return mode, nil
}
