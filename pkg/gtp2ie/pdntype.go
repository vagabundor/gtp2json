package gtp2ie

import (
	"fmt"
	"gtp2json/config"
)

// PDNTypeNames maps the numerical codes to PDN type descriptions (3GPPP TS 29.274 8.34)
var PDNTypeNames = map[byte]string{
	1: "IPv4",
	2: "IPv6",
	3: "IPv4v6",
	4: "Non-IP",
	5: "Ethernet",
}

// DecodePDNType decodes the PDN Type from a single-byte slice
func DecodePDNType(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("insufficient data for PDN Type")
	}
	pdnType := data[0]
	description, exists := PDNTypeNames[pdnType]
	if !exists {
		return "", fmt.Errorf("unknown PDN Type value: %d", pdnType)
	}

	format := config.GetOutputFormat()
	switch format {
	case "numeric":
		return pdnType, nil
	case "text":
		return description, nil
	case "mixed":
		return fmt.Sprintf("%s (%d)", description, pdnType), nil
	default:
		return pdnType, nil
	}
}
