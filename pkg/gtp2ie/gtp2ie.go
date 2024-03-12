package gtp2ie

import (
	"encoding/hex"
	"fmt"
	"gtp2json/pkg/gtp2"
)

const (
	IETypeIMSI   = 1
	IETypeMSISDN = 76
	IETypeMEI    = 75
)

var ieTypeNames = map[uint8]string{
	IETypeIMSI:   "imsi",
	IETypeMSISDN: "msisdn",
	IETypeMEI:    "mei",
}

func ProcessIE(ie gtp2.IE) (string, interface{}, error) {

	ieName, ok := ieTypeNames[ie.Type]
	if !ok {
		// Unknown type encode to hex
		return fmt.Sprintf("unknown_type_%d", ie.Type), hex.EncodeToString(ie.Content), nil
	}

	switch ie.Type {
	case IETypeIMSI, IETypeMSISDN: // Group for BCD types
		decodedContent, err := DecodeBCD(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil
	default:
		// Unknown type encode to hex
		return ieName, hex.EncodeToString(ie.Content), nil
	}
}

func DecodeBCD(content []byte) (string, error) {
	var decoded string

	for _, b := range content {
		// First digit
		firstDigit := b & 0x0F
		if firstDigit == 0xF {
			break
		}
		decoded += fmt.Sprintf("%d", firstDigit)

		// Second digit
		secondDigit := (b >> 4) & 0x0F
		if secondDigit == 0xF {
			break
		}
		decoded += fmt.Sprintf("%d", secondDigit)
	}

	return decoded, nil
}

func processMSISDN(content []byte) string {
	return string(content)
}
