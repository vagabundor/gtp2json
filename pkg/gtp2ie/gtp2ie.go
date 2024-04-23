package gtp2ie

import (
	"encoding/hex"
	"fmt"
	"gtp2json/pkg/gtp2"
)

const (
	IETypeIMSI       = 1
	IETypeMSISDN     = 76
	IETypeMEI        = 75
	IETypeFTEID      = 87
	IETypeULI        = 86
	IETypeServingNet = 83
	IETypeRATType    = 82
	IETypeIndication = 77
	IETypeAPN        = 71
)

// ieTypeNames maps IE types to their string representations
var ieTypeNames = map[uint8]string{
	IETypeIMSI:       "IMSI",
	IETypeMSISDN:     "MSISDN",
	IETypeMEI:        "MEI",
	IETypeFTEID:      "F-TEID",
	IETypeULI:        "ULI",
	IETypeServingNet: "ServingNetwork",
	IETypeRATType:    "RATType",
	IETypeIndication: "Indication",
	IETypeAPN:        "APN",
}

// ProcessIE decodes the content of a given IE based on its type
func ProcessIE(ie gtp2.IE) (string, interface{}, error) {

	ieName, ok := ieTypeNames[ie.Type]
	if !ok {
		// Unknown type encode to hex
		return fmt.Sprintf("unknown_type_%d", ie.Type), hex.EncodeToString(ie.Content), nil
	}

	switch ie.Type {
	case IETypeIMSI, IETypeMSISDN, IETypeMEI: // Group for BCD types
		decodedContent, err := DecodeBCD(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil
	case IETypeFTEID:
		decodedContent, err := DecodeFTEID(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil
	case IETypeULI:
		decodedContent, err := DecodeULI(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil
	case IETypeServingNet:
		decodedContent, err := DecodeServingNet(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil
	case IETypeRATType:
		decodedContent, err := DecodeRATType(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil
	case IETypeIndication:
		decodedContent, err := DecodeIndication(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil
	case IETypeAPN:
		decodedContent, err := DecodeAPN(ie.Content)
		if err != nil {
			return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
		}
		return ieName, decodedContent, nil

	default:
		// Unknown type encode to hex
		return ieName, hex.EncodeToString(ie.Content), nil
	}
}
