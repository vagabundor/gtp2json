package gtp2ie

import (
	"encoding/hex"
	"fmt"
	"gtp2json/pkg/gtp2"
)

const (
	IETypeIMSI                    = 1
	IETypeMSISDN                  = 76
	IETypeMEI                     = 75
	IETypeFTEID                   = 87
	IETypeULI                     = 86
	IETypeServingNet              = 83
	IETypeRATType                 = 82
	IETypeIndication              = 77
	IETypeAPN                     = 71
	IETypeSelectionMode           = 128
	IETypePDNType                 = 99
	IETypePAA                     = 79
	IETypeAPNRestriction          = 127
	IETypeAMBR                    = 72
	IETypePCO                     = 78
	IETypeCause                   = 2
	IETypeEBI                     = 73
	IETypeBearerQoS               = 80
	IETypeBearerContext           = 93
	IETypeRecovery                = 3
	IETypeUETimeZone              = 114
	IETypeChargingCharacteristics = 95
)

// ieTypeNames maps IE types to their string representations
var ieTypeNames = map[uint8]string{
	IETypeIMSI:                    "IMSI",
	IETypeMSISDN:                  "MSISDN",
	IETypeMEI:                     "MEI",
	IETypeFTEID:                   "F-TEID",
	IETypeULI:                     "ULI",
	IETypeServingNet:              "ServingNetwork",
	IETypeRATType:                 "RATType",
	IETypeIndication:              "Indication",
	IETypeAPN:                     "APN",
	IETypeSelectionMode:           "SelectionMode",
	IETypePDNType:                 "PDNType",
	IETypePAA:                     "PAA",
	IETypeAPNRestriction:          "APNRestriction",
	IETypeAMBR:                    "AMBR",
	IETypePCO:                     "PCO",
	IETypeCause:                   "Cause",
	IETypeEBI:                     "EBI",
	IETypeBearerQoS:               "BearerQoS",
	IETypeBearerContext:           "BearerContext",
	IETypeRecovery:                "Recovery",
	IETypeUETimeZone:              "UETimeZone",
	IETypeChargingCharacteristics: "ChargingCharacteristics",
}

// ProcessIE decodes the content of a given IE based on its type
func ProcessIE(ie gtp2.IE) (string, interface{}, error) {

	ieName, ok := ieTypeNames[ie.Type]
	if !ok {
		// Unknown type encode to hex
		return fmt.Sprintf("unknown_type_%d", ie.Type), hex.EncodeToString(ie.Content), nil
	}

	var decodeFunc func([]byte) (interface{}, error)
	switch ie.Type {
	case IETypeIMSI, IETypeMSISDN, IETypeMEI:
		decodeFunc = DecodeBCD
	case IETypeFTEID:
		decodeFunc = DecodeFTEID
	case IETypeULI:
		decodeFunc = DecodeULI
	case IETypeServingNet:
		decodeFunc = DecodeServingNet
	case IETypeRATType:
		decodeFunc = DecodeRATType
	case IETypeIndication:
		decodeFunc = DecodeIndication
	case IETypeAPN:
		decodeFunc = DecodeAPN
	case IETypeSelectionMode:
		decodeFunc = DecodeSelectionMode
	case IETypePDNType:
		decodeFunc = DecodePDNType
	case IETypePAA:
		decodeFunc = DecodePAA
	case IETypeAPNRestriction:
		decodeFunc = DecodeAPNRestriction
	case IETypeAMBR:
		decodeFunc = DecodeAMBR
	case IETypePCO:
		decodeFunc = DecodePCO
	case IETypeCause:
		decodeFunc = DecodeCause
	case IETypeEBI:
		decodeFunc = DecodeEBI
	case IETypeBearerQoS:
		decodeFunc = DecodeBearerQoS
	case IETypeBearerContext:
		decodeFunc = DecodeBearerContext
	case IETypeRecovery:
		decodeFunc = DecodeRecovery
	case IETypeUETimeZone:
		decodeFunc = DecodeUETimeZone
	case IETypeChargingCharacteristics:
		decodeFunc = DecodeChargingCharacteristics
	default:
		return ieName, hex.EncodeToString(ie.Content), nil
	}

	decodedContent, err := decodeFunc(ie.Content)
	if err != nil {
		return ieName, nil, fmt.Errorf("failed to decode %s: %w", ieName, err)
	}

	return ieName, decodedContent, nil
}
