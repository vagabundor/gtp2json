package gtp2ie

import (
	"fmt"
	"github.com/vagabundor/gtp2json/config"
)

// RATTypeNames maps RAT type values to their descriptions
var RATTypeNames = map[byte]string{
	1:  "UTRAN",
	2:  "GERAN",
	3:  "WLAN",
	4:  "GAN",
	5:  "HSPA Evolution",
	6:  "EUTRAN",
	7:  "Virtual",
	8:  "EUTRAN-NB-IoT",
	9:  "LTE-M",
	10: "NR",
	11: "WB-E-UTRAN(LEO)",
	12: "WB-E-UTRAN(MEO)",
	13: "WB-E-UTRAN(GEO)",
	14: "WB-E-UTRAN(OTHERSAT)",
	15: "EUTRAN-NB-IoT(LEO)",
	16: "EUTRAN-NB-IoT(MEO)",
	17: "EUTRAN-NB-IoT(GEO)",
	18: "EUTRAN-NB-IoT(OTHERSAT)",
	19: "LTE-M(LEO)",
	20: "LTE-M(MEO)",
	21: "LTE-M(GEO)",
	22: "LTE-M(OTHERSAT)",
}

// DecodeRATType decodes the RAT Type from a single-byte slice
func DecodeRATType(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("insufficient data for RAT Type")
	}

	format := config.GetOutputFormat()
	ratType := data[0]
	description, exists := RATTypeNames[ratType]
	if !exists {
		return fmt.Sprintf("Unknown RAT Type (%d)", ratType), nil
	}

	var ratTypeFormatted interface{}
	switch format {
	case "numeric":
		ratTypeFormatted = ratType
	case "text":
		ratTypeFormatted = description
	case "mixed":
		ratTypeFormatted = fmt.Sprintf("%s (%d)", description, ratType)
	default:
		ratTypeFormatted = ratType
	}

	return ratTypeFormatted, nil
}
