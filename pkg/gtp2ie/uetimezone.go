package gtp2ie

import (
	"fmt"
	"github.com/vagabundor/gtp2json/config"
)

// UETimeZone represents the UE Time Zone IE containing the time zone and DST adjustment.
type UETimeZone struct {
	TimeZone      string      `json:"TimeZone"`
	DSTAdjustment interface{} `json:"DST"`
}

// DST adjustment descriptions
var DSTAdjustmentDescriptions = map[uint8]string{
	0: "No adjustment for Daylight Saving Time",
	1: "+1 hour adjustment for Daylight Saving Time",
	2: "+2 hours adjustment for Daylight Saving Time",
	3: "Reserved",
}

// DecodeUETimeZone decodes the UE Time Zone IE from a byte slice.
func DecodeUETimeZone(data []byte) (interface{}, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("insufficient data for UE Time Zone: expected at least 2 bytes, got %d", len(data))
	}

	timeZoneByte := data[0]
	dstAdjustmentByte := data[1] & 0x03

	sign := "+"
	if timeZoneByte&0x08 != 0 {
		sign = "-"
	}

	// Calculate the timezone value
	timeZoneValue := ((timeZoneByte & 0x70) >> 4) + (timeZoneByte&0x07)*10
	hours := timeZoneValue / 4
	minutes := (timeZoneValue % 4) * 15

	timeZoneFormatted := fmt.Sprintf("GMT %s %d hours %d minutes", sign, hours, minutes)

	// Determine DST adjustment description
	description, exists := DSTAdjustmentDescriptions[dstAdjustmentByte]
	if !exists {
		description = "Unknown adjustment"
	}

	// Handle formatting
	format := config.GetOutputFormat()
	var dstAdjustmentFormatted interface{}
	switch format {
	case "numeric":
		dstAdjustmentFormatted = dstAdjustmentByte
	case "text":
		dstAdjustmentFormatted = description
	case "mixed":
		dstAdjustmentFormatted = fmt.Sprintf("%s (%d)", description, dstAdjustmentByte)
	default:
		dstAdjustmentFormatted = dstAdjustmentByte
	}

	return UETimeZone{
		TimeZone:      timeZoneFormatted,
		DSTAdjustment: dstAdjustmentFormatted,
	}, nil
}
