package gtp2ie

import (
	"encoding/binary"
	"fmt"
	"time"
)

// DecodeULITimestamp decodes the ULI Timestamp IE from a byte slice
func DecodeULITimestamp(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("insufficient data for ULI Timestamp: expected at least 4 bytes, got %d", len(data))
	}

	// Read the timestamp value
	timestamp := binary.BigEndian.Uint32(data[:4])
	// Convert the timestamp to time.Time relative to 1 January 1900
	epoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	decodedTimestamp := epoch.Add(time.Duration(timestamp) * time.Second)

	// Format the timestamp
	formattedTime := decodedTimestamp.Format("Jan 2, 2006 15:04:05 UTC")

	return formattedTime, nil
}
