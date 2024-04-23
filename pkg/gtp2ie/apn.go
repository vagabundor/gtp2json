package gtp2ie

import (
	"bytes"
	"fmt"
)

// DecodeAPN decodes the APN from IE data
func DecodeAPN(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("APN data is empty")
	}

	// APN IE might be dot-separated like "inet.ycc.ru"
	// the format is length-prefixed segments: <length><segment><length><segment>
	var result bytes.Buffer
	index := 0
	for index < len(data) {
		length := int(data[index])
		index++
		if index+length > len(data) {
			return "", fmt.Errorf("invalid APN length: exceeds data length")
		}
		if result.Len() > 0 {
			result.WriteByte('.')
		}
		result.Write(data[index : index+length])
		index += length
	}

	return result.String(), nil
}
