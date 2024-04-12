package gtp2ie

import (
	"encoding/hex"
	"fmt"
	"gtp2json/config"
	"net"
)

// FTEID represents F-TEID (3GPPP TS 29.274 8.22)
type FTEID struct {
	InterfaceType string `json:"InterfaceType"`
	TEIDGREKey    string `json:"TEID/GRE Key"`
	IPv4          string `json:"F-TEID IPv4,omitempty"`
	IPv6          string `json:"F-TEID IPv6,omitempty"`
}

// DecodeFTEID decodes FTEID fields from bytes, including TEID/GRE key and optional IP addresses
func DecodeFTEID(content []byte) (FTEID, error) {
	if len(content) < 5 {
		return FTEID{}, fmt.Errorf("content is too short for F-TEID")
	}

	flagsInterfaceType := content[0]
	v4Flag := flagsInterfaceType & 0x80
	v6Flag := flagsInterfaceType & 0x40
	interfaceType := flagsInterfaceType & 0x3F

	teidGREKey := hex.EncodeToString(content[1:5])

	var ipv4Addr, ipv6Addr string
	currentIndex := 5

	if v4Flag != 0 {
		if len(content) < currentIndex+4 {
			return FTEID{}, fmt.Errorf("content is too short for IPv4 address")
		}
		ipv4Addr = net.IP(content[currentIndex : currentIndex+4]).To4().String()
		currentIndex += 4
	}

	if v6Flag != 0 {
		if len(content) < currentIndex+16 {
			return FTEID{}, fmt.Errorf("content is too short for IPv6 address")
		}
		ipv6Addr = net.IP(content[currentIndex : currentIndex+16]).To16().String()
	}

	// Formatted result support
	format := config.GetOutputFormat()
	interfaceTypeFormatted := ""
	switch format {
	case "numeric":
		interfaceTypeFormatted = fmt.Sprintf("%d", interfaceType)
	case "text":
		interfaceTypeFormatted = InterfaceTypeDescriptions[uint8(interfaceType)]
	case "mixed":
		interfaceTypeFormatted = fmt.Sprintf("%s (%d)", InterfaceTypeDescriptions[uint8(interfaceType)], interfaceType)
	default:
		interfaceTypeFormatted = fmt.Sprintf("%d", interfaceType)
	}

	return FTEID{
		IPv4:          ipv4Addr,
		IPv6:          ipv6Addr,
		InterfaceType: interfaceTypeFormatted,
		TEIDGREKey:    teidGREKey,
	}, nil
}
