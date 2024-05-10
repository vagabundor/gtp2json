package gtp2ie

import (
	"fmt"
	"gtp2json/config"
	"net"
)

type PAA struct {
	PDNType interface{} `json:"pdnType"`
	IPv4    string      `json:"ipv4,omitempty"`
	IPv6    string      `json:"ipv6,omitempty"`
}

// DecodePAA decodes PDN Address Allocation from given data bytes
func DecodePAA(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return PAA{}, fmt.Errorf("insufficient data for PAA")
	}

	paaType := data[0] & 0x07 // Extracting the PDN type information
	index := 1

	var ipv4, ipv6 net.IP
	var paa PAA

	format := config.GetOutputFormat()
	var pdnTypeDescription interface{}

	switch paaType {
	case 0x01: // IPv4
		pdnTypeDescription = formatDescription("IPv4", paaType, format)
	case 0x02: // IPv6
		pdnTypeDescription = formatDescription("IPv6", paaType, format)
	case 0x03: // IPv4v6
		pdnTypeDescription = formatDescription("IPv4v6", paaType, format)
	case 0x04: // Non-IP
		pdnTypeDescription = formatDescription("Non-IP", paaType, format)
	case 0x05: // Ethernet
		pdnTypeDescription = formatDescription("Ethernet", paaType, format)
	default:
		return PAA{}, fmt.Errorf("unknown PDN type in PAA: %d", paaType)
	}

	paa.PDNType = pdnTypeDescription

	if paaType == 0x01 || paaType == 0x03 { // IPv4 or IPv4v6
		if len(data) < index+4 {
			return PAA{}, fmt.Errorf("insufficient data for IPv4 address")
		}
		ipv4 = net.IP(data[index : index+4])
		paa.IPv4 = ipv4.String()
		index += 4
	}

	if paaType == 0x02 || paaType == 0x03 { // IPv6 or IPv4v6
		if len(data) < index+16 {
			return PAA{}, fmt.Errorf("insufficient data for IPv6 address")
		}
		ipv6 = net.IP(data[index : index+16])
		paa.IPv6 = ipv6.String()
	}

	return paa, nil
}

// formatDescription formats the PDN type description according to the specified format
func formatDescription(description string, pdnType byte, format string) interface{} {
	switch format {
	case "numeric":
		return pdnType
	case "text":
		return description
	case "mixed":
		return fmt.Sprintf("%s (%d)", description, pdnType)
	default:
		return pdnType
	}
}
