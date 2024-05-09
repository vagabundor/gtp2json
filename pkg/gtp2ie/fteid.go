package gtp2ie

import (
	"encoding/hex"
	"fmt"
	"gtp2json/config"
	"net"
)

var InterfaceTypeDescriptions = map[uint8]string{
	0:  "S1-U eNodeB GTP-U interface",
	1:  "S1-U SGW GTP-U interface",
	2:  "S12 RNC GTP-U interface",
	3:  "S12 SGW GTP-U interface",
	4:  "S5/S8 SGW GTP-U interface",
	5:  "S5/S8 PGW GTP-U interface",
	6:  "S5/S8 SGW GTP-C interface",
	7:  "S5/S8 PGW GTP-C interface",
	8:  "S5/S8 SGW PMIPv6 interface",
	9:  "S5/S8 PGW PMIPv6 interface",
	10: "S11 MME GTP-C interface",
	11: "S11/S4 SGW GTP-C interface",
	12: "S10/N26 MME GTP-C interface",
	13: "S3 MME GTP-C interface",
	14: "S3 SGSN GTP-C interface",
	15: "S4 SGSN GTP-U interface",
	16: "S4 SGW GTP-U interface",
	17: "S4 SGSN GTP-C interface",
	18: "S16 SGSN GTP-C interface",
	19: "eNodeB/gNodeB GTP-U interface for DL data forwarding",
	20: "eNodeB GTP-U interface for UL data forwarding",
	21: "RNC GTP-U interface for data forwarding",
	22: "SGSN GTP-U interface for data forwarding",
	23: "SGW/UPF GTP-U interface for DL data forwarding",
	24: "Sm MBMS GW GTP-C interface",
	25: "Sn MBMS GW GTP-C interface",
	26: "Sm MME GTP-C interface",
	27: "Sn SGSN GTP-C interface",
	28: "SGW GTP-U interface for UL data forwarding",
	29: "Sn SGSN GTP-U interface",
	30: "S2b ePDG GTP-C interface",
	31: "S2b-U ePDG GTP-U interface",
	32: "S2b PGW GTP-C interface",
	33: "S2b-U PGW GTP-U interface",
	34: "S2a TWAN GTP-U interface",
	35: "S2a TWAN GTP-C interface",
	36: "S2a PGW GTP-C interface",
	37: "S2a PGW GTP-U interface",
	38: "S11 MME GTP-U interface",
	39: "S11 SGW GTP-U interface",
	40: "N26 AMF GTP-C interface",
	41: "N19mb UPF GTP-U interface",
}

// FTEID represents F-TEID (3GPPP TS 29.274 8.22)
type FTEID struct {
	InterfaceType interface{} `json:"InterfaceType"`
	TEIDGREKey    string      `json:"TEID/GRE Key"`
	IPv4          string      `json:"F-TEID IPv4,omitempty"`
	IPv6          string      `json:"F-TEID IPv6,omitempty"`
}

// DecodeFTEID decodes FTEID fields from bytes, including TEID/GRE key and optional IP addresses
func DecodeFTEID(content []byte) (interface{}, error) {
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
	var interfaceTypeFormatted interface{}
	switch format {
	case "numeric":
		interfaceTypeFormatted = interfaceType
	case "text":
		interfaceTypeFormatted = InterfaceTypeDescriptions[uint8(interfaceType)]
	case "mixed":
		interfaceTypeFormatted = fmt.Sprintf("%s (%d)", InterfaceTypeDescriptions[uint8(interfaceType)], interfaceType)
	default:
		interfaceTypeFormatted = interfaceType
	}

	return FTEID{
		IPv4:          ipv4Addr,
		IPv6:          ipv6Addr,
		InterfaceType: interfaceTypeFormatted,
		TEIDGREKey:    teidGREKey,
	}, nil
}
