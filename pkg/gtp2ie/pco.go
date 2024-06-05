package gtp2ie

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"gtp2json/config"
)

// ProtocolIDNames maps protocol IDs to their descriptions (3GPP TS 24.008 10.5.6.3)
var ProtocolIDNames = map[uint16]string{
	0x0001: "P-CSCF IPv6 Address Request",
	0x0002: "IM CN Subsystem Signaling Flag",
	0x0003: "DNS Server IPv6 Address Request",
	0x0004: "Not Supported",
	0x0005: "MS Support of Network Requested Bearer Control indicator",
	0x0007: "DSMIPv6 Home Agent Address Request",
	0x0008: "DSMIPv6 Home Network Prefix Request",
	0x0009: "DSMIPv6 IPv4 Home Agent Address Request",
	0x000A: "IP address allocation via NAS signalling",
	0x000B: "IPv4 address allocation via DHCPv4",
	0x000C: "P-CSCF IPv4 Address Request",
	0x000D: "DNS Server IPv4 Address Request",
	0x000E: "MSISDN Request",
	0x000F: "IFOM-Support-Request",
	0x0010: "IPv4 Link MTU Request",
	0x0011: "MS support of Local address in TFT indicator",
	0x0012: "P-CSCF Re-selection support",
	0x0013: "NBIFOM request indicator",
	0x0014: "NBIFOM mode",
	0x0015: "Non-IP Link MTU Request",
	0x0016: "APN rate control support indicator",
	0x0017: "3GPP PS data off UE status",
	0x0018: "Reliable Data Service request indicator",
	0x0019: "Additional APN rate control",
	0x001A: "PDU session ID",
	0x0020: "Ethernet Frame Payload MTU Request",
	0x0021: "Unstructured Link MTU Request",
	0x0022: "5GSM cause value",
	0x0023: "QoS rules",
	0x0024: "QoS flow descriptions",
	0x0027: "ACS information request",
	0x0030: "ATSSS request",
	0x0031: "DNS server security information indicator",
	0x0032: "ECS configuration information",
	0x0036: "PVS information request",
	0x0039: "DNS server security protocol support",
	0x003A: "EAS rediscovery support indication",
	0x0041: "Service-level-AA container",
	0x0047: "EDC support indicator",
	0x004A: "MS support of MAC address range in 5GS indicator",
	0x0050: "SDNAEPC support indicator",
	0x0051: "SDNAEPC EAP message",
	0x0052: "SDNAEPC DN-specific identity",
	0x0056: "UE policy container",
	0x8021: "IPCP",
	0xC021: "LCP",
	0xC023: "PAP",
	0xC223: "CHAP",
}

// PCO represents the Protocol Configuration Options information element.
type PCO struct {
	ConfigurationProtocol uint8       `json:"ConfigurationProtocol"`
	Options               []PCOOption `json:"Options"`
}

// PCOOption represents a single protocol option within a PCO.
type PCOOption struct {
	ProtocolID       interface{} `json:"ProtocolID"`
	ProtocolContents string      `json:"ProtocolContents"`
}

// DecodePCO decodes the PCO fields from the provided byte slice.
func DecodePCO(data []byte) (interface{}, error) {
	if len(data) < 3 {
		return PCO{}, fmt.Errorf("insufficient data for PCO")
	}

	var pco PCO
	pco.ConfigurationProtocol = data[0]
	index := 1

	format := config.GetOutputFormat()

	for index < len(data) {
		if len(data[index:]) < 2 {
			return PCO{}, fmt.Errorf("truncated data at protocol ID at index %d", index)
		}
		protocolID := binary.BigEndian.Uint16(data[index : index+2])
		protocolIDDesc, found := ProtocolIDNames[protocolID]
		if !found {
			protocolIDDesc = fmt.Sprintf("Unknown Protocol (0x%04X)", protocolID)
		}
		formattedID := formatProtocolID(protocolID, protocolIDDesc, format)
		index += 2

		if len(data[index:]) < 1 {
			return PCO{}, fmt.Errorf("truncated data at content length at index %d", index)
		}
		contentLength := data[index]
		index += 1

		if len(data[index:]) < int(contentLength) {
			return PCO{}, fmt.Errorf("truncated data at protocol contents at index %d, contentLength %d", index, contentLength)
		}
		protocolContents := base64.StdEncoding.EncodeToString(data[index : index+int(contentLength)])
		index += int(contentLength)

		option := PCOOption{
			ProtocolID:       formattedID,
			ProtocolContents: protocolContents,
		}

		// Append the new option to the list of options
		pco.Options = append(pco.Options, option)
	}

	return pco, nil
}

// formatProtocolID returns the formatted protocol ID based on the selected format.
func formatProtocolID(id uint16, description string, format string) interface{} {
	switch format {
	case "numeric":
		return id
	case "text":
		return description
	case "mixed":
		return fmt.Sprintf("%s (0x%04X)", description, id)
	default:
		return id
	}
}
