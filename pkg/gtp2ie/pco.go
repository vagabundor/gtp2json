package gtp2ie

import (
	"encoding/binary"
	"fmt"
	"gtp2json/config"
)

// ProtocolIDNames maps protocol IDs to their descriptions (3GPP TS 24.008 10.5.6.3)
var ProtocolIDNames = map[uint16]string{
	0x0001: "P-CSCF IPv6 Address",
	0x0002: "IM CN Subsystem Signaling Flag",
	0x0003: "DNS Server IPv6 Address",
	0x0004: "Not Supported",
	0x0005: "MS Support of Network Bearer Control indicator",
	0x0007: "DSMIPv6 Home Agent Address",
	0x0008: "DSMIPv6 Home Network Prefix",
	0x0009: "DSMIPv6 IPv4 Home Agent Address",
	0x000A: "IP address allocation via NAS signalling",
	0x000B: "IPv4 address allocation via DHCPv4",
	0x000C: "P-CSCF IPv4 Address",
	0x000D: "DNS Server IPv4 Address",
	0x000E: "MSISDN",
	0x000F: "IFOM-Support-Request",
	0x0010: "IPv4 Link MTU",
	0x0011: "MS support of Local address in TFT indicator",
	0x0012: "P-CSCF Re-selection support",
	0x0013: "NBIFOM indicator",
	0x0014: "NBIFOM mode",
	0x0015: "Non-IP Link MTU",
	0x0016: "APN rate control support indicator",
	0x0017: "3GPP PS data off UE status",
	0x0018: "Reliable Data Service indicator",
	0x0019: "Additional APN rate control",
	0x001A: "PDU session ID",
	0x0020: "Ethernet Frame Payload MTU",
	0x0021: "Unstructured Link MTU",
	0x0022: "5GSM cause value",
	0x0023: "QoS rules",
	0x0024: "QoS flow descriptions",
	0x0027: "ACS information",
	0x0030: "ATSSS",
	0x0031: "DNS server security information indicator",
	0x0032: "ECS configuration information",
	0x0036: "PVS information",
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

// SelectedBearerControlModeNames maps Selected Bearer Control Mode values to their descriptions
var SelectedBearerControlModeNames = map[uint8]string{
	0: "MS only",
	1: "Network only",
	2: "MS/NW",
}

// PCO represents the Protocol Configuration Options information element.
type PCO struct {
	ConfigurationProtocol uint8       `json:"ConfigurationProtocol"`
	Options               []PCOOption `json:"Options"`
}

// PCOOption represents a single protocol option within a PCO.
type PCOOption struct {
	ProtocolID       interface{} `json:"ProtocolID"`
	ProtocolContents interface{} `json:"ProtocolContents"`
}

// IPCPOption represents a single IPCP option field
type IPCPOption struct {
	Type interface{} `json:"Type"`
	Data interface{} `json:"Data"`
}

// IPCP represents the decoded IPCP protocol contents
type IPCP struct {
	Code       uint8        `json:"Code"`
	Identifier uint8        `json:"Identifier"`
	Length     uint16       `json:"-"`
	Options    []IPCPOption `json:"Options"`
}

// IPCPOptionNames maps IPCP option types to their descriptions
var IPCPOptionNames = map[uint8]string{
	0x03: "IP Address",
	0x81: "Primary DNS Server IP Address",
	0x83: "Secondary DNS Server IP Address",
}

// PAP represents the decoded PAP protocol contents
type PAP struct {
	Code       uint8  `json:"Code"`
	Identifier uint8  `json:"Identifier"`
	Username   string `json:"Username"`
	Password   string `json:"Password"`
}

// CHAP represents the decoded CHAP protocol contents
type CHAP struct {
	Code       uint8  `json:"Code"`
	Identifier uint8  `json:"Identifier"`
	Value      string `json:"Value"`
	Name       string `json:"Name"`
}

// DecodeIPCP decodes the IPCP protocol contents from a byte slice
func DecodeIPCP(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("insufficient data for IPCP: expected at least 4 bytes, got %d", len(data))
	}

	ipcp := IPCP{
		Code:       data[0],
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
	}

	if len(data) < int(ipcp.Length) {
		return nil, fmt.Errorf("IPCP length %d exceeds remaining data %d", ipcp.Length, len(data))
	}

	ipcpData := data[4:ipcp.Length]
	index := 0

	for index < len(ipcpData) {
		if index+2 > len(ipcpData) {
			return nil, fmt.Errorf("insufficient data for IPCP option at index %d", index)
		}

		optionType := ipcpData[index]
		optionLength := ipcpData[index+1]
		if index+int(optionLength) > len(ipcpData) {
			return nil, fmt.Errorf("IPCP option length %d exceeds remaining data %d at index %d", optionLength, len(ipcpData)-index, index)
		}

		optionData := ipcpData[index+2 : index+int(optionLength)]
		var optionValue interface{}

		switch optionType {
		case 0x03, 0x81, 0x83: // IP Address, Primary DNS Server IP Address, Secondary DNS Server IP Address
			if len(optionData) != 4 {
				return nil, fmt.Errorf("invalid IP address length %d, expected 4", len(optionData))
			}
			optionValue = fmt.Sprintf("%d.%d.%d.%d", optionData[0], optionData[1], optionData[2], optionData[3])
		default:
			optionValue = optionData
		}

		description := formatIPCPOption(optionType)

		ipcp.Options = append(ipcp.Options, IPCPOption{
			Type: description,
			Data: optionValue,
		})
		index += int(optionLength)
	}

	return ipcp, nil
}

// formatIPCPOption returns the formatted IPCP option based on the selected format.
func formatIPCPOption(optionType uint8) interface{} {
	format := config.GetOutputFormat()
	description, exists := IPCPOptionNames[optionType]
	if !exists {
		description = fmt.Sprintf("Unknown Option (%02X)", optionType)
	}

	switch format {
	case "numeric":
		return optionType
	case "text":
		return description
	case "mixed":
		return fmt.Sprintf("%s (%d)", description, optionType)
	default:
		return optionType
	}
}

// DecodeIPv4Address decodes a generic IPv4 address
func DecodeIPv4Address(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}

	if len(data) != 4 {
		return nil, fmt.Errorf("invalid length for IPv4 Address: expected 4 bytes, got %d", len(data))
	}

	ipv4Address := fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
	return ipv4Address, nil
}

// DecodeDNSServerIPv4Address decodes the DNS Server IPv4 Address using the generic IPv4 decoder
func DecodeDNSServerIPv4Address(data []byte) (interface{}, error) {
	return DecodeIPv4Address(data)
}

// DecodeSelectedBearerControlMode decodes the Selected Bearer Control Mode
func DecodeSelectedBearerControlMode(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 1 {
		return nil, fmt.Errorf("insufficient data for Selected Bearer Control Mode")
	}

	mode := data[0]
	description, exists := SelectedBearerControlModeNames[mode]
	if !exists {
		description = fmt.Sprintf("Unknown Mode (%d)", mode)
	}

	format := config.GetOutputFormat()
	switch format {
	case "numeric":
		return mode, nil
	case "text":
		return description, nil
	case "mixed":
		return fmt.Sprintf("%s (%d)", description, mode), nil
	default:
		return mode, nil
	}
}

// DecodeIPv4LinkMTU decodes the IPv4 Link MTU
func DecodeIPv4LinkMTU(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}

	if len(data) != 2 {
		return nil, fmt.Errorf("invalid length for IPv4 Link MTU: expected 2 bytes, got %d", len(data))
	}

	mtu := binary.BigEndian.Uint16(data)
	return mtu, nil
}

// DecodePAP decodes the PAP (Password Authentication Protocol) content
func DecodePAP(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("insufficient data for PAP: expected at least 4 bytes, got %d", len(data))
	}

	code := data[0]
	identifier := data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if len(data) < int(length) {
		return nil, fmt.Errorf("PAP length %d exceeds remaining data %d", length, len(data))
	}

	authData := data[4:length]
	usernameLength := int(authData[0])
	if len(authData) < 1+usernameLength {
		return nil, fmt.Errorf("insufficient data for username: expected %d bytes, got %d", usernameLength, len(authData)-1)
	}

	username := string(authData[1 : 1+usernameLength])
	passwordLengthIndex := 1 + usernameLength
	if len(authData) < passwordLengthIndex+1 {
		return nil, fmt.Errorf("insufficient data for password length")
	}

	passwordLength := int(authData[passwordLengthIndex])
	if len(authData) < passwordLengthIndex+1+passwordLength {
		return nil, fmt.Errorf("insufficient data for password: expected %d bytes, got %d", passwordLength, len(authData)-(passwordLengthIndex+1))
	}

	password := string(authData[passwordLengthIndex+1 : passwordLengthIndex+1+passwordLength])

	return PAP{
		Code:       code,
		Identifier: identifier,
		Username:   username,
		Password:   password,
	}, nil
}

// DecodeCHAP decodes the CHAP (Challenge Handshake Authentication Protocol) content
func DecodeCHAP(data []byte) (interface{}, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("insufficient data for CHAP: expected at least 5 bytes, got %d", len(data))
	}

	code := data[0]
	identifier := data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if len(data) < int(length) {
		return nil, fmt.Errorf("CHAP length %d exceeds remaining data %d", length, len(data))
	}

	valueLength := int(data[4])
	if len(data) < 5+valueLength {
		return nil, fmt.Errorf("insufficient data for CHAP value: expected %d bytes, got %d", valueLength, len(data)-5)
	}

	value := data[5 : 5+valueLength]
	name := data[5+valueLength:]

	return CHAP{
		Code:       code,
		Identifier: identifier,
		Value:      fmt.Sprintf("%x", value),
		Name:       string(name),
	}, nil
}

// DecodeMSLocalAddressSupport decodes the MS support of Local address in TFT indicator
func DecodeMSLocalAddressSupport(data []byte) (interface{}, error) {
	// Example decoding logic for MS support of Local address in TFT indicator
	return data, nil
}

// DecodePCSCFIPv4Address decodes the P-CSCF IPv4 Address using the generic IPv4 decoder
func DecodePCSCFIPv4Address(data []byte) (interface{}, error) {
	return DecodeIPv4Address(data)
}

var ProtocolIDDecoders = map[uint16]func([]byte) (interface{}, error){
	0x8021: DecodeIPCP,
	0x000D: DecodeDNSServerIPv4Address,
	0x0005: DecodeSelectedBearerControlMode,
	0x0010: DecodeIPv4LinkMTU,
	0x000C: DecodePCSCFIPv4Address,
	0xC023: DecodePAP,
	0xC223: DecodeCHAP,
}

// DecodePCO decodes the Protocol Configuration Options (PCO) IE from a byte slice
func DecodePCO(data []byte) (interface{}, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("insufficient data for PCO")
	}

	configurationProtocol := data[0]
	options := make([]PCOOption, 0)
	index := 1

	for index < len(data) {
		if index+3 > len(data) {
			return nil, fmt.Errorf("truncated data at protocol ID at index %d", index)
		}

		protocolID := binary.BigEndian.Uint16(data[index : index+2])
		contentLength := int(data[index+2])
		index += 3

		if index+contentLength > len(data) {
			return nil, fmt.Errorf("truncated data at protocol ID contents at index %d, contentLength %d", index, contentLength)
		}

		protocolContents := data[index : index+contentLength]
		index += contentLength

		description, exists := ProtocolIDNames[protocolID]
		if !exists {
			description = fmt.Sprintf("Unknown Protocol (%04X)", protocolID)
		}

		option := PCOOption{
			ProtocolID: formatProtocolID(protocolID, description, config.GetOutputFormat()),
		}

		if decodeFunc, exists := ProtocolIDDecoders[protocolID]; exists {
			decodedContent, err := decodeFunc(protocolContents)
			if err != nil {
				return nil, err
			}
			option.ProtocolContents = decodedContent
		} else {
			if len(protocolContents) == 0 {
				option.ProtocolContents = nil
			} else {
				option.ProtocolContents = protocolContents
			}
		}

		options = append(options, option)
	}

	return PCO{
		ConfigurationProtocol: configurationProtocol,
		Options:               options,
	}, nil
}

// formatProtocolID returns the formatted protocol ID based on the selected format.
func formatProtocolID(id uint16, description string, format string) interface{} {
	switch format {
	case "numeric":
		return id
	case "text":
		return description
	case "mixed":
		return fmt.Sprintf("%s (%d)", description, id)
	default:
		return id
	}
}
