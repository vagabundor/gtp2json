package gtp2ie

import (
	"encoding/binary"
	"fmt"
)

// ULI represents ULI IE (3GPPP TS 29.274 8.21)
type ULI struct {
	CGI                   *CGI                   `json:"CGI,omitempty"`
	SAI                   *SAI                   `json:"SAI,omitempty"`
	RAI                   *RAI                   `json:"RAI,omitempty"`
	TAI                   *TAI                   `json:"TAI,omitempty"`
	ECGI                  *ECGI                  `json:"ECGI,omitempty"`
	LAI                   *LAI                   `json:"LAI,omitempty"`
	MacroENodebID         *MacroENodebID         `json:"Macro_eNodebID,omitempty"`
	ExtendedMacroENodebID *ExtendedMacroENodebID `json:"ExtendedMacroENodebID,omitempty"`
}

type CGI struct {
	MCCMNC
	LAC string `json:"LAC,omitempty"`
	CI  string `json:"CI,omitempty"`
}

type SAI struct {
	MCCMNC
	LAC string `json:"LAC,omitempty"`
	SAC string `json:"SAC,omitempty"`
}

type RAI struct {
	MCCMNC
	LAC string `json:"LAC,omitempty"`
	RAC string `json:"RAC,omitempty"`
}

type TAI struct {
	MCCMNC
	TAC string `json:"TAC,omitempty"`
}

type ECGI struct {
	MCCMNC
	ECI string `json:"ECI,omitempty"`
}

type LAI struct {
	MCCMNC
	LAC string `json:"LAC,omitempty"`
}

type MacroENodebID struct {
	MCCMNC
	MacroID string `json:"MacroID,omitempty"`
}

type ExtendedMacroENodebID struct {
	MCCMNC
	ExtendedID string `json:"ExtendedID,omitempty"`
}

// decodeTAI decodes the Tracking Area Identity (TAI) from a slice of bytes
func decodeTAI(data []byte) (TAI, int, error) {
	if len(data) < 5 {
		return TAI{}, 0, fmt.Errorf("not enough data for TAI")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return TAI{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	tac := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[3:5]))

	return TAI{
		MCCMNC: mccmnc,
		TAC:    tac,
	}, 5, nil
}

// decodeLAI
func decodeLAI(data []byte) (LAI, int, error) {
	if len(data) < 5 {
		return LAI{}, 0, fmt.Errorf("not enough data for LAI")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return LAI{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	lac := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[3:5]))

	return LAI{
		MCCMNC: mccmnc,
		LAC:    lac,
	}, 5, nil
}

// decodeCGI decodes Cell Global Identity from a slice of bytes
func decodeCGI(data []byte) (CGI, int, error) {
	// 3 for MCC/MNC, 2 for LAC, 2 for CI
	if len(data) < 7 {
		return CGI{}, 0, fmt.Errorf("not enough data for CGI")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return CGI{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	lac := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[3:5]))
	ci := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[5:7]))

	return CGI{
		MCCMNC: mccmnc,
		LAC:    lac,
		CI:     ci,
	}, 7, nil
}

// decodeSAI decodes Service Area Identity from a slice of bytes
func decodeSAI(data []byte) (SAI, int, error) {
	// 7 bytes needed: 3 for MCC/MNC, 2 for LAC, 2 for SAC
	if len(data) < 7 {
		return SAI{}, 0, fmt.Errorf("not enough data for SAI")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return SAI{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	lac := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[3:5]))
	sac := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[5:7]))

	return SAI{
		MCCMNC: mccmnc,
		LAC:    lac,
		SAC:    sac,
	}, 7, nil
}

// decodeRAI decodes Routing Area Identity from a slice of bytes
func decodeRAI(data []byte) (RAI, int, error) {
	// 7 bytes needed: 3 for MCC/MNC, 2 for LAC, 2 for RAC
	if len(data) < 7 {
		return RAI{}, 0, fmt.Errorf("not enough data for RAI")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return RAI{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	lac := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[3:5]))
	rac := fmt.Sprintf("%d", binary.BigEndian.Uint16(data[5:7]))

	return RAI{
		MCCMNC: mccmnc,
		LAC:    lac,
		RAC:    rac,
	}, 7, nil
}

// decodeECGI decodes E-UTRAN Cell Global Identifier from a slice of bytes
func decodeECGI(data []byte) (ECGI, int, error) {
	// 7 bytes needed: 3 for MCC/MNC, 4 for ECI
	if len(data) < 7 {
		return ECGI{}, 0, fmt.Errorf("not enough data for ECGI")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return ECGI{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	eci := fmt.Sprintf("%d", binary.BigEndian.Uint32(data[3:7]))

	return ECGI{
		MCCMNC: mccmnc,
		ECI:    eci,
	}, 7, nil
}

// decodeMacroENodeBID decodes Macro eNodeB Identifier from a slice of bytes
func decodeMacroENodeBID(data []byte) (MacroENodebID, int, error) {
	// 7 bytes needed: 3 for MCC/MNC, 4 for Macro eNodeB ID
	if len(data) < 7 {
		return MacroENodebID{}, 0, fmt.Errorf("not enough data for Macro eNodeB ID")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return MacroENodebID{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	macroID := binary.BigEndian.Uint32(data[3:7]) & 0xFFFFF // Mask to extract the first 20 bits

	return MacroENodebID{
		MCCMNC:  mccmnc,
		MacroID: fmt.Sprintf("%d", macroID),
	}, 7, nil // Return the Macro_eNodebID structure along with the number of bytes processed
}

// decodeExtendedMacroENodeBID decodes Extended Macro eNodeB Identifier from a slice of bytes
func decodeExtendedMacroENodeBID(data []byte) (ExtendedMacroENodebID, int, error) {
	// 7 bytes needed: 3 for MCC/MNC, 4 for Extended Macro eNodeB ID
	if len(data) < 7 {
		return ExtendedMacroENodebID{}, 0, fmt.Errorf("not enough data for Extended Macro eNodeB ID")
	}

	mccmnc, err := DecodeMCCMNC(data[:3])
	if err != nil {
		return ExtendedMacroENodebID{}, 0, fmt.Errorf("failed to decode MCC/MNC: %v", err)
	}

	extendedID := binary.BigEndian.Uint32(data[3:7]) & 0x1FFFFF

	return ExtendedMacroENodebID{
		MCCMNC:     mccmnc,
		ExtendedID: fmt.Sprintf("%d", extendedID),
	}, 7, nil
}

// DecodeULI decodes User Location Information (ULI) from a given byte slice
func DecodeULI(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return ULI{}, fmt.Errorf("not enough data to decode ULI")
	}

	uli := ULI{}
	flags := data[0]
	index := 1

	// decode CGI if present
	if flags&0x01 != 0 && len(data) > index {
		cgi, nextIndex, err := decodeCGI(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding CGI: %v", err)
		}
		uli.CGI = &cgi
		index += nextIndex
	}

	// decode SAI if present
	if flags&0x02 != 0 && len(data) > index {
		sai, nextIndex, err := decodeSAI(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding SAI: %v", err)
		}
		uli.SAI = &sai
		index += nextIndex
	}

	// decode RAI if present
	if flags&0x04 != 0 && len(data) > index {
		rai, nextIndex, err := decodeRAI(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding RAI: %v", err)
		}
		uli.RAI = &rai
		index += nextIndex
	}

	// decode TAI if present
	if flags&0x08 != 0 && len(data) > index {
		tai, nextIndex, err := decodeTAI(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding TAI: %v", err)
		}
		uli.TAI = &tai
		index += nextIndex
	}

	// decode ECGI if present
	if flags&0x10 != 0 && len(data) > index {
		ecgi, nextIndex, err := decodeECGI(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding ECGI: %v", err)
		}
		uli.ECGI = &ecgi
		index += nextIndex
	}

	// decode LAI if present
	if flags&0x20 != 0 && len(data) > index {
		lai, nextIndex, err := decodeLAI(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding LAI: %v", err)
		}
		uli.LAI = &lai
		index += nextIndex
	}

	// decode Macro eNodeB ID if present
	if flags&0x40 != 0 && len(data) > index {
		macroID, nextIndex, err := decodeMacroENodeBID(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding Macro eNodeB ID: %v", err)
		}
		uli.MacroENodebID = &macroID
		index += nextIndex
	}

	// decode Extended Macro eNodeB ID if present
	if flags&0x80 != 0 && len(data) > index {
		extendedID, nextIndex, err := decodeExtendedMacroENodeBID(data[index:])
		if err != nil {
			return ULI{}, fmt.Errorf("error decoding Extended Macro eNodeB ID: %v", err)
		}
		uli.ExtendedMacroENodebID = &extendedID
		index += nextIndex
	}

	return uli, nil
}
