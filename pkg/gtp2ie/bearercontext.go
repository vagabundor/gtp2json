package gtp2ie

import (
	"fmt"
)

// BearerContext represents a bearer context within GTP messages, holding specific bearer related information.
type BearerContext struct {
	EBI       EBI       `json:"EBI,omitempty"`
	BearerQoS BearerQoS `json:"BearerQoS,omitempty"`
	Cause     Cause     `json:"Cause,omitempty"`
	FTEIDs    []FTEID   `json:"FTEIDs,omitempty"`
}

// DecodeBearerContext decodes the bytes into a BearerContext structure
func DecodeBearerContext(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("insufficient data for BearerContext")
	}

	var bearerContext BearerContext
	index := 0

	for index < len(data) {
		if index+3 > len(data) {
			return nil, fmt.Errorf("unexpected end of data at index %d", index)
		}

		ieType := data[index]
		ieLength := int(data[index+1])<<8 | int(data[index+2])
		index += 4

		if index+ieLength > len(data) {
			return nil, fmt.Errorf("data length %d exceeds remaining payload size %d at index %d", ieLength, len(data)-index, index)
		}

		ieData := data[index : index+ieLength]
		index += ieLength

		switch ieType {
		case IETypeEBI:
			ebi, err := DecodeEBI(ieData)
			if err != nil {
				return nil, err
			}
			ebiVal := ebi.(EBI)
			bearerContext.EBI = ebiVal
		case IETypeBearerQoS:
			qos, err := DecodeBearerQoS(ieData)
			if err != nil {
				return nil, err
			}
			qosVal := qos.(BearerQoS)
			bearerContext.BearerQoS = qosVal
		case IETypeCause:
			cause, err := DecodeCause(ieData)
			if err != nil {
				return nil, err
			}
			causeVal := cause.(Cause)
			bearerContext.Cause = causeVal
		case IETypeFTEID:
			fteid, err := DecodeFTEID(ieData)
			if err != nil {
				return nil, err
			}
			fteidVal := fteid.(FTEID)
			bearerContext.FTEIDs = append(bearerContext.FTEIDs, fteidVal)
		default:
			// If the IE type is unknown, skip to the next IE
			continue
		}
	}

	return bearerContext, nil
}
