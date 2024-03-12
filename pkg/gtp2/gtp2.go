package gtp2

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeGTPv2 = gopacket.RegisterLayerType(1010,
	gopacket.LayerTypeMetadata{Name: "GTPv2", Decoder: gopacket.DecodeFunc(decodeGTPv2)})

const gtpMinimumSizeInBytes int = 4

type IE struct {
	Type    uint8
	Content []byte
}

type GTPv2 struct {
	Version          uint8
	PiggybackingFlag bool
	TEIDflag         bool
	MessagePriority  uint8
	MessageType      uint8
	MessageLength    uint16
	TEID             uint32
	SequenceNumber   uint32
	Spare            uint8
	IEs              []IE

	Contents []byte
	Payload  []byte
}

func init() {
	udpPort := layers.UDPPort(2123)
	layers.RegisterUDPPortLayerType(udpPort, LayerTypeGTPv2)
}

func (g *GTPv2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	hLen := gtpMinimumSizeInBytes
	dLen := len(data)
	if dLen < hLen {
		return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	}
	g.Version = (data[0] >> 5) & 0x07
	g.PiggybackingFlag = ((data[0] >> 4) & 0x01) == 1
	g.TEIDflag = ((data[0] >> 3) & 0x01) == 1
	g.MessagePriority = (data[0] >> 2) & 0x01
	g.MessageType = data[1]
	g.MessageLength = binary.BigEndian.Uint16(data[2:4])

	pLen := 4 + g.MessageLength
	if uint16(dLen) < pLen {
		return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	}

	cIndex := uint16(hLen)
	if g.TEIDflag {
		hLen += 4
		cIndex += 4
		if dLen < hLen {
			return fmt.Errorf("GTP packet too small: %d bytes", dLen)
		}
		g.TEID = binary.BigEndian.Uint32(data[4:8])
	}

	g.SequenceNumber = uint32(data[cIndex])<<16 | uint32(data[cIndex+1])<<8 | uint32(data[cIndex+2])
	g.Spare = data[cIndex+3]
	hLen += 4
	cIndex += 4

	for cIndex < uint16(dLen) {
		ieType := data[cIndex]
		ieLength := binary.BigEndian.Uint16(data[cIndex+1 : cIndex+3])
		if cIndex+4+uint16(ieLength) > uint16(dLen) {
			return fmt.Errorf("IE %d exceeds packet length", ieType)
		}
		ieContent := data[cIndex+4 : cIndex+4+uint16(ieLength)]
		g.IEs = append(g.IEs, IE{Type: ieType, Content: ieContent})
		cIndex += 4 + uint16(ieLength)
	}

	g.Contents = data[:cIndex]
	g.Payload = data[cIndex:]
	return nil

}

func decodeGTPv2(data []byte, p gopacket.PacketBuilder) error {
	gtp := &GTPv2{}

	if err := gtp.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(gtp)
	return nil
}

func (g *GTPv2) LayerType() gopacket.LayerType {
	return LayerTypeGTPv2
}

func (g *GTPv2) LayerContents() []byte {
	return g.Contents
}

func (g *GTPv2) LayerPayload() []byte {
	return g.Payload
}

func (g *GTPv2) CanDecode() gopacket.LayerClass {
	return LayerTypeGTPv2
}

func (g *GTPv2) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}
