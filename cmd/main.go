package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gtp2json/config"
	"gtp2json/pkg/gtp2"
	"gtp2json/pkg/gtp2ie"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type IE struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type GTPv2Packet struct {
	Timestamp        time.Time `json:"timestamp"`
	Version          uint8     `json:"version"`
	PiggybackingFlag bool      `json:"piggybackingFlag"`
	TEIDflag         bool      `json:"teidFlag"`
	MessagePriority  uint8     `json:"messagePriority"`
	MessageType      uint8     `json:"messageType"`
	MessageLength    uint16    `json:"messageLength"`
	TEID             *uint32   `json:"teid,omitempty"`
	SequenceNumber   uint32    `json:"sequenceNumber"`
	Spare            uint8     `json:"spare"`
	IEs              []IE      `json:"ies"`
}

func main() {

	var pcapFile string
	var format string
	flag.StringVar(&pcapFile, "f", "", "Path to the pcap file to analyze")
	flag.StringVar(&pcapFile, "file", "", "Path to the pcap file to analyze")
	flag.StringVar(&format, "format", "numeric", "Specifies the format of the output")

	flag.Parse()

	if pcapFile == "" {
		fmt.Println("Please specify a pcap file using -f or --file flag")
		fmt.Println("Example: gtp2json --file cutured.pcap")
		flag.PrintDefaults()
		return
	}

	switch format {
	case "numeric", "text", "mixed":
		config.SetOutputFormat(format)
	default:
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a valid format. Use 'numeric', 'text', or 'mixed'.\n", format)
		return
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatalf("Opening pcap failed: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	gtpLayer := packet.Layer(gtp2.LayerTypeGTPv2)
	if gtpLayer != nil {
		gtp, ok := gtpLayer.(*gtp2.GTPv2)
		if !ok {
			log.Println("Error asserting layer to GTPv2")
			return
		}

		var ieItems []IE
		for _, ie := range gtp.IEs {

			ieName, processedContent, err := gtp2ie.ProcessIE(ie)
			if err != nil {
				log.Printf("Error processing IE: %v", err)
				continue
			}

			ieItems = append(ieItems, IE{
				Type:  ieName,
				Value: processedContent,
			})
		}

		// This allows us to check for nil,
		// enabling conditional inclusion of the TEID field in the JSON output based on the TEIDflag
		var teidPtr *uint32
		if gtp.TEIDflag {
			teidPtr = new(uint32)
			*teidPtr = gtp.TEID
		}

		packetData := GTPv2Packet{
			Timestamp:        packet.Metadata().Timestamp,
			Version:          gtp.Version,
			PiggybackingFlag: gtp.PiggybackingFlag,
			TEIDflag:         gtp.TEIDflag,
			MessagePriority:  gtp.MessagePriority,
			MessageType:      gtp.MessageType,
			MessageLength:    gtp.MessageLength,
			TEID:             teidPtr,
			SequenceNumber:   gtp.SequenceNumber,
			Spare:            gtp.Spare,
			IEs:              ieItems,
		}

		jsonData, err := json.MarshalIndent(packetData, "", "    ")
		if err != nil {
			log.Printf("Error converting to JSON: %v", err)
			return
		}
		fmt.Println(string(jsonData))
	}
}
