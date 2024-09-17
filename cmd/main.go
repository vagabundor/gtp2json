package main

import (
	"encoding/json"
	"fmt"
	"gtp2json/config"
	"gtp2json/pkg/gtp2"
	"gtp2json/pkg/gtp2ie"
	"log"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/IBM/sarama"
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

var producer sarama.SyncProducer

func main() {

	pflag.String("file", "", "Path to the pcap file to analyze")
	pflag.String("interface", "", "Name of the interface to analyze")
	pflag.String("format", "numeric", "Specifies the format of the output (numeric, text, mixed)")
	pflag.String("kafkaBroker", "", "Address of the Kafka broker (if not set, output to stdout)")
	pflag.String("kafkaTopic", "gtp_packets", "Kafka topic to send data to")
	pflag.Parse()

	viper.SetEnvPrefix("G2J")
	viper.AutomaticEnv()
	viper.BindPFlags(pflag.CommandLine)

	pcapFile := viper.GetString("file")
	iface := viper.GetString("interface")
	kafkaBroker := viper.GetString("kafkaBroker")
	kafkaTopic := viper.GetString("kafkaTopic")

	if pcapFile == "" && iface == "" {
		fmt.Println("Please specify a pcap file using --file or an interface using --interface")
		fmt.Println("Example: gtp2json --file captured.pcap or gtp2json --interface eth0")
		pflag.PrintDefaults()
		return
	}

	format := viper.GetString("format")
	switch format {
	case "numeric", "text", "mixed":
		config.SetOutputFormat(format)
		fmt.Printf("Output format set to: %s\n", format)
	default:
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a valid format. Use 'numeric', 'text', or 'mixed'.\n", format)
		return
	}

	fmt.Printf("pcapFile: %s, iface: %s, kafkaBroker: %s, kafkaTopic: %s\n", pcapFile, iface, kafkaBroker, kafkaTopic)

	var err error
	if kafkaBroker != "" {
		producer, err = sarama.NewSyncProducer([]string{kafkaBroker}, nil)
		if err != nil {
			log.Fatalf("Failed to start Sarama producer: %v", err)
		}
		defer producer.Close()
	}

	packetChan := make(chan gopacket.Packet, 200000)
	doneChan := make(chan struct{})

	go processPackets(packetChan, kafkaBroker, kafkaTopic, doneChan)

	if pcapFile != "" {
		handle, err := pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Fatalf("Opening pcap file failed: %v", err)
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packetChan <- packet
		}
	} else if iface != "" {
		handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("Opening interface failed: %v", err)
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packetChan <- packet
		}
	}

	close(packetChan)
	<-doneChan
}

func processPackets(packetChan <-chan gopacket.Packet, kafkaBroker, kafkaTopic string, doneChan chan<- struct{}) {
	for packet := range packetChan {
		processPacket(packet, kafkaBroker, kafkaTopic)
	}
	doneChan <- struct{}{}
}

func processPacket(packet gopacket.Packet, kafkaBroker, kafkaTopic string) {
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

		if kafkaBroker != "" {
			sendToKafka(jsonData, kafkaTopic)
		} else {
			outputToStdout(jsonData)
		}
	}
}

func sendToKafka(data []byte, kafkaTopic string) {
	msg := &sarama.ProducerMessage{
		Topic: kafkaTopic,
		Value: sarama.ByteEncoder(data),
	}

	partition, offset, err := producer.SendMessage(msg)
	if err != nil {
		log.Printf("Failed to send message to Kafka: %v", err)
		return
	}

	log.Printf("Message is stored in topic(%s)/partition(%d)/offset(%d)\n", kafkaTopic, partition, offset)
}

func outputToStdout(data []byte) {
	fmt.Println(string(data))
}
