package main

import (
	"encoding/json"
	"fmt"
	"gtp2json/config"
	"gtp2json/pkg/gtp2"
	"gtp2json/pkg/gtp2ie"
	"log"
	"net/http"
	"os"
	"sync/atomic"
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

var (
	producer      sarama.SyncProducer
	maxRetries    int
	retryInterval time.Duration
	isReady       atomic.Value
)

func main() {

	http.HandleFunc("/ready", readinessHandler)
	go func() {
		log.Println("Starting readiness probe server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	pflag.String("file", "", "Path to the pcap file to analyze")
	pflag.String("interface", "", "Name of the interface to analyze")
	pflag.Int("packetBufferSize", 200000, "Size of the packet buffer channel")
	pflag.String("format", "numeric", "Specifies the format of the output (numeric, text, mixed)")
	pflag.String("kafkaBroker", "", "Address of the Kafka broker (if not set, output to stdout)")
	pflag.String("kafkaTopic", "gtp_packets", "Kafka topic to send data to")
	pflag.Int("maxRetries", 25, "Maximum number of retries for Kafka connection (use 0 for infinite retries)")
	pflag.Duration("retryInterval", 5*time.Second, "Interval between retries for Kafka connection")
	pflag.Parse()

	viper.SetEnvPrefix("G2J")
	viper.AutomaticEnv()
	viper.BindPFlags(pflag.CommandLine)

	pcapFile := viper.GetString("file")
	iface := viper.GetString("interface")
	packetBufferSize := viper.GetInt("packetBufferSize")
	kafkaBroker := viper.GetString("kafkaBroker")
	kafkaTopic := viper.GetString("kafkaTopic")
	maxRetries = viper.GetInt("maxRetries")
	retryInterval = viper.GetDuration("retryInterval")

	if pcapFile == "" && iface == "" {
		fmt.Println("Please specify a pcap file using --file or an interface using --interface")
		fmt.Println("Example: gtp2json --file captured.pcap or gtp2json --interface eth0")
		pflag.PrintDefaults()
		return
	}

	if retryInterval == 0 {
		log.Fatalf("Invalid retryInterval format. Please specify a valid duration like '5s', '1m', etc.")
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

	fmt.Printf(
		"pcapFile: %s, iface: %s, packetBufferSize: %d, kafkaBroker: %s, kafkaTopic: %s, maxRetries: %d, retryInterval: %v\n",
		pcapFile, iface, packetBufferSize, kafkaBroker, kafkaTopic, maxRetries, retryInterval,
	)

	var err error
	isReady.Store(false)

	if kafkaBroker != "" {
		producer, err = createKafkaProducer(kafkaBroker, maxRetries, retryInterval)
		if err != nil {
			log.Fatalf("Failed to start Sarama producer after retries: %v", err)
		}
		defer producer.Close()
		isReady.Store(true)
	}

	packetChan := make(chan gopacket.Packet, packetBufferSize)
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

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	if isReady.Load().(bool) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Kafka is connected"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Kafka is not connected"))
	}
}

func createKafkaProducer(broker string, maxRetries int, retryInterval time.Duration) (sarama.SyncProducer, error) {
	var producer sarama.SyncProducer
	var err error

	for i := 0; i < maxRetries || maxRetries == 0; i++ {
		producer, err = sarama.NewSyncProducer([]string{broker}, nil)
		if err == nil {
			log.Printf("Connected to Kafka after %d attempt(s)\n", i+1)
			return producer, nil
		}

		log.Printf("Failed to connect to Kafka (attempt %d/%d): %v\n", i+1, maxRetries, err)
		time.Sleep(retryInterval)
		if maxRetries == 0 {
			i--
		}
	}

	return nil, fmt.Errorf("could not connect to Kafka after %d attempts: %v", maxRetries, err)
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

func sendToKafkaWithRetry(data []byte, kafkaTopic string, maxRetries int, retryInterval time.Duration) {
	msg := &sarama.ProducerMessage{
		Topic: kafkaTopic,
		Value: sarama.ByteEncoder(data),
	}

	for i := 0; i < maxRetries || maxRetries == 0; i++ {

		if !ensureProducerConnected(viper.GetString("kafkaBroker"), retryInterval) {
			log.Println("Failed to connect to Kafka. Aborting send.")
			return
		}

		partition, offset, err := producer.SendMessage(msg)
		if err != nil {
			log.Printf("Failed to send message to Kafka (attempt %d/%d): %v\n", i+1, maxRetries, err)
			isReady.Store(false)

			if maxRetries == 0 {
				i--
			}
			time.Sleep(retryInterval)
			continue
		} else {
			log.Printf("Message is stored in topic(%s)/partition(%d)/offset(%d)\n", kafkaTopic, partition, offset)
			isReady.Store(true)
			return
		}
	}

	log.Println("Failed to send message to Kafka after retries")
	isReady.Store(false)
}

func ensureProducerConnected(broker string, retryInterval time.Duration) bool {
	if producer == nil {
		log.Println("Producer is not initialized. Trying to reconnect.")
		var err error
		producer, err = createKafkaProducer(broker, 1, retryInterval)
		if err != nil {
			log.Printf("Failed to reconnect to Kafka: %v\n", err)
			return false
		} else {
			isReady.Store(true)
		}
	}
	return true
}

func sendToKafka(data []byte, kafkaTopic string) {
	sendToKafkaWithRetry(data, kafkaTopic, maxRetries, retryInterval)
}

func outputToStdout(data []byte) {
	fmt.Println(string(data))
}
