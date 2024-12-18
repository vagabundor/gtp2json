package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"gtp2json/config"
	"gtp2json/pkg/gtp2"
	"gtp2json/pkg/gtp2ie"
	"gtp2json/pkg/kafkabuff"
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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	ringBuffer    *kafkabuff.RingBuffer
	packetChan    chan gopacket.Packet
	AppVersion    string = "dev"
	AppName       string = "gtp2json"
)

var (
	packetsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pcap_packets_received_total",
		Help: "Total number of packets received by the pcap handle.",
	})
	packetsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pcap_packets_dropped_total",
		Help: "Total number of packets dropped by the pcap handle.",
	})
	packetsIfDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pcap_packets_if_dropped_total",
		Help: "Total number of packets dropped by the interface.",
	})
	packetChanOccupancy = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "packet_channel_occupancy",
		Help: "Number of packets currently in packetChan.",
	})
	ringBufferOccupancy = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ring_buffer_occupancy",
		Help: "Number of messages currently in the ring buffer.",
	})
	packetBufferSizeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "packet_buffer_size",
		Help: "Size of the packet buffer channel",
	})
	kafkaBufferSizeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kafka_buffer_size",
		Help: "Size of the Kafka ring buffer",
	})
	kafkaBatchSizeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kafka_batch_size",
		Help: "Size of the Kafka batch",
	})
	ieTypeCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "gtp_ie_types_total",
		Help: "Total number of processed Information Elements by type.",
	}, []string{"ie_type"})
)

func init() {
	prometheus.MustRegister(packetsReceived)
	prometheus.MustRegister(packetsDropped)
	prometheus.MustRegister(packetsIfDropped)
	prometheus.MustRegister(packetChanOccupancy)
	prometheus.MustRegister(ringBufferOccupancy)
	prometheus.MustRegister(packetBufferSizeGauge)
	prometheus.MustRegister(kafkaBufferSizeGauge)
	prometheus.MustRegister(kafkaBatchSizeGauge)
	prometheus.MustRegister(ieTypeCounter)
}

func main() {

	http.HandleFunc("/ready", readinessHandler)
	http.HandleFunc("/live", livenessHandler)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/about", aboutHandler)

	pflag.String("file", "", "Path to the pcap file to analyze")
	pflag.String("interface", "", "Name of the interface to analyze")
	pflag.Int("packetBufferSize", 200000, "Size of the packet buffer channel")
	pflag.String("format", "numeric", "Specifies the format of the output (numeric, text, mixed)")
	pflag.String("kafkaBroker", "", "Address of the Kafka broker (if not set, output to stdout)")
	pflag.String("kafkaTopic", "gtp_packets", "Kafka topic to send data to")
	pflag.Int("maxRetries", 25, "Maximum number of retries for Kafka connection (use 0 for infinite retries)")
	pflag.Duration("retryInterval", 5*time.Second, "Interval between retries for Kafka connection")
	pflag.Int("kafkaBufferSize", 250000, "Size of the Kafka ring buffer")
	pflag.Int("kafkaBatchSize", 10000, "Size of the Kafka batch")
	pflag.Duration("kafkaBatchInterval", 10*time.Second, "Interval for Kafka batch sending")
	pflag.String("metrics_addr", ":8080", "Address for the metrics server (prometheus, probes, about)")
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
	kafkaBufferSize := viper.GetInt("kafkaBufferSize")
	kafkaBatchSize := viper.GetInt("kafkaBatchSize")
	kafkaBatchInterval := viper.GetDuration("kafkaBatchInterval")
	metricsAddr := viper.GetString("metrics_addr")

	if pcapFile == "" && iface == "" {
		log.Println("Please specify a pcap file using --file or an interface using --interface")
		log.Println("Example: gtp2json --file captured.pcap or gtp2json --interface eth0")
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
		log.Printf("Output format set to: %s\n", format)
	default:
		log.Printf("Error: '%s' is not a valid format. Use 'numeric', 'text', or 'mixed'.", format)
		return
	}

	pcapBufferSize := os.Getenv("PCAP_BUFFER_SIZE")
	if pcapBufferSize == "" {
		pcapBufferSize = "default"
	}

	packetBufferSizeGauge.Set(float64(packetBufferSize))
	kafkaBufferSizeGauge.Set(float64(kafkaBufferSize))
	kafkaBatchSizeGauge.Set(float64(kafkaBatchSize))

	log.Printf(
		"pcapFile: %s, iface: %s, packetBufferSize: %d, kafkaBroker: %s, kafkaTopic: %s, \n"+
			"maxRetries: %d, retryInterval: %v, pcapBufferSize: %s, kafkaBufferSize: %d, kafkaBatchSize: %d\n",
		pcapFile, iface, packetBufferSize, kafkaBroker, kafkaTopic, maxRetries, retryInterval, pcapBufferSize, kafkaBufferSize, kafkaBatchSize,
	)

	var err error
	isReady.Store(false)

	if kafkaBroker != "" {
		//metrics server
		go func() {
			log.Printf("Starting metrics server on %s", metricsAddr)
			if err := http.ListenAndServe(metricsAddr, nil); err != nil {
				log.Fatalf("Failed to start HTTP server: %v", err)
			}
		}()

		producer, err = createKafkaProducer(kafkaBroker, maxRetries, retryInterval)
		if err != nil {
			log.Fatalf("Failed to start Sarama producer after retries: %v", err)
		}
		defer producer.Close()
		isReady.Store(true)

		ringBuffer = kafkabuff.NewRingBuffer(kafkaBufferSize)
		startKafkaBatchSender(ringBuffer, kafkaBatchSize, kafkaBatchInterval, kafkaTopic)
	}

	packetChan = make(chan gopacket.Packet, packetBufferSize)
	doneChan := make(chan struct{})

	go processPackets(packetChan, kafkaBroker, kafkaTopic, doneChan, ringBuffer)

	go func() {
		for {
			packetChanOccupancy.Set(float64(len(packetChan)))

			if ringBuffer != nil {
				ringBufferOccupancy.Set(float64(ringBuffer.Size()))
			} else {
				ringBufferOccupancy.Set(0)
			}

			time.Sleep(5 * time.Second)
		}
	}()

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

		if err := handle.SetBPFFilter("udp port 2123"); err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
		}

		go func() {
			var prevReceived, prevDropped, prevIfDropped int
			for {
				stats, err := handle.Stats()
				if err != nil {
					log.Printf("Error getting stats: %v", err)
					continue
				}

				packetsReceived.Add(float64(stats.PacketsReceived - prevReceived))
				packetsDropped.Add(float64(stats.PacketsDropped - prevDropped))
				packetsIfDropped.Add(float64(stats.PacketsIfDropped - prevIfDropped))

				prevReceived = stats.PacketsReceived
				prevDropped = stats.PacketsDropped
				prevIfDropped = stats.PacketsIfDropped

				time.Sleep(5 * time.Second)
			}
		}()

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

func livenessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Application is alive"))
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	html := `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>About</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                line-height: 1.6;
            }
            h1 {
                color: #333;
            }
            .info {
                margin-top: 20px;
            }
            .info dt {
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>About This Application</h1>
        <dl class="info">
            <dt>Name:</dt>
            <dd>` + AppName + `</dd>
            <dt>Version:</dt>
            <dd>` + AppVersion + `</dd>
            <dt>Author:</dt>
            <dd>Alexander Nikonov</dd>
            <dt>Description:</dt>
            <dd><strong>gtp2json</strong> is an application that captures GTPv2 packets from a network interface using pcap, decodes them, and converts the data into JSON format for further processing or storage.</dd>
        </dl>
    </body>
    </html>
    `

	_, err := w.Write([]byte(html))
	if err != nil {
		log.Printf("Failed to write /about response: %v", err)
	}
}

func createKafkaProducer(broker string, maxRetries int, retryInterval time.Duration) (sarama.SyncProducer, error) {
	var producer sarama.SyncProducer
	var err error

	config := sarama.NewConfig()

	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForLocal

	attemptCount := 0

	for i := 0; i < maxRetries || maxRetries == 0; i++ {
		attemptCount++

		producer, err = sarama.NewSyncProducer([]string{broker}, config)
		if err == nil {
			log.Printf("Connected to Kafka after %d attempt(s)\n", attemptCount)
			return producer, nil
		}

		if maxRetries == 0 {
			log.Printf("Failed to connect to Kafka (attempt %d/∞): %v\n", attemptCount, err)
		} else {
			log.Printf("Failed to connect to Kafka (attempt %d/%d): %v\n", attemptCount, maxRetries, err)
		}

		time.Sleep(retryInterval)

		if maxRetries == 0 {
			i--
		}
	}

	return nil, fmt.Errorf("could not connect to Kafka after %d attempts: %v", maxRetries, err)
}

func processPackets(packetChan <-chan gopacket.Packet, kafkaBroker, kafkaTopic string, doneChan chan<- struct{}, ringBuffer *kafkabuff.RingBuffer) {
	for packet := range packetChan {
		processPacket(packet, kafkaBroker, kafkaTopic, ringBuffer)
	}
	doneChan <- struct{}{}
}

func processPacket(packet gopacket.Packet, kafkaBroker, kafkaTopic string, ringBuffer *kafkabuff.RingBuffer) {
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

			ieTypeCounter.WithLabelValues(ieName).Inc()

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
			sendToKafka(jsonData, kafkaTopic, ringBuffer)
		} else {
			outputToStdout(jsonData)
		}
	}
}

func startKafkaBatchSender(ringBuffer *kafkabuff.RingBuffer, batchSize int, interval time.Duration, kafkaTopic string) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				if ringBuffer.Size() > 0 {
					batch := ringBuffer.GetBatch(batchSize)
					sendBatchToKafkaWithRetry(batch, kafkaTopic, maxRetries, retryInterval)
				}
			default:
				if ringBuffer.Size() >= batchSize {
					batch := ringBuffer.GetBatch(batchSize)
					sendBatchToKafkaWithRetry(batch, kafkaTopic, maxRetries, retryInterval)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
}

func sendBatchToKafkaWithRetry(batch []*sarama.ProducerMessage, kafkaTopic string, maxRetries int, retryInterval time.Duration) {

	for i := 0; i < maxRetries || maxRetries == 0; i++ {

		if !ensureProducerConnected(viper.GetString("kafkaBroker"), retryInterval) {
			log.Println("Failed to connect to Kafka. Aborting batch send.")
			return
		}

		err := producer.SendMessages(batch)
		if err != nil {
			var producerErrors sarama.ProducerErrors
			if errors.As(err, &producerErrors) {
				var failedMessages []*sarama.ProducerMessage
				for _, pe := range producerErrors {
					failedMessages = append(failedMessages, pe.Msg)
				}
				batch = failedMessages
				log.Printf("Retrying to send %d failed messages", len(failedMessages))
				time.Sleep(retryInterval)
				continue
			} else {
				log.Printf("Failed to send batch to Kafka: %v", err)
				isReady.Store(false)
				time.Sleep(retryInterval)
				continue
			}
		}

		log.Printf("Batch of %d messages sent to Kafka topic(%s)\n", len(batch), kafkaTopic)
		isReady.Store(true)
		return
	}

	log.Println("Failed to send batch to Kafka after retries")
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

func sendToKafka(data []byte, kafkaTopic string, ringBuffer *kafkabuff.RingBuffer) {
	msg := &sarama.ProducerMessage{
		Topic: kafkaTopic,
		Value: sarama.ByteEncoder(data),
	}
	ringBuffer.Add(msg)
}

func outputToStdout(data []byte) {
	fmt.Println(string(data))
}
