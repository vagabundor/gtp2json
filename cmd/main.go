package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"gtp2json/config"
	"gtp2json/pkg/assets"
	"gtp2json/pkg/gtp2"
	"gtp2json/pkg/gtp2ie"
	"html/template"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/vagabundor/kafkabuff"
	"github.com/vagabundor/kafkaclient/v2"
	"github.com/vagabundor/kafkaclient/v2/scram"

	"github.com/IBM/sarama"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/nazar256/parapipe"
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

type KafkaMsgBuff struct {
	Topic      string
	RingBuffer *kafkabuff.RingBuffer
}

var (
	isReady       atomic.Value
	isFirstOutput        = true
	AppVersion    string = "dev"
)

const (
	AppName  = "gtp2json"
	AppDescr = `is an application that captures GTPv2 packets from a network interface using pcap, 
            decodes them, and converts the data into JSON format for further processing or storage.`
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
	pflag.String("kafka_brokers", "", "addresses of the Kafka brokers, comma separated")
	pflag.String("kafkaTopic", "gtp_packets", "Kafka topic to send data to")
	pflag.String("kafka_user", "", "Kafka username for SASL authentication")
	pflag.String("kafka_password", "", "Kafka password for SASL authentication")
	pflag.String("kafka_cert_file", "", "TLS certificate file for Kafka (optional)")
	pflag.Int("maxRetries", 25, "Maximum number of retries for Kafka connection (use 0 for infinite retries)")
	pflag.Duration("retryInterval", 5*time.Second, "Interval between retries for Kafka connection")
	pflag.Int("kafkaBufferSize", 250000, "Size of the Kafka ring buffer")
	pflag.Int("kafkaBatchSize", 10000, "Size of the Kafka batch")
	pflag.Duration("kafkaBatchInterval", 10*time.Second, "Interval for Kafka batch sending")
	pflag.String("metrics_addr", ":8080", "Address for the metrics server (prometheus, probes, about)")
	pflag.Bool("debug", false, "enable debug mode for detailed logging")
	pflag.Parse()

	viper.SetEnvPrefix("G2J")
	viper.AutomaticEnv()
	viper.BindPFlags(pflag.CommandLine)

	pcapFile := viper.GetString("file")
	iface := viper.GetString("interface")
	packetBufferSize := viper.GetInt("packetBufferSize")
	kafkaBrokers := viper.GetString("kafka_brokers")
	kafkaTopic := viper.GetString("kafkaTopic")
	certKafkaFile := viper.GetString("kafka_cert_file")
	kafkaUsername := viper.GetString("kafka_user")
	kafkaPassword := viper.GetString("kafka_password")
	maxRetries := viper.GetInt("maxRetries")
	retryInterval := viper.GetDuration("retryInterval")
	kafkaBufferSize := viper.GetInt("kafkaBufferSize")
	kafkaBatchSize := viper.GetInt("kafkaBatchSize")
	kafkaBatchInterval := viper.GetDuration("kafkaBatchInterval")
	metricsAddr := viper.GetString("metrics_addr")
	debug := viper.GetBool("debug")

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
		"pcapFile: %s, iface: %s, packetBufferSize: %d, kafkaBrokers: %s, kafkaTopic: %s, \n"+
			"maxRetries: %d, retryInterval: %v, pcapBufferSize: %s, kafkaBufferSize: %d, kafkaBatchSize: %d\n",
		pcapFile, iface, packetBufferSize, kafkaBrokers, kafkaTopic, maxRetries, retryInterval, pcapBufferSize, kafkaBufferSize, kafkaBatchSize,
	)

	isReady.Store(false)

	useKafka := false
	var kmsgbuff *KafkaMsgBuff

	// Input packet buffer
	packetChan := make(chan gopacket.Packet, packetBufferSize)

	if kafkaBrokers != "" {

		useKafka = true

		//metrics server
		go func() {
			log.Printf("Starting metrics server on %s", metricsAddr)
			if err := http.ListenAndServe(metricsAddr, nil); err != nil {
				log.Fatalf("Failed to start HTTP server: %v", err)
			}
		}()

		logger := logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: "2006-01-02T15:04:05",
			FullTimestamp:   true,
		})
		log.SetOutput(logger.Writer())
		logger.Info("Application started")

		if debug {
			logger.SetLevel(logrus.DebugLevel)
		} else {
			logger.SetLevel(logrus.InfoLevel)
		}

		saramaConfig := sarama.NewConfig()
		saramaConfig.Producer.Return.Successes = true
		saramaConfig.Producer.RequiredAcks = sarama.WaitForAll
		saramaConfig.ClientID = AppName

		// Enable SASL SCRAM-SHA-512 if username and password are provided
		if kafkaUsername != "" && kafkaPassword != "" {
			saramaConfig.Net.SASL.Enable = true
			saramaConfig.Net.SASL.User = kafkaUsername
			saramaConfig.Net.SASL.Password = kafkaPassword
			saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512

			// Implement SCRAM-SHA-512 client using xdg-go/scram
			scramClientGen := &scram.XDGSCRAMClientGenerator{
				HashGeneratorFcn: scram.SHA512,
			}
			saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = scramClientGen.Generate
			logger.Infof("SASL SCRAM-SHA-512 authentication enabled for Kafka with user: %s", kafkaUsername)
		}

		// Enable TLS if a CA certificate file is provided
		if certKafkaFile != "" {
			tlsConfig, err := createTLSConfig(certKafkaFile)
			if err != nil {
				log.Fatalf("Failed to configure TLS: %v", err)
			}
			saramaConfig.Net.TLS.Enable = true
			saramaConfig.Net.TLS.Config = tlsConfig
			logger.Infof("TLS enabled for Kafka with CA certificate: %s", certKafkaFile)
		}

		brokerList := strings.Split(kafkaBrokers, ",")
		for i := range brokerList {
			brokerList[i] = strings.TrimSpace(brokerList[i])
		}

		// Initialize Kafka client
		kafkaClient, err := kafkaclient.NewKafkaClient(brokerList, 0, 1*time.Second, saramaConfig, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize Kafka client")
		}
		defer kafkaClient.Close()

		packetBufferSizeGauge.Set(float64(kafkaBufferSize))
		ringBuffer := kafkabuff.NewRingBuffer(kafkaBufferSize)
		if ringBuffer == nil {
			log.Fatalf("Failed to create Kafka ring buffer")
		}

		kmsgbuff = &KafkaMsgBuff{
			Topic:      kafkaTopic,
			RingBuffer: ringBuffer,
		}

		kafkaClient.StartBatchSender(ringBuffer, kafkaBatchSize, kafkaBatchInterval)

		isReady.Store(true)

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

	}

	doneChan := make(chan struct{})

	// Parallel packet processing with strict result ordering
	concurrency := runtime.NumCPU()
	pipeline := parapipe.NewPipeline(concurrency, parseGTP)

	go func() {
		for packet := range packetChan {
			pipeline.Push(packet)
		}
	}()

	go processOutput(pipeline, useKafka, kmsgbuff, doneChan)

	if pcapFile != "" {
		handle, err := pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Fatalf("Opening pcap file failed: %v", err)
		}
		defer handle.Close()

		dispatchPackets(handle, packetChan)

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

		dispatchPackets(handle, packetChan)
	}

	pipeline.Close()
	close(packetChan)
	<-doneChan

	if useKafka {
		log.Println("Waiting for Kafka buffer to flush...")
		for kmsgbuff.RingBuffer.Size() > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		log.Println("Kafka buffer flushed.")
	}

	log.Println("All tasks completed. Exiting.")
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
	// html-template
	tmplData, err := assets.AboutHTML.ReadFile("html/about.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Failed to load about.html: %v", err)
		return
	}

	tmpl, err := template.New("about").Parse(string(tmplData))
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		log.Printf("Failed to parse template: %v", err)
		return
	}

	data := struct {
		AppName    string
		AppVersion string
		AppDescr   string
	}{
		AppName:    AppName,
		AppVersion: AppVersion,
		AppDescr:   AppDescr,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

func createTLSConfig(caCertPath string) (*tls.Config, error) {
	// Read the CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Add the CA certificate to the trusted pool
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to add CA certificate to the trusted pool")
	}

	// Create and return the TLS configuration
	return &tls.Config{
		RootCAs: certPool,
	}, nil
}

func dispatchPackets(handle *pcap.Handle, packchan chan gopacket.Packet) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packchan <- packet
	}
}

func processOutput(pipeline *parapipe.Pipeline[gopacket.Packet, []byte], useKafka bool, kmsgbuff *KafkaMsgBuff, doneChan chan<- struct{}) {
	defer finalizeOutput()

	for jsonData := range pipeline.Out() {
		if useKafka {
			err := sendToKafka(jsonData, kmsgbuff)
			if err != nil {
				log.Printf("Error sending to Kafka: %v", err)
			}
		} else {
			outputToStdout(jsonData)
		}
	}

	doneChan <- struct{}{}
}

func parseGTP(packet gopacket.Packet) ([]byte, bool) {
	gtpLayer := packet.Layer(gtp2.LayerTypeGTPv2)
	if gtpLayer == nil {
		return nil, false
	}
	gtp, ok := gtpLayer.(*gtp2.GTPv2)
	if !ok {
		log.Println("Error asserting layer to GTPv2")
		return nil, false
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
		return nil, false
	}
	return jsonData, true
}

func sendToKafka(data []byte, msgbuff *KafkaMsgBuff) error {
	if msgbuff == nil || msgbuff.RingBuffer == nil {
		return fmt.Errorf("invalid KafkaMsgBuff")
	}
	msg := &sarama.ProducerMessage{
		Topic: msgbuff.Topic,
		Value: sarama.ByteEncoder(data),
	}
	msgbuff.RingBuffer.Add(msg)
	return nil
}

func outputToStdout(data []byte) {
	if isFirstOutput {
		fmt.Println("[") // Start of array
		isFirstOutput = false
	} else {
		fmt.Println(",")
	}
	fmt.Print(string(data))
}

func finalizeOutput() {
	if !isFirstOutput {
		fmt.Println("\n]") // End of array
	}
}
