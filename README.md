# gtp2json

A Go application that captures GTPv2 packets from a network interface or pcap file, decodes them, and converts the data into JSON format for further processing or storage. The application can output the JSON data to a Kafka topic or stdout and provides built-in Prometheus metrics.

## Features
- Capture GTPv2 packets from a live network interface or a pcap file.
- Decode GTPv2 packets into JSON format.
- Flexible output options: Kafka or stdout.
- Configurable Kafka batching and retry mechanisms.
- Built-in metrics server for monitoring.

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd gtp2json
   ```
2. Build the application:
   ```bash
   go build -o gtp2json ./cmd
   ```

## Usage
Run the application with either a pcap file or a network interface.

### Examples
- Analyze a pcap file:
  ```bash
  ./gtp2json --file captured.pcap
  ```
- Capture packets from a live interface:
  ```bash
  ./gtp2json --interface eth0
  ```

### Options
| Flag                          | Description                                                                          | Default            |
|-------------------------------|--------------------------------------------------------------------------------------|--------------------|
| `--file string`               | Path to the pcap file to analyze                                                    |                    |
| `--format string`             | Specifies the format of the output (numeric, text, mixed)                           | `numeric`          |
| `--interface string`          | Name of the interface to analyze                                                    |                    |
| `--kafkaBatchInterval duration` | Interval for Kafka batch sending                                                    | `10s`              |
| `--kafkaBatchSize int`        | Size of the Kafka batch                                                             | `10000`            |
| `--kafkaBroker string`        | Address of the Kafka broker (if not set, output to stdout)                          |                    |
| `--kafkaBufferSize int`       | Size of the Kafka ring buffer                                                       | `250000`           |
| `--kafkaTopic string`         | Kafka topic to send data to                                                         | `gtp_packets`      |
| `--maxRetries int`            | Maximum number of retries for Kafka connection (use 0 for infinite retries)         | `25`               |
| `--metrics_addr string`       | Address for the metrics server (Prometheus, probes, about)                          | `:8080`            |
| `--packetBufferSize int`      | Size of the packet buffer channel                                                   | `200000`           |
| `--retryInterval duration`    | Interval between retries for Kafka connection                                       | `5s`               |

All options can also be configured using environment variables with the `G2J_` prefix. For example:
- `--kafkaBroker` can be set with the environment variable `G2J_KAFKA_BROKER`.
- `--metrics_addr` can be set with `G2J_METRICS_ADDR`.

## Metrics
The application exposes the following Prometheus metrics for monitoring:

- `gtp2json_packets_received_total`: Total number of packets received.
- `gtp2json_packets_processed_total`: Total number of packets successfully processed.
- `gtp2json_kafka_retries_total`: Total number of retries for Kafka connection.
- `gtp2json_kafka_buffer_utilization`: Current utilization of the Kafka ring buffer.
- `gtp2json_packet_buffer_utilization`: Current utilization of the packet buffer channel.
- `gtp2json_processing_duration_seconds`: Histogram of packet processing durations.

Metrics are accessible at the address specified by `--metrics_addr` (default: `:8080`).

## License
This project is licensed under the MIT License. See the LICENSE file for details.
