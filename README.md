# gtp2json

Приложение на Go для захвата пакетов GTPv2 с сетевого интерфейса или pcap-файла, их декодирования и преобразования в JSON-формат для дальнейшей обработки или хранения. Приложение может отправлять данные в формате JSON в Kafka или выводить их в stdout, а также предоставляет встроенные метрики для Prometheus.

## Основные возможности
- Захват пакетов GTPv2 с сетевого интерфейса или из pcap-файла
- Декодирование пакетов GTPv2 в JSON-формат
- Гибкие варианты вывода: Kafka или stdout
- Настраиваемые параметры отправки батчей в Kafka и механизмы повторной попытки
- Встроенный сервер метрик для мониторинга


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

| Flag                           | Description                                                                          | Default            |
|--------------------------------|--------------------------------------------------------------------------------------|--------------------|
| `--debug`                      | Enable debug mode for detailed logging                                              | `false`            |
| `--file string`                | Path to the pcap file to analyze                                                    |                    |
| `--format string`              | Specifies the format of the output (numeric, text, mixed)                           | `numeric`          |
| `--interface string`           | Name of the interface to analyze                                                    |                    |
| `--kafkaBatchInterval duration`| Interval for Kafka batch sending                                                    | `10s`              |
| `--kafkaBatchSize int`         | Size of the Kafka batch                                                             | `10000`            |
| `--kafkaBufferSize int`        | Size of the Kafka ring buffer                                                       | `250000`           |
| `--kafkaTopic string`          | Kafka topic to send data to                                                         | `gtp_packets`      |
| `--kafka_brokers string`       | Addresses of the Kafka brokers, comma separated                                     |                    |
| `--kafka_cert_file string`     | TLS certificate file for Kafka (optional)                                           |                    |
| `--kafka_password string`      | Kafka password for SASL authentication                                              |                    |
| `--kafka_user string`          | Kafka username for SASL authentication                                              |                    |
| `--maxRetries int`             | Maximum number of retries for Kafka connection (use 0 for infinite retries)         | `25`               |
| `--metrics_addr string`        | Address for the metrics server (Prometheus, probes, about)                          | `:8080`            |
| `--packetBufferSize int`       | Size of the packet buffer channel                                                   | `200000`           |
| `--retryInterval duration`     | Interval between retries for Kafka connection                                       | `5s`               |

---

### Environment Variables

All options can also be configured using environment variables with the `G2J_` prefix. For example:
- `--kafka_brokers` can be set with the environment variable `G2J_KAFKA_BROKERS`.
- `--metrics_addr` can be set with `G2J_METRICS_ADDR`.

## Metrics
Приложение экспортирует следующие метрики Prometheus для мониторинга:

- `pcap_packets_received_total`: Общее количество пакетов, полученных через pcap.
- `pcap_packets_dropped_total`: Общее количество пакетов, потерянных pcap.
- `pcap_packets_if_dropped_total`: Общее количество пакетов, потерянных интерфейсом.
- `packet_channel_occupancy`: Текущее количество пакетов в канале `packetChan`.
- `ring_buffer_occupancy`: Текущее количество сообщений в кольцевом буфере.
- `packet_buffer_size`: Размер канала буфера пакетов.
- `kafka_buffer_size`: Размер кольцевого буфера Kafka.
- `kafka_batch_size`: Размер Kafka-батча.
- `gtp_ie_types_total`: Общее количество обработанных элементов информации (Information Elements) по типам (с меткой `ie_type`).

Метрики доступны по адресу, указанному в параметре `--metrics_addr` (по умолчанию: `:8080`).

## License
This project is licensed under the MIT License. See the LICENSE file for details.
