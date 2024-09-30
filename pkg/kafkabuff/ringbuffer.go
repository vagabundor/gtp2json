package kafkabuff

import (
	"sync"

	"github.com/IBM/sarama"
)

// RingBuffer is a thread-safe circular buffer for storing Kafka messages
type RingBuffer struct {
	data  []*sarama.ProducerMessage
	size  int
	start int
	end   int
	full  bool
	mu    sync.Mutex
}

// NewRingBuffer creates a new ring buffer with the specified size.
func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		data: make([]*sarama.ProducerMessage, size),
		size: size,
	}
}

// Add inserts a new message into the buffer. If the buffer is full, it overwrites the oldest message.
func (rb *RingBuffer) Add(msg *sarama.ProducerMessage) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.data[rb.end] = msg
	if rb.full {
		rb.start = (rb.start + 1) % rb.size
	}
	rb.end = (rb.end + 1) % rb.size
	rb.full = rb.end == rb.start
}

// GetBatch retrieves up to batchSize messages from the ring buffer.
func (rb *RingBuffer) GetBatch(batchSize int) []*sarama.ProducerMessage {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.start == rb.end && !rb.full {
		return nil
	}

	var batch []*sarama.ProducerMessage
	for i := 0; i < batchSize && (rb.start != rb.end || rb.full); i++ {
		batch = append(batch, rb.data[rb.start])
		rb.start = (rb.start + 1) % rb.size
		rb.full = false
	}

	return batch
}

// Size returns the current number of messages in the buffer.
func (rb *RingBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.full {
		return rb.size
	}
	if rb.end >= rb.start {
		return rb.end - rb.start
	}
	return rb.size - rb.start + rb.end
}
