package kafkabuff

import (
	"reflect"
	"testing"

	"github.com/IBM/sarama"
)

func createTestMessage(value string) *sarama.ProducerMessage {
	return &sarama.ProducerMessage{
		Value: sarama.StringEncoder(value),
	}
}

func TestNewRingBuffer(t *testing.T) {
	tests := []struct {
		name string
		size int
		want *RingBuffer
	}{
		{
			name: "Create buffer with size 3",
			size: 3,
			want: &RingBuffer{
				data: make([]*sarama.ProducerMessage, 3),
				size: 3,
			},
		},
		{
			name: "Create buffer with size 0",
			size: 0,
			want: &RingBuffer{
				data: make([]*sarama.ProducerMessage, 0),
				size: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRingBuffer(tt.size)
			if !reflect.DeepEqual(got.data, tt.want.data) || got.size != tt.want.size {
				t.Errorf("NewRingBuffer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRingBuffer_Add(t *testing.T) {
	tests := []struct {
		name       string
		bufferSize int
		messages   []string
		wantSize   int
	}{
		{
			name:       "Add one message",
			bufferSize: 3,
			messages:   []string{"msg1"},
			wantSize:   1,
		},
		{
			name:       "Add multiple messages",
			bufferSize: 3,
			messages:   []string{"msg1", "msg2", "msg3"},
			wantSize:   3,
		},
		{
			name:       "Overwrite old messages",
			bufferSize: 2,
			messages:   []string{"msg1", "msg2", "msg3"},
			wantSize:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRingBuffer(tt.bufferSize)
			for _, msg := range tt.messages {
				rb.Add(createTestMessage(msg))
			}
			if got := rb.Size(); got != tt.wantSize {
				t.Errorf("RingBuffer size = %v, want %v", got, tt.wantSize)
			}
		})
	}
}

func TestRingBuffer_GetBatch(t *testing.T) {
	tests := []struct {
		name       string
		bufferSize int
		messages   []string
		batchSize  int
		wantBatch  []string
	}{
		{
			name:       "Get a batch from partially filled buffer",
			bufferSize: 3,
			messages:   []string{"msg1", "msg2"},
			batchSize:  1,
			wantBatch:  []string{"msg1"},
		},
		{
			name:       "Get a full batch",
			bufferSize: 3,
			messages:   []string{"msg1", "msg2", "msg3"},
			batchSize:  3,
			wantBatch:  []string{"msg1", "msg2", "msg3"},
		},
		{
			name:       "Get a batch larger than available messages",
			bufferSize: 3,
			messages:   []string{"msg1", "msg2"},
			batchSize:  3,
			wantBatch:  []string{"msg1", "msg2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRingBuffer(tt.bufferSize)
			for _, msg := range tt.messages {
				rb.Add(createTestMessage(msg))
			}
			batch := rb.GetBatch(tt.batchSize)
			gotBatch := []string{}
			for _, msg := range batch {
				gotBatch = append(gotBatch, string(msg.Value.(sarama.StringEncoder)))
			}
			if !reflect.DeepEqual(gotBatch, tt.wantBatch) {
				t.Errorf("RingBuffer.GetBatch() = %v, want %v", gotBatch, tt.wantBatch)
			}
		})
	}
}

func TestRingBuffer_Size(t *testing.T) {
	tests := []struct {
		name       string
		bufferSize int
		messages   []string
		wantSize   int
	}{
		{
			name:       "Empty buffer",
			bufferSize: 3,
			messages:   []string{},
			wantSize:   0,
		},
		{
			name:       "Partially filled buffer",
			bufferSize: 3,
			messages:   []string{"msg1", "msg2"},
			wantSize:   2,
		},
		{
			name:       "Full buffer",
			bufferSize: 3,
			messages:   []string{"msg1", "msg2", "msg3"},
			wantSize:   3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRingBuffer(tt.bufferSize)
			for _, msg := range tt.messages {
				rb.Add(createTestMessage(msg))
			}
			if got := rb.Size(); got != tt.wantSize {
				t.Errorf("RingBuffer.Size() = %v, want %v", got, tt.wantSize)
			}
		})
	}
}
