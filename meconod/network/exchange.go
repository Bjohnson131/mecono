package network

import (
	"math"
	"time"
)

const (
	BytesPerPayloadChunk uint32 = 1024 * 256 // 256 KB
)

// An exchange is a stateful request + response.
type Exchange struct {
	AttemptCounter     uint32
	LastAttempt        time.Time
	ReceivedResponse   bool
	Id                 uint64
	PayloadType        PayloadType
	Payload            []byte
	PayloadChunkStatus map[int]bool
	EncryptionKey      []byte
	Destination        *Node
	Controller         *Controller
}

// Actuate this exchange, which may be a no-op if there's nothing that can be done at this time.
func (exchange *Exchange) Actuate() {

}

func (exchange *Exchange) PayloadChunkCount() uint32 {
	return uint32(math.Ceil(float64(len(exchange.Payload)) / float64(BytesPerPayloadChunk)))
}

func (exchange *Exchange) PayloadChunk(index uint32) []byte {
	startByteI := index * BytesPerPayloadChunk
	endByteI := startByteI + BytesPerPayloadChunk
	return exchange.Payload[startByteI:endByteI]
}
