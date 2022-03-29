package network

import "time"

// An exchange is a stateful request + response.
type Exchange struct {
	AttemptCounter   uint32
	LastAttempt      time.Time
	ReceivedResponse bool
	Id               uint64
	PayloadType      PayloadType
	Payload          []byte
	EncryptionKey    []byte
	Destination      *Node
	Controller       *Controller
}

// Actuate this exchange, which may be a no-op if there's nothing that can be done at this time.
func (exchange *Exchange) Actuate() {

}
