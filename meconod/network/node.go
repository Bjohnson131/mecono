package network

import "github.com/jaksonkallio/mecono/meconod/encoding"

// A node is a record of a remote node on the network
type Node struct {
	// Successful pings sent across this node (received some sort of response)
	PingSuccesses uint32

	// Total pings sent across this node
	PingTotal uint32

	// The public key of this node
	PublicKey []byte

	// Whether geo point is known.
	GeoPointKnown bool

	// Where the node is located geographically on a coordinate plane to assist with path finding
	GeoPoint Coords

	// Messages sent to this node will use this anti-replay nonce.
	// Incremented after every sent message.
	NextOutboundAntiReplayCounter uint64

	// Messages received from this node must have an anti-replay nonce greater than or equal to this number.
	// Updated with the next expected counter after each recieved message.
	MinimumInboundAntiReplayCounter uint64
}

// A neighbor is a node that is adjacent and reachable via network interface directly
type Neighbor struct {
	// The node for the neighbor
	Node *Node

	// The interface that neighbor is on
	InterfaceIpAddress string

	// The IP address the neighbor is hosted on
	IpAddress string

	// The port the neighbor is hosted on
	Port uint16
}

func (node *Node) Reliability() float32 {
	if node.PingTotal == 0 {
		return 1.0
	}

	return float32(node.PingSuccesses) / float32(node.PingTotal)
}

func (node *Node) Descriptor() string {
	return encoding.MiniHexString(encoding.BytesToSha256HashHexString(node.PublicKey))
}
