package network

import (
	"context"
	"fmt"
	"time"

	"github.com/jaksonkallio/mecono/meconod/encoding"
	"github.com/jaksonkallio/mecono/meconod/protos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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

	// Adjacent nodes
	AdjacentNodes []*Node
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

	// Last successfull neighbor health check
	LastHealthy time.Time

	// GRPC client connection to this neighbor
	GrpcClient protos.MeconodServiceClient

	// GRPC client connection
	GrpcClientConn *grpc.ClientConn
}

func InitNeighbor(
	node *Node,
	interfaceIpAddress string,
	ipAddress string,
	port uint16,
) (*Neighbor, error) {

	neighbor := &Neighbor{
		Node:               node,
		InterfaceIpAddress: interfaceIpAddress,
		IpAddress:          ipAddress,
		Port:               port,
	}

	// Create the GRPC client connection
	conn, err := grpc.Dial(neighbor.HostAddress(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("could not dial host: %s", err)
	}

	// Store a copy of the client connection
	neighbor.GrpcClientConn = conn

	// Create the GRPC client
	neighbor.GrpcClient = protos.NewMeconodServiceClient(conn)

	return neighbor, nil
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

func (neighbor *Neighbor) HostAddress() string {
	return fmt.Sprintf("%s:%d", neighbor.IpAddress, neighbor.Port)
}

func (neighbor *Neighbor) Stop() {
	if neighbor.GrpcClientConn != nil {
		neighbor.GrpcClientConn.Close()
	}
}

func (neighbor *Neighbor) HealthCheck() bool {
	neighborHealthCheckResponse, err := neighbor.GrpcClient.NeighborHealthCheck(context.TODO(), &protos.NeighborHealthCheckRequest{})
	healthy := (err == nil && neighborHealthCheckResponse.Status == "healthy")
	if healthy {
		neighbor.LastHealthy = time.Now()
	}

	return healthy
}
