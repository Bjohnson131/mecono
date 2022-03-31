package network

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/jaksonkallio/mecono/meconod/pkg/model/proto"
	"github.com/jaksonkallio/mecono/meconod/pkg/utils/encoding"
)

const (
	MessageEncodingSchemaCode uint32 = 1
)

// A controller is the daemon that manages sending/receiving messages to nodes.
type Controller struct {

	// Name string
	Name string

	// Message of the day, used to share arbitrary information about the node with the network
	Motd string

	// Private key, encoded in hexadecimal
	privateKey []byte

	// Public key
	PublicKey []byte

	// Foreign messages leaving the controller.
	Outbox chan ForeignMessage

	// Foreign messages coming into the controller.
	Inbox chan ForeignMessage

	// All active exchanges initated by this controller.
	Exchanges []*Exchange

	// Whether the controller should be actively processing
	Started bool

	// Next unused thread ID
	NextExchangeId uint64

	// Various signalling
	OutboxProcessingStopped    chan bool
	InboxProcessingStopped     chan bool
	OutboxProcessingShouldStop chan bool
	InboxProcessingShouldStop  chan bool

	// Local storage of mappings from base 64 public key to node pointer.
	// TODO: Temporary solution, switch to persistent storage.
	Nodes map[encoding.Base64String]*Node

	// Neighbors of this controller.
	Neighbors []*Neighbor

	// Port that this controller listens for connections on.
	NetworkPort uint16

	// This makes unimplemented methods not create runtime errors from healthcheck.
	// Required by GRPC.
	proto.UnimplementedMeconodServiceServer

	GrpcServer *grpc.Server
}

func InitController(name string, motd string, networkPort uint16) (*Controller, error) {
	controller := &Controller{
		Name:                       name,
		Motd:                       motd,
		OutboxProcessingStopped:    make(chan bool),
		InboxProcessingStopped:     make(chan bool),
		OutboxProcessingShouldStop: make(chan bool),
		InboxProcessingShouldStop:  make(chan bool),
		NetworkPort:                networkPort,
		Neighbors:                  make([]*Neighbor, 0),
		Nodes:                      make(map[encoding.Base64String]*Node),
	}

	controller.GenerateAsymmetricKeyPair()

	return controller, nil
}

func (controller *Controller) AddNeighbor(
	node *Node,
	interfaceIpAddress string,
	ipAddress string,
	port uint16,
) error {
	// Check if this neighbor already exists
	for _, neighbor := range controller.Neighbors {
		if neighbor.InterfaceIpAddress == interfaceIpAddress {
			// Interface IP address is the same.
			if neighbor.IpAddress == ipAddress && neighbor.Port == port {
				// Same IP address and port on a specific interface, can't add this neighbor.
				return fmt.Errorf("neighbor already exists on this network interface")
			}
		}
	}

	neighbor, err := InitNeighbor(
		node,
		interfaceIpAddress,
		ipAddress,
		port,
	)
	if err != nil {
		return fmt.Errorf("could not add neighbor: %s", err)
	}

	controller.Neighbors = append(controller.Neighbors, neighbor)

	newNeighborHealthy := neighbor.HealthCheck()
	controller.Log(fmt.Sprintf("Added neighbor %s, %s", node.Descriptor(), encoding.BoolToHealthString(newNeighborHealthy)))

	return nil
}

func (controller *Controller) StartExchange(
	payloadType PayloadType,
	payload []byte,
	destination *Node,
) *Exchange {
	return &Exchange{
		AttemptCounter: 0,
		Id:             controller.ProvisionExchangeId(),
		Payload:        payload,
		PayloadType:    payloadType,
		Controller:     controller,
	}
}

func (controller *Controller) LookupNode(publicKey []byte) *Node {
	// Convert the public key bytes to something that can be used as a map key (hint: base64 string).
	publicKeyStr := encoding.BytesToSha256HashBase64String(publicKey)

	node, exists := controller.Nodes[publicKeyStr]
	if exists {
		// We've seen this node before, return the existing node reference.
		return node
	}

	// We have not seen this node before, create the node reference and return.
	node = &Node{
		PingSuccesses:                   0,
		PingTotal:                       0,
		PublicKey:                       publicKey,
		GeoPointKnown:                   false,
		NextOutboundAntiReplayCounter:   0,
		MinimumInboundAntiReplayCounter: 0,
	}

	// Add the newly created node to the database.
	controller.Nodes[publicKeyStr] = node

	return node
}

func (controller *Controller) Start() {
	controller.Log("Starting controller")
	controller.Started = true

	go controller.InitApi()
	go controller.processInbox()
	go controller.processOutbox()
}

// Provisions an unused exchange ID
func (controller *Controller) ProvisionExchangeId() uint64 {
	provisionedThreadId := controller.NextExchangeId
	controller.NextExchangeId += 1
	return provisionedThreadId
}

func (controller *Controller) PrintKeys() {
	log.Printf("Prv Key: %s", controller.privateKey)
	log.Printf("Pub Key: %s", controller.PublicKey)
}

func (controller *Controller) Stop() {
	if controller.Started {
		controller.Log("Stopping controller")
		controller.Started = false
		controller.OutboxProcessingShouldStop <- true
		controller.InboxProcessingShouldStop <- true
		<-controller.OutboxProcessingStopped
		<-controller.InboxProcessingStopped
		controller.StopApi()
	}
}

func (controller *Controller) StopApi() {
	if controller.GrpcServer != nil {
		controller.Log("Stopping API service")
		controller.GrpcServer.GracefulStop()
	}
}

// The controller descriptor is a short string used to identify this controller
func (controller *Controller) Descriptor() string {
	return encoding.MiniHexString(controller.PublicKeyHashString())
}

func (controller *Controller) Log(msg string) {
	log.Printf("[%s %s] %s", controller.Name, controller.Descriptor(), msg)
}

func (controller *Controller) Logf(msg string, tokens ...string) {
	controller.Log(fmt.Sprintf(msg, tokens))
}

func (controller *Controller) knowMessage(message ForeignMessage) (*Message, error) {
	// TODO: implement
	return nil, nil
}

func (controller *Controller) processOutbox() {
	controller.Log("Outbox processing started")

	started := true
	for started {
		select {
		case outboxMessage := <-controller.Outbox:
			controller.processOutboxMessage(outboxMessage)
		case <-controller.OutboxProcessingShouldStop:
			started = false
		}
	}

	controller.Log("Outbox processing stopped")
	controller.OutboxProcessingStopped <- true
}

func (controller *Controller) processInbox() {
	controller.Log("Inbox processing started")

	started := true
	for started {
		select {
		case inboxMessage := <-controller.Inbox:
			controller.processInboxMessage(inboxMessage)
		case <-controller.InboxProcessingShouldStop:
			started = false
		}
	}

	controller.Log("Inbox processing stopped")
	controller.InboxProcessingStopped <- true
}

func (controller *Controller) processOutboxMessage(message ForeignMessage) {
	controller.Logf("Processing outbox message: %s", message.Descriptor())
}

func (controller *Controller) processInboxMessage(message ForeignMessage) {
	controller.Logf("Processing inbox message: %s", message.Descriptor())
}

// Gets base64 encoded version of public key
func (controller *Controller) PublicKeyString() string {
	return base64.StdEncoding.EncodeToString(controller.PublicKey)
}

func (controller *Controller) PublicKeyHash() []byte {
	sum := sha256.Sum256(controller.PublicKey)
	return sum[:]
}

func (controller *Controller) PublicKeyHashString() encoding.HexString {
	return encoding.BytesToHex(controller.PublicKeyHash())
}

func (controller *Controller) privateKeyString() encoding.Base64String {
	return encoding.BytesToBase64(controller.privateKey)
}

func (controller *Controller) AsymmetricallySign(messagebytes []byte) []byte {
	// Calculate a SHA256 sum of the message (we sign the message sum, not the entire message)
	messageSumArr := sha256.Sum256(controller.PublicKey)
	messageSum := messageSumArr[:]

	// Parse our private key from the private key bytes
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(controller.privateKey)
	if err != nil {
		panic(err)
	}

	// Create an RSA signature using PSS method
	signaturebytes, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, crypto.SHA256, messageSum, nil)
	if err != nil {
		panic(err)
	}

	return signaturebytes
}

func (controller *Controller) AsymmetricallyEncrypt(plainbytes []byte) []byte {
	rsaPublicKey, err := x509.ParsePKCS1PublicKey(controller.PublicKey)
	if err != nil {
		panic(err)
	}

	cipherbytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, plainbytes, nil)
	if err != nil {
		panic(err)
	}

	return cipherbytes
}

func (controller *Controller) AsymmetricallyDecrypt(cipherbytes []byte) []byte {
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(controller.privateKey)
	if err != nil {
		panic(err)
	}

	plainbytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, cipherbytes, nil)
	if err != nil {
		panic(err)
	}

	return plainbytes
}

func (controller *Controller) GenerateAsymmetricKeyPair() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	controller.PublicKey = x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	controller.privateKey = x509.MarshalPKCS1PrivateKey(privateKey)

	// Test the encryption and decryption of newly generated key
	plaintext := "Testing encryption and decryption of newly generated key"
	cipherbytes := controller.AsymmetricallyEncrypt([]byte(plaintext))
	decipherbytes := controller.AsymmetricallyDecrypt(cipherbytes)
	if string(decipherbytes) != plaintext {
		panic(fmt.Errorf("generated public/private keys failed to encrypt/decrypt successfully"))
	}

	controller.Log("Generated a valid RSA public/private key pair")
}

func (controller *Controller) Encode(knownMessage *Message) ([]byte, error) {
	// Encode itinerary
	itinerary := make([]byte, 0)
	for i := range knownMessage.Itinerary().Nodes {
		itinerary = append(itinerary, knownMessage.Itinerary().Nodes[i].PublicKey...)
	}

	// Encode the asymmetrically encrypted symmetric encryption key
	messageKey := controller.AsymmetricallyEncrypt(knownMessage.EncryptionKey)

	// Encode encrypted header
	symmetricallyEncryptedHeader, err := knownMessage.SymetricallyEncryptedHeader()
	if err != nil {
		return nil, fmt.Errorf("could not encode symmetrically encrypted header: %s", err)
	}

	header := symmetricallyEncryptedHeader

	// Encode encrypted payload
	payload := knownMessage.SymetricallyEncryptedPayload()

	var data []byte

	// Add schema code
	data = append(data, encoding.UInt32ToBytes(MessageEncodingSchemaCode)...)

	// Add itinerary length component
	data = append(data, encoding.UInt32ToBytes(uint32(len(itinerary)))...)

	// Add itinerary
	data = append(data, itinerary...)

	// Add message key length component
	data = append(data, encoding.UInt32ToBytes(uint32(len(messageKey)))...)

	// Add itinerary
	data = append(data, messageKey...)

	// Add header length
	data = append(data, encoding.UInt32ToBytes(uint32(len(header)))...)

	// Add header
	data = append(data, header...)

	// Add header length
	data = append(data, encoding.UInt32ToBytes(uint32(len(payload)))...)

	// Add header
	data = append(data, payload...)

	// Asymmetrically sign all of the data encoded so far
	signature := controller.AsymmetricallySign(data)

	// Add header length
	data = append(data, encoding.UInt32ToBytes(uint32(len(signature)))...)

	// Add header
	data = append(data, signature...)

	return data, nil
}

func (controller *Controller) InitApi() error {
	netAddr := fmt.Sprintf("127.0.0.1:%d", controller.NetworkPort)
	lis, err := net.Listen("tcp", netAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	controller.Logf("API service listening on %s", netAddr)

	controller.GrpcServer = grpc.NewServer()
	proto.RegisterMeconodServiceServer(controller.GrpcServer, controller)
	reflection.Register(controller.GrpcServer)
	controller.GrpcServer.Serve(lis)

	return nil
}
