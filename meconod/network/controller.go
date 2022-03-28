package network

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/jaksonkallio/mecono/meconod/encoding"
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

	// Messages coming into the controller
	Outbox MessageQueue

	// Messages leaving the controller
	Inbox MessageQueue

	// Whether the controller should be actively processing
	Started bool

	// Various signalling
	OutboxProcessingStopped    chan bool
	InboxProcessingStopped     chan bool
	OutboxProcessingShouldStop chan bool
	InboxProcessingShouldStop  chan bool
}

func InitController(name string, motd string) (*Controller, error) {
	controller := &Controller{
		Name:                       name,
		Motd:                       motd,
		OutboxProcessingStopped:    make(chan bool),
		InboxProcessingStopped:     make(chan bool),
		OutboxProcessingShouldStop: make(chan bool),
		InboxProcessingShouldStop:  make(chan bool),
	}

	controller.GenerateAsymmetricKeyPair()

	return controller, nil
}

func (controller *Controller) Start() {
	controller.Log("Starting controller")
	controller.Started = true

	go controller.processInbox()
	go controller.processOutbox()
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
	}
}

// The controller descriptor is a short string used to identify this controller
func (controller *Controller) Descriptor() string {
	address := controller.PublicKeyHashString()
	return fmt.Sprintf("%s-%s", address[0:3], address[len(address)-3:])
}

func (controller *Controller) Log(msg string) {
	log.Printf("[%s %s] %s", controller.Name, controller.Descriptor(), msg)
}

func (controller *Controller) Logf(msg string, tokens ...string) {
	controller.Log(fmt.Sprintf(msg, tokens))
}

func (controller *Controller) knowMessage(message *ForeignMessage) (*KnownMessage, error) {
	// TODO: implement
	return nil, nil
}

func (controller *Controller) processOutbox() {
	controller.Log("Outbox processing started")

	started := true
	for started {
		select {
		case outboxMessage := <-controller.Outbox.Messages:
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
		case inboxMessage := <-controller.Inbox.Messages:
			controller.processInboxMessage(inboxMessage)
		case <-controller.InboxProcessingShouldStop:
			started = false
		}
	}

	controller.Log("Inbox processing stopped")
	controller.InboxProcessingStopped <- true
}

func (controller *Controller) processOutboxMessage(message Message) {
	controller.Logf("Processing outbox message: %s", message.Descriptor())
}

func (controller *Controller) processInboxMessage(message Message) {
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

func (controller *Controller) PublicKeyHashString() string {
	return hex.EncodeToString(controller.PublicKeyHash())
}

func (controller *Controller) privateKeyString() string {
	return base64.StdEncoding.EncodeToString(controller.privateKey)
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

func (controller *Controller) Encode(knownMessage *KnownMessage) ([]byte, error) {
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
