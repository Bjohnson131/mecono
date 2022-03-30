package network

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

type MessageDirection int
type PayloadType uint8

const (
	Outbound MessageDirection = 1
	Inbound  MessageDirection = 2
)

const (
	PingRequest   PayloadType = 1
	PingResponse  PayloadType = 2
	ArbitraryData PayloadType = 3
	RouteRequest  PayloadType = 4
	RouteResponse PayloadType = 5
)

const (
	// Byte length of generated message symmetrical encryption keys.
	MessageEncryptionKeyLength uint8 = 32
)

// A message is a fully-known (AKA unencrypted) unit of data for transmitting through the network.
type Message struct {
	itinerary Path

	// Whether this message is a response.
	Response bool

	// Exchange ID that this message is a part of.
	ExchangeId uint64

	// Chunk ID within this that this message belongs to.
	PayloadChunkIndex uint64

	// Total chunk count for all of the messages
	PayloadChunkCount uint64

	// Payload type.
	PayloadType PayloadType

	// Raw payload bytes.
	PayloadChunk []byte

	// Symmetric encryption key, used to encrypt header and body
	EncryptionKey []byte
}

type MessageHeader struct {
	Response        bool   `json:"Response"`
	ExchangeId      uint64 `json:"ExchangeId"`
	PayloadTypeCode uint8  `json:"PayloadTypeCode"`
}

type PayloadTypeInfo struct {
	Description string
	TypeCode    uint8
}

type ForeignMessage struct {
	itinerary Path
	Body      []byte
}

type Directionality interface {
	Direction() MessageDirection
}

// A known message can always be known
func (knownMessage *Message) CanBeKnown(controller *Controller) bool {
	return true
}

func (knownMessage *Message) Descriptor() string {
	// TODO: include more info about message
	return "Known Message"
}

func (knownMessage *Message) Itinerary() Path {
	return knownMessage.itinerary
}

// A foreign message can be known if the controller is the intended recipient
func (foreignMessage *ForeignMessage) CanBeKnown(controller *Controller) bool {
	// TODO: see if controller is the intended recipient
	return false
}

func (foreignMessage *ForeignMessage) Descriptor() string {
	// TODO: include more info about message
	return "Foreign Message"
}

func (foreignMessage *ForeignMessage) Itinerary() Path {
	return foreignMessage.itinerary
}

// Serialize header into a JSON representation, then encode JSON string to bytes.
func (knownMessage *Message) SerializeHeader() ([]byte, error) {
	header := MessageHeader{
		Response:        knownMessage.Response,
		ExchangeId:      knownMessage.ExchangeId,
		PayloadTypeCode: LookupPayloadTypeInfo(knownMessage.PayloadType).TypeCode,
	}

	headerStr, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshalling header failed: %s", err)
	}

	return headerStr, nil
}

// Decrypt cipherbytes using the symmetrical encryption key for this message.
func (knownMessage *Message) SymmetricallyDecrypt(cipherbytes []byte) []byte {
	key, err := aes.NewCipher(knownMessage.EncryptionKey)
	if err != nil {
		panic(err)
	}

	plainbytes := make([]byte, len(cipherbytes))
	key.Decrypt(plainbytes, cipherbytes)

	return plainbytes
}

// Encrypt plainbytes using the symmetrical encryption key for this message.
func (knownMessage *Message) SymmetricallyEncrypt(plainbytes []byte) []byte {
	key, err := aes.NewCipher(knownMessage.EncryptionKey)
	if err != nil {
		panic(err)
	}

	cipherbytes := make([]byte, len(plainbytes))
	key.Encrypt(cipherbytes, []byte(plainbytes))

	return cipherbytes
}

// Generate and overwrite the message encryption key.
func (knownMessage *Message) GenerateEncryptionKey() {
	knownMessage.EncryptionKey = make([]byte, MessageEncryptionKeyLength)
	rand.Read(knownMessage.EncryptionKey)
}

func (knownMessage *Message) SymetricallyEncryptedHeader() ([]byte, error) {
	serializedHeader, err := knownMessage.SerializeHeader()
	if err != nil {
		return nil, fmt.Errorf("could not serialize header: %s", err)
	}

	return knownMessage.SymmetricallyEncrypt(serializedHeader), nil
}

func (knownMessage *Message) SymetricallyEncryptedPayload() []byte {
	return knownMessage.SymmetricallyEncrypt(knownMessage.PayloadChunk)
}

func LookupPayloadTypeInfo(payloadType PayloadType) PayloadTypeInfo {
	switch payloadType {
	case PingRequest:
		return PayloadTypeInfo{
			Description: "Outward Ping",
			TypeCode:    1,
		}
	case PingResponse:
		return PayloadTypeInfo{
			Description: "Response from Ping",
			TypeCode:    1,
		}
	case ArbitraryData:
		return PayloadTypeInfo{
			Description: "Arbitrary Data",
			TypeCode:    3,
		}
	case RouteRequest:
		return PayloadTypeInfo{
			Description: "Route Request",
			TypeCode:    4,
		}
	case RouteResponse:
		return PayloadTypeInfo{
			Description: "Route Response",
			TypeCode:    5,
		}
	default:
		return PayloadTypeInfo{
			Description: "Unrecognized Payload Type",
			TypeCode:    0,
		}
	}
}
