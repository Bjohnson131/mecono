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
	// A ping message being sent to it's destination.
	PingOutward PayloadType = 1

	// A response to a ping message being sent back to the original ping origin.
	PingResponse PayloadType = 2

	// Arbitrary data bytes.
	ArbitraryData PayloadType = 3
)

const (
	// Byte length of generated message symmetrical encryption keys.
	MessageEncryptionKeyLength uint8 = 32
)

type Message interface {
	// Can this message be known by the controller
	CanBeKnown(*Controller) bool

	// Unique descriptor of this message for the purposes of observability
	Descriptor() string

	// Upcoming path
	Itinerary() Path

	// Encodes the message into the standard byte format
	Encode() []byte
}

type KnownMessage struct {
	itinerary Path

	// Whether this message is a response.
	Response bool

	// Either this message's unique ID, or the ID of the message this is a response to.
	MessageId uint64

	// Which attempt is this message to be sent.
	Attempt uint32

	// Payload type.
	PayloadType PayloadType

	// Raw payload bytes.
	Payload []byte

	// Symmetric encryption key, used to encrypt header and body
	EncryptionKey []byte
}

type MessageHeader struct {
	Response        bool   `json:"Response"`
	MessageId       uint64 `json:"MessageId"`
	Attempt         uint32 `json:"Attempt"`
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
func (knownMessage *KnownMessage) CanBeKnown(controller *Controller) bool {
	return true
}

func (knownMessage *KnownMessage) Descriptor() string {
	// TODO: include more info about message
	return "Known Message"
}

func (knownMessage *KnownMessage) Itinerary() Path {
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
func (knownMessage *KnownMessage) SerializeHeader() ([]byte, error) {
	header := MessageHeader{
		Response:        knownMessage.Response,
		MessageId:       knownMessage.MessageId,
		Attempt:         knownMessage.Attempt,
		PayloadTypeCode: LookupPayloadTypeInfo(knownMessage.PayloadType).TypeCode,
	}

	headerStr, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshalling header failed: %s", err)
	}

	return headerStr, nil
}

// Decrypt cipherbytes using the symmetrical encryption key for this message.
func (knownMessage *KnownMessage) SymmetricallyDecrypt(cipherbytes []byte) []byte {
	key, err := aes.NewCipher(knownMessage.EncryptionKey)
	if err != nil {
		panic(err)
	}

	plainbytes := make([]byte, len(cipherbytes))
	key.Decrypt(plainbytes, cipherbytes)

	return plainbytes
}

// Encrypt plainbytes using the symmetrical encryption key for this message.
func (knownMessage *KnownMessage) SymmetricallyEncrypt(plainbytes []byte) []byte {
	key, err := aes.NewCipher(knownMessage.EncryptionKey)
	if err != nil {
		panic(err)
	}

	cipherbytes := make([]byte, len(plainbytes))
	key.Encrypt(cipherbytes, []byte(plainbytes))

	return cipherbytes
}

// Generate and overwrite the message encryption key.
func (knownMessage *KnownMessage) GenerateEncryptionKey() {
	knownMessage.EncryptionKey = make([]byte, MessageEncryptionKeyLength)
	rand.Read(knownMessage.EncryptionKey)
}

func (knownMessage *KnownMessage) SymetricallyEncryptedHeader() ([]byte, error) {
	serializedHeader, err := knownMessage.SerializeHeader()
	if err != nil {
		return nil, fmt.Errorf("could not serialize header: %s", err)
	}

	return knownMessage.SymmetricallyEncrypt(serializedHeader), nil
}

func (knownMessage *KnownMessage) SymetricallyEncryptedPayload() []byte {
	return knownMessage.SymmetricallyEncrypt(knownMessage.Payload)
}

func LookupPayloadTypeInfo(payloadType PayloadType) PayloadTypeInfo {
	switch payloadType {
	case PingOutward:
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
	default:
		return PayloadTypeInfo{
			Description: "Unrecognized Payload Type",
			TypeCode:    0,
		}
	}
}
