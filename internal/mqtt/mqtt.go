// Package mqtt implements a faithful MQTT 3.1.1 / 5.0 packet codec.
//
// The codec never hides a byte: Decode retains the raw bytes, direction and
// every flag alongside the parsed fields, and parse problems are returned as a
// Diagnostic attached to the result instead of dropping the packet. Unparseable
// values stay in place so upstream layers never invent data "to make a chart".
package mqtt

import (
	"errors"
	"fmt"
)

// Type is the MQTT control packet type (high nibble of byte 0).
type Type byte

const (
	RESERVED1 Type = 0
	CONNECT   Type = 1
	CONNACK   Type = 2
	PUBLISH   Type = 3
	PUBACK    Type = 4
	PUBREC    Type = 5
	PUBREL    Type = 6
	PUBCOMP   Type = 7
	SUBSCRIBE Type = 8
	SUBACK    Type = 9
	UNSUBSCRIBE Type = 10
	UNSUBACK  Type = 11
	PINGREQ   Type = 12
	PINGRESP  Type = 13
	DISCONNECT Type = 14
	AUTH      Type = 15
)

func (t Type) String() string {
	switch t {
	case CONNECT:
		return "CONNECT"
	case CONNACK:
		return "CONNACK"
	case PUBLISH:
		return "PUBLISH"
	case PUBACK:
		return "PUBACK"
	case PUBREC:
		return "PUBREC"
	case PUBREL:
		return "PUBREL"
	case PUBCOMP:
		return "PUBCOMP"
	case SUBSCRIBE:
		return "SUBSCRIBE"
	case SUBACK:
		return "SUBACK"
	case UNSUBSCRIBE:
		return "UNSUBSCRIBE"
	case UNSUBACK:
		return "UNSUBACK"
	case PINGREQ:
		return "PINGREQ"
	case PINGRESP:
		return "PINGRESP"
	case DISCONNECT:
		return "DISCONNECT"
	case AUTH:
		return "AUTH"
	default:
		return fmt.Sprintf("RESERVED(%d)", byte(t))
	}
}

// Diagnostic records a recoverable parse problem; the packet is still kept.
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Offset  int    `json:"offset"`
}

func (d Diagnostic) Error() string { return fmt.Sprintf("%s @%d: %s", d.Code, d.Offset, d.Message) }

// Filter represents one SUBSCRIBE filter.
type Filter struct {
	Topic string `json:"topic"`
	QoS   byte   `json:"qos"`
	// MQTT5 subscription options
	NoLocal bool `json:"noLocal,omitempty"`
	RetainAsPublished bool `json:"retainAsPublished,omitempty"`
	RetainHandling byte `json:"retainHandling,omitempty"`
}

// Properties holds MQTT 5.0 properties; only the fields this domain needs are
// decoded, but unknown/property-identifier values are surfaced via diagnostics.
type Properties struct {
	PayloadFormat   byte   `json:"payloadFormatIndicator,omitempty"`
	MessageExpiry   uint32 `json:"messageExpiryInterval,omitempty"`
	ContentType     string `json:"contentType,omitempty"`
	ResponseTopic   string `json:"responseTopic,omitempty"`
	CorrelationData []byte `json:"correlationData,omitempty"`
	SubscriptionID  []int  `json:"subscriptionIdentifier,omitempty"`
	SessionExpiry   uint32 `json:"sessionExpiryInterval,omitempty"`
	WillDelay       uint32 `json:"willDelayInterval,omitempty"`
	TopicAlias      uint16 `json:"topicAlias,omitempty"`
	ReceiveMaximum  uint16 `json:"receiveMaximum,omitempty"`
	MaxPacketSize   uint32 `json:"maximumPacketSize,omitempty"`
	TopicAliasMax   uint16 `json:"topicAliasMaximum,omitempty"`
	RequestRespInfo byte   `json:"requestResponseInformation,omitempty"`
	RequestProblem  byte   `json:"requestProblemInformation,omitempty"`
	UserProperty    [][2]string `json:"userProperty,omitempty"`
	ReasonCode      byte   `json:"reasonCode,omitempty"` // SUBACK payload reuse kept separate below
}

// Packet is a fully parsed control packet plus the original framing.
type Packet struct {
	Type       Type   `json:"type"`
	Flags      byte   `json:"flags"`
	DUP        bool   `json:"dup"`
	QoS        byte   `json:"qos"`
	Retain     bool   `json:"retain"`
	Protocol   byte   `json:"protocolLevel"` // 4 = 3.1.1, 5 = 5.0, 0 until CONNECT parsed
	Raw        []byte `json:"raw"`

	// CONNECT
	ClientID        string `json:"clientId,omitempty"`
	CleanStart      bool   `json:"cleanStart,omitempty"`
	CleanSession311 bool   `json:"cleanSession311,omitempty"`
	KeepAlive       uint16 `json:"keepAlive,omitempty"`
	WillTopic       string `json:"willTopic,omitempty"`
	WillPayload     []byte `json:"willPayload,omitempty"`
	WillQoS         byte   `json:"willQos,omitempty"`
	WillRetain      bool   `json:"willRetain,omitempty"`
	Username        string `json:"username,omitempty"`
	Password        []byte `json:"password,omitempty"`
	Props           *Properties `json:"props,omitempty"`

	// CONNACK
	SessionPresent bool `json:"sessionPresent,omitempty"`
	ReturnCode     byte `json:"returnCode,omitempty"`

	// PUBLISH
	Topic   string `json:"topic,omitempty"`
	PacketID uint16 `json:"packetId,omitempty"`
	Payload []byte `json:"payload,omitempty"`

	// ACK family / DISCONNECT
	Reason     byte   `json:"reason,omitempty"`
	AckProps   *Properties `json:"ackProps,omitempty"`

	// SUBSCRIBE family
	Filters []Filter `json:"filters,omitempty"`
	// SUBACK: one reason per filter
	Granted []byte `json:"granted,omitempty"`

	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// SessionExpiry is a convenience accessor for the CONNECT expiry in seconds,
// with the protocol default (0 for both levels).
func (p *Packet) SessionExpirySeconds() uint32 {
	if p.Protocol == 5 && p.Props != nil {
		return p.Props.SessionExpiry
	}
	return 0
}

// ErrShort is returned for frames that cannot contain a declared length.
var ErrShort = errors.New("mqtt: truncated packet")
