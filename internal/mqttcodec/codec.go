// Package mqttcodec implements a small, dependency-free decoder/encoder for the
// subset of MQTT 5.0 (and the fixed headers shared with 3.1.1) needed by the
// session-imprint replay tool. It never rewrites captured bytes: decode keeps
// the raw frame alongside the parsed view.
package mqttcodec

import (
	"errors"
	"fmt"
)

// Control packet types (MQTT 5.0 §2.1.2).
const (
	RESERVED1   = 0
	CONNECT     = 1
	CONNACK     = 2
	PUBLISH     = 3
	PUBACK      = 4
	PUBREC      = 5
	PUBREL      = 6
	PUBCOMP     = 7
	SUBSCRIBE   = 8
	SUBACK      = 9
	UNSUBSCRIBE = 10
	UNSUBACK    = 11
	PINGREQ     = 12
	PINGRESP    = 13
	DISCONNECT  = 14
	AUTH        = 15
)

// PacketName maps a control packet type number to its spec name.
func PacketName(t byte) string {
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
		return "RESERVED"
	}
}

// Property identifiers (MQTT 5.0 §2.2.2.2).
const (
	PropPayloadFormat         byte = 1
	PropMessageExpiry         byte = 2
	PropContentType           byte = 3
	PropResponseTopic         byte = 8
	PropCorrelationData       byte = 9
	PropSubscriptionID        byte = 11
	PropSessionExpiryInterval byte = 17
	PropAssignedClientID      byte = 18
	PropServerKeepAlive       byte = 19
	PropAuthMethod            byte = 21
	PropAuthData              byte = 22
	PropRequestProblemInfo    byte = 23
	PropWillDelayInterval     byte = 24
	PropRequestResponseInfo   byte = 25
	PropResponseInfo          byte = 26
	PropServerReference       byte = 28
	PropReasonString          byte = 31
	PropReceiveMaximum        byte = 33
	PropTopicAliasMaximum     byte = 34
	PropTopicAlias            byte = 35
	PropMaximumQoS            byte = 36
	PropRetainAvailable       byte = 37
	PropUserProperty          byte = 38
	PropMaximumPacketSize     byte = 39
	PropWildcardSubAvailable  byte = 40
	PropSubIDAvailable        byte = 41
	PropSharedSubAvailable    byte = 42
	PropCleanStart            byte = 66
)

var errShort = errors.New("mqttcodec: truncated packet")

// Frame is the parsed view of one wire frame; Raw is the original bytes.
type Frame struct {
	Raw          []byte
	Type         byte
	Flags        byte // low 4 bits of fixed header
	DUP          bool
	QoS          byte
	Retain       bool
	RemainingLen int
	VarPayload   []Byte
	Properties   map[byte][]Byte
	UserProps    map[string][]string
	PacketID     uint16 // 0 when absent
	Topic        string // PUBLISH only (after alias resolution by caller if desired)
	ReasonCode   byte   // 0 when not present on wire

	// CONNECT fields.
	ProtocolLevel byte
	CleanStart    bool
	ClientID      string
	KeepAlive     uint16
	SessionExpiry uint32 // CONNECT/CONNACK/DISCONNECT, property 17
	TopicAliasMax uint16 // CONNECT(34 client→server max)/CONNACK(34 server→client max)
	WillQoS       byte
	WillRetain    bool
	WillTopic     string
	WillPayload   []byte
	DisReason     byte

	// SUBSCRIBE / SUBACK.
	SubFilters []SubFilter
	SubAcks    []SubAck

	// Parse diagnostics (non-fatal: header still usable).
	Warnings []string
}

// Byte is an offset-tagged byte span inside the raw frame.
type Byte struct {
	B []byte
}

// SubFilter is one SUBSCRIBE filter with its options.
type SubFilter struct {
	Filter            string
	QoS               byte
	NoLocal           bool
	RetainAsPublished bool
	RetainHandling    byte
}

// SubAck is one SUBACK reason code with retain-availability handling flag.
type SubAck struct {
	ReasonCode byte
}

func (f *Frame) DUPFlag() bool    { return f.DUP }
func (f *Frame) RetainFlag() bool { return f.Retain }
