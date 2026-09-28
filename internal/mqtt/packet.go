package mqtt

// PacketType is the MQTT control packet type (high nibble of fixed header).
type PacketType byte

const (
	CONNECT     PacketType = 1
	CONNACK     PacketType = 2
	PUBLISH     PacketType = 3
	PUBACK      PacketType = 4
	PUBREC      PacketType = 5
	PUBREL      PacketType = 6
	PUBCOMP     PacketType = 7
	SUBSCRIBE   PacketType = 8
	SUBACK      PacketType = 9
	UNSUBSCRIBE PacketType = 10
	UNSUBACK    PacketType = 11
	PINGREQ     PacketType = 12
	PINGRESP    PacketType = 13
	DISCONNECT  PacketType = 14
	AUTH        PacketType = 15
)

func (t PacketType) String() string {
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
	}
	return "UNKNOWN"
}

// Version is the MQTT protocol version.
type Version byte

const (
	V311 Version = 4
	V5   Version = 5
)

// Dir is the packet direction from the broker's perspective.
type Dir byte

const (
	// DirUp is client -> broker (received by broker).
	DirUp Dir = 0
	// DirDown is broker -> client (sent by broker).
	DirDown Dir = 1
)

func (d Dir) String() string {
	if d == DirUp {
		return "C->B"
	}
	return "B->C"
}

// Sub is a single subscription entry in SUBSCRIBE.
type Sub struct {
	Filter string
	QoS    byte
}

// Packet is a decoded MQTT control packet.
type Packet struct {
	Type    PacketType
	Version Version

	// Fixed-header flags (PUBLISH / PUBREL etc.)
	DUP    bool
	QoS    byte
	Retain bool

	PacketID uint16

	// PUBLISH
	Topic   string
	Payload []byte

	// CONNECT
	ClientID      string
	CleanStart    bool
	KeepAlive     uint16
	Username      string
	Password      []byte
	SessionExpiry *uint32 // seconds; nil = property absent
	TopicAliasMax *uint16 // nil = property absent

	// CONNACK
	SessionPresent bool
	ReasonCode     byte

	// SUBSCRIBE
	Subscriptions []Sub

	// SUBACK
	ReasonCodes []byte

	// MQTT 5 properties (subset used by replay)
	TopicAlias     *uint16
	SubscriptionID *uint32

	// Raw are the exact wire bytes the trace preserved.
	Raw []byte
}

// HasPacketID reports whether the packet type carries a packet identifier.
func (p *Packet) HasPacketID() bool {
	switch p.Type {
	case PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK:
		return true
	case PUBLISH:
		return p.QoS > 0
	}
	return false
}
