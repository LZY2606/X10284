package mqttwire

// Builder constructs raw MQTT 5.0 packets for fixtures.
type Builder struct{}

func NewBuilder() *Builder { return &Builder{} }

func encU16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func encU32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func encString(s string) []byte {
	b := []byte(s)
	return append(encU16(uint16(len(b))), b...)
}

func encVBI(v int) []byte {
	var out []byte
	for {
		d := byte(v % 128)
		v /= 128
		if v > 0 {
			d |= 0x80
		}
		out = append(out, d)
		if v == 0 {
			return out
		}
	}
}

func finish(pType, flags byte, variable []byte) []byte {
	h := []byte{(pType << 4) | flags}
	h = append(h, encVBI(len(variable))...)
	return append(h, variable...)
}

type ConnectOpt struct {
	ClientID             string
	CleanStart           bool
	SessionExpiry        uint32
	KeepAlive            uint16
	SessionExpiryOmitted bool
}

func (b *Builder) Connect(o ConnectOpt) []byte {
	v := encString("MQTT")
	v = append(v, 5) // MQTT 5.0
	var flags byte
	if o.CleanStart {
		flags |= 0x02
	}
	v = append(v, flags)
	v = append(v, encU16(o.KeepAlive)...)
	var props []byte
	if !o.SessionExpiryOmitted {
		props = append(props, 17)
		props = append(props, encU32(o.SessionExpiry)...)
	}
	v = append(v, encVBI(len(props))...)
	v = append(v, props...)
	v = append(v, encString(o.ClientID)...)
	return finish(TypeCONNECT, 0, v)
}

type ConnackOpt struct {
	SessionPresent bool
	Reason         byte
	SessionExpiry  *uint32
}

func (b *Builder) Connack(o ConnackOpt) []byte {
	var flags byte
	if o.SessionPresent {
		flags = 1
	}
	v := []byte{flags, o.Reason}
	var props []byte
	if o.SessionExpiry != nil {
		props = append(props, 17)
		props = append(props, encU32(*o.SessionExpiry)...)
	}
	v = append(v, encVBI(len(props))...)
	v = append(v, props...)
	return finish(TypeCONNACK, 0, v)
}

type PublishOpt struct {
	DUP        bool
	QoS        byte
	Retain     bool
	Topic      string
	PacketID   uint16
	Payload    []byte
	TopicAlias *uint16
	TopicEmpty bool
}

func (b *Builder) Publish(o PublishOpt) []byte {
	var flags byte
	if o.DUP {
		flags |= 0x08
	}
	flags |= (o.QoS & 0x03) << 1
	if o.Retain {
		flags |= 0x01
	}
	topic := o.Topic
	if o.TopicEmpty {
		topic = ""
	}
	v := encString(topic)
	if o.QoS > 0 {
		v = append(v, encU16(o.PacketID)...)
	}
	var props []byte
	if o.TopicAlias != nil {
		props = append(props, 35)
		props = append(props, encU16(*o.TopicAlias)...)
	}
	v = append(v, encVBI(len(props))...)
	v = append(v, props...)
	v = append(v, o.Payload...)
	return finish(TypePUBLISH, flags, v)
}

func (b *Builder) Ack(pType byte, packetID uint16, reason byte, withReason bool) []byte {
	flags := byte(0)
	if pType == TypePUBREL || pType == TypeUNSUBSCRIBE || pType == TypeSUBSCRIBE {
		flags = 0x02
	}
	v := encU16(packetID)
	if withReason {
		v = append(v, reason)
		v = append(v, 0) // empty properties
	}
	return finish(pType, flags, v)
}

type SubscribeOpt struct {
	PacketID uint16
	Filters  []SubFilter
}

func (b *Builder) Subscribe(o SubscribeOpt) []byte {
	v := encU16(o.PacketID)
	v = append(v, 0) // empty properties
	for _, f := range o.Filters {
		v = append(v, encString(f.Filter)...)
		v = append(v, f.QoS)
	}
	return finish(TypeSUBSCRIBE, 0x02, v)
}

func (b *Builder) Suback(packetID uint16, reasons []byte) []byte {
	v := encU16(packetID)
	v = append(v, 0)
	v = append(v, reasons...)
	return finish(TypeSUBACK, 0, v)
}

func (b *Builder) Unsubscribe(packetID uint16, filters []string) []byte {
	v := encU16(packetID)
	v = append(v, 0)
	for _, f := range filters {
		v = append(v, encString(f)...)
	}
	return finish(TypeUNSUBSCRIBE, 0x02, v)
}

func (b *Builder) Unsuback(packetID uint16) []byte {
	v := encU16(packetID)
	v = append(v, 0)
	return finish(TypeUNSUBACK, 0, v)
}

type DisconnectOpt struct {
	Reason        byte
	IncludeReason bool
}

func (b *Builder) Disconnect(o DisconnectOpt) []byte {
	if !o.IncludeReason {
		return finish(TypeDISCONNECT, 0, nil)
	}
	v := []byte{o.Reason, 0}
	return finish(TypeDISCONNECT, 0, v)
}

func (b *Builder) PingReq() []byte  { return finish(TypePINGREQ, 0, nil) }
func (b *Builder) PingResp() []byte { return finish(TypePINGRESP, 0, nil) }
