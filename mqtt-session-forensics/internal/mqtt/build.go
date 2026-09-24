package mqtt

// Frame builders for the domain fixtures. They produce the exact subset of
// MQTT used by the case pack; bytes are the authoritative source thereafter.

func encString(s string) []byte {
	b := []byte{byte(len(s) >> 8), byte(len(s))}
	return append(b, []byte(s)...)
}

func encVarInt(n int) []byte {
	var out []byte
	for {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		out = append(out, d)
		if n == 0 {
			return out
		}
	}
}

func frame(t byte, flags byte, body []byte) []byte {
	hdr := []byte{(t << 4) | flags}
	hdr = append(hdr, encVarInt(len(body))...)
	return append(hdr, body...)
}

// Connect builds a CONNECT. level 4 => MQTT3.1.1; level 5 => MQTT5 with
// optional session expiry (seconds) in the connect properties.
func Connect(level byte, clientID string, cleanStart bool, keepalive uint16, sessionExpirySec uint32, hasExpiry bool) []byte {
	var body []byte
	body = append(body, encString("MQTT")...)
	body = append(body, level)
	flags := byte(0)
	if cleanStart {
		flags |= 0x02
	}
	body = append(body, flags)
	body = append(body, byte(keepalive>>8), byte(keepalive))
	if level == 5 {
		var props []byte
		if hasExpiry {
			props = append(props, 17)
			props = append(props, byte(sessionExpirySec>>24), byte(sessionExpirySec>>16),
				byte(sessionExpirySec>>8), byte(sessionExpirySec))
		}
		body = append(body, encVarInt(len(props))...)
		body = append(body, props...)
	}
	body = append(body, encString(clientID)...)
	return frame(1, 0, body)
}

// Connack builds a CONNACK.
func Connack(sessionPresent bool, rc byte) []byte {
	flags := byte(0)
	if sessionPresent {
		flags = 1
	}
	return frame(2, 0, []byte{flags, rc})
}

// Publish builds a PUBLISH. qos 1/2 with packet id. MQTT5 topic alias property
// can be attached; aliasOnly omits the topic name (alias-only PUBLISH).
func Publish(dup bool, qos uint8, retain bool, topic string, packetID uint16, payload []byte,
	level byte, topicAlias uint16, aliasOnly bool) []byte {
	var flags byte
	if dup {
		flags |= 0x08
	}
	flags |= (qos & 0x03) << 1
	if retain {
		flags |= 0x01
	}
	var body []byte
	if !aliasOnly || topic != "" && topicAlias == 0 {
		body = append(body, encString(topic)...)
	} else if aliasOnly {
		// alias-only: zero length topic
		body = append(body, 0, 0)
	} else {
		body = append(body, encString(topic)...)
	}
	if qos > 0 {
		body = append(body, byte(packetID>>8), byte(packetID))
	}
	if level == 5 && topicAlias > 0 {
		props := []byte{35, byte(topicAlias >> 8), byte(topicAlias)}
		body = append(body, encVarInt(len(props))...)
		body = append(body, props...)
	}
	body = append(body, payload...)
	return frame(3, flags, body)
}

func ack(t byte, packetID uint16) []byte {
	body := []byte{byte(packetID >> 8), byte(packetID)}
	flags := byte(0)
	if t == 6 { // PUBREL has fixed header bits 0010
		flags = 0x02
	}
	return frame(t, flags, body)
}

func Puback(id uint16) []byte { return ack(4, id) }
func Pubrec(id uint16) []byte { return ack(5, id) }
func Pubrel(id uint16) []byte { return ack(6, id) }
func Pubcomp(id uint16) []byte { return ack(7, id) }

// Subscribe builds an MQTT5 SUBSCRIBE (0x82) with filters.
func Subscribe(packetID uint16, filters map[string]uint8) []byte {
	var body []byte
	body = append(body, byte(packetID>>8), byte(packetID))
	body = append(body, 0) // properties length
	for t, q := range filters {
		body = append(body, encString(t)...)
		body = append(body, q&0x03)
	}
	return frame(8, 0x02, body)
}

// Suback builds a SUBACK with grants.
func Suback(packetID uint16, grants []byte) []byte {
	var body []byte
	body = append(body, byte(packetID>>8), byte(packetID))
	body = append(body, 0) // properties length
	body = append(body, grants...)
	return frame(9, 0, body)
}

// Unsubscribe builds an MQTT5 UNSUBSCRIBE (0xA2).
func Unsubscribe(packetID uint16, topics []string) []byte {
	var body []byte
	body = append(body, byte(packetID>>8), byte(packetID))
	body = append(body, 0)
	for _, t := range topics {
		body = append(body, encString(t)...)
	}
	return frame(10, 0x02, body)
}

// Disconnect builds a DISCONNECT with reason code (MQTT5).
func Disconnect(level byte, reason byte) []byte {
	if level == 5 {
		return frame(14, 0, []byte{reason})
	}
	return frame(14, 0, nil)
}

// Pingreq builds a PINGREQ (type 12, no body).
func Pingreq() []byte { return frame(12, 0, nil) }
