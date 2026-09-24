package mqtt

// Encoders produce real MQTT 5 wire bytes so fixtures and tests never depend
// on hand-copied hex.

func varint(n int) []byte {
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

func utf(s string) []byte {
	return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...)
}

func frame(typeNib, flags byte, body []byte) []byte {
	h := append([]byte{typeNib<<4 | flags}, varint(len(body))...)
	return append(h, body...)
}

func EncodeCONNECT(clientID string, cleanStart bool, keepAlive uint16, sessionExpiry *uint32) []byte {
	var props []byte
	if sessionExpiry != nil {
		props = append(props, 0x11,
			byte(*sessionExpiry>>24), byte(*sessionExpiry>>16), byte(*sessionExpiry>>8), byte(*sessionExpiry))
	}
	body := utf("MQTT")
	body = append(body, 5)
	flags := byte(0x02) // clean start
	if !cleanStart {
		flags = 0x00
	}
	body = append(body, flags, byte(keepAlive>>8), byte(keepAlive))
	body = append(body, varint(len(props))...)
	body = append(body, props...)
	body = append(body, utf(clientID)...)
	return frame(1, 0, body)
}

func EncodeCONNACK(sessionPresent bool) []byte {
	b := byte(0)
	if sessionPresent {
		b = 1
	}
	return frame(2, 0, []byte{b, 0x00, 0x00})
}

func EncodePUBLISH(dup bool, qos int, retain bool, topic string, pid *uint16, alias *uint16, payload []byte) []byte {
	flags := byte(0)
	if dup {
		flags |= 0x08
	}
	flags |= byte(qos&0x03) << 1
	if retain {
		flags |= 0x01
	}
	body := utf(topic)
	if qos > 0 && pid != nil {
		body = append(body, byte(*pid>>8), byte(*pid))
	}
	var props []byte
	if alias != nil {
		props = append(props, 0x23, byte(*alias>>8), byte(*alias))
	}
	body = append(body, varint(len(props))...)
	body = append(body, props...)
	body = append(body, payload...)
	return frame(3, flags, body)
}

func EncodeAck(typeNib byte, pid uint16) []byte {
	return frame(typeNib, map[byte]byte{6: 2}[typeNib], []byte{byte(pid >> 8), byte(pid)})
}

func EncodeSUBSCRIBE(pid uint16, subs ...Subscription) []byte {
	body := []byte{byte(pid >> 8), byte(pid), 0x00}
	for _, s := range subs {
		body = append(body, utf(s.Topic)...)
		body = append(body, byte(s.QoS))
	}
	return frame(8, 2, body)
}

func EncodeSUBACK(pid uint16) []byte {
	return frame(9, 0, []byte{byte(pid >> 8), byte(pid), 0x00, 0x01})
}

func EncodeDISCONNECT() []byte { return frame(14, 0, nil) }
