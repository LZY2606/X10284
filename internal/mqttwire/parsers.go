package mqttwire

func (p *Packet) parseConnect(r *reader) error {
	proto, err := r.s()
	if err != nil {
		return err
	}
	level, err := r.byte()
	if err != nil {
		return err
	}
	cflags, err := r.byte()
	if err != nil {
		return err
	}
	keepAlive, err := r.u16()
	if err != nil {
		return err
	}
	props, err := readProps(r)
	if err != nil {
		return err
	}
	props = append(props,
		Property{ID: 254, Name: "ProtocolName", Value: proto},
		Property{ID: 253, Name: "ProtocolLevel", Value: level},
		Property{ID: 252, Name: "ConnectFlags", Value: cflags},
		Property{ID: 251, Name: "KeepAlive", Value: keepAlive},
	)
	p.Props = props
	// Payload begins with client identifier; remaining will fields stay
	// untouched in Raw.
	cid, err := r.s()
	if err != nil {
		return err
	}
	p.Payload = []byte(cid)
	return nil
}

func (p *Packet) parseConnack(r *reader) error {
	ackFlags, err := r.byte()
	if err != nil {
		return err
	}
	reason, err := r.byte()
	if err != nil {
		return err
	}
	props, err := readProps(r)
	if err != nil {
		return err
	}
	props = append(props, Property{ID: 252, Name: "ConnAckFlags", Value: ackFlags})
	p.Reason = &reason
	p.Props = props
	return nil
}

func (p *Packet) parsePublish(r *reader) error {
	topic, err := r.s()
	if err != nil {
		return err
	}
	p.Topic = topic
	if p.QoS > 0 {
		pid, err := r.u16()
		if err != nil {
			return err
		}
		p.PacketID = pid
	}
	props, err := readProps(r)
	if err != nil {
		return err
	}
	p.Props = props
	p.Payload = append([]byte(nil), r.b[r.pos:]...)
	return nil
}

func (p *Packet) parseAck(r *reader) error {
	pid, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = pid
	if r.remaining() == 0 {
		return nil
	}
	reason, err := r.byte()
	if err != nil {
		return err
	}
	p.Reason = &reason
	if r.remaining() > 0 {
		props, err := readProps(r)
		if err != nil {
			return err
		}
		p.Props = props
	}
	return nil
}

func (p *Packet) parseSubscribe(r *reader) error {
	pid, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = pid
	props, err := readProps(r)
	if err != nil {
		return err
	}
	p.Props = props
	p.Payload = append([]byte(nil), r.b[r.pos:]...)
	return nil
}

func (p *Packet) parseSuback(r *reader) error {
	pid, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = pid
	props, err := readProps(r)
	if err != nil {
		return err
	}
	p.Props = props
	p.Payload = append([]byte(nil), r.b[r.pos:]...)
	return nil
}

func (p *Packet) parseUnsubscribe(r *reader) error {
	pid, err := r.u16()
	if err != nil {
		return err
	}
	p.PacketID = pid
	props, err := readProps(r)
	if err != nil {
		return err
	}
	p.Props = props
	p.Payload = append([]byte(nil), r.b[r.pos:]...)
	return nil
}

func (p *Packet) parseReasonProps(r *reader) error {
	if r.remaining() == 0 {
		return nil
	}
	reason, err := r.byte()
	if err != nil {
		return err
	}
	p.Reason = &reason
	if r.remaining() > 0 {
		props, err := readProps(r)
		if err != nil {
			return err
		}
		p.Props = props
	}
	return nil
}

// ParseSubscribeFilters extracts topic filters and requested QoS bytes
// from a SUBSCRIBE payload (raw after properties).
func ParseSubscribeFilters(p *Packet) ([]SubFilter, string) {
	return parseFilterList(p.Payload)
}

type SubFilter struct {
	Filter string
	QoS    byte
}

func parseFilterList(body []byte) ([]SubFilter, string) {
	r := newReader(body)
	var out []SubFilter
	for r.remaining() > 0 {
		f, err := r.s()
		if err != nil {
			return out, "truncated filter"
		}
		o, err := r.byte()
		if err != nil {
			return out, "truncated options"
		}
		out = append(out, SubFilter{Filter: f, QoS: o & 0x03})
	}
	return out, ""
}

// ParseSubackReasons returns SUBACK payload reason codes.
func ParseSubackReasons(p *Packet) []byte {
	return append([]byte(nil), p.Payload...)
}
