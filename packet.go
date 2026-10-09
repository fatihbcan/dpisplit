package main

import "encoding/binary"

// Packet parsing and rewriting. Pure Go, no Windows dependencies, so it can be
// unit-tested anywhere. Checksums are NOT computed here: on Windows the
// WinDivert helper recomputes them right before sending.

const (
	protoTCP = 6
	protoUDP = 17
)

type ipPacket struct {
	b      []byte // whole packet, trimmed to the IP length
	v6     bool
	proto  byte
	l4     int // offset of TCP/UDP header
	data   int // offset of TCP/UDP payload
	sport  uint16
	dport  uint16
	tcpSeq uint32
}

// parsePacket parses an IPv4/IPv6 packet carrying TCP or UDP.
func parsePacket(b []byte) (ipPacket, bool) {
	var p ipPacket
	if len(b) < 20 {
		return p, false
	}
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if ihl < 20 || total < ihl || total > len(b) {
			return p, false
		}
		// Skip IP fragments: more-fragments flag or non-zero offset.
		if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
			return p, false
		}
		p.b, p.proto, p.l4 = b[:total], b[9], ihl
	case 6:
		if len(b) < 40 {
			return p, false
		}
		total := 40 + int(binary.BigEndian.Uint16(b[4:]))
		if total > len(b) {
			return p, false
		}
		// No extension-header walking: Windows doesn't add them to normal traffic.
		p.b, p.v6, p.proto, p.l4 = b[:total], true, b[6], 40
	default:
		return p, false
	}

	switch p.proto {
	case protoTCP:
		if len(p.b) < p.l4+20 {
			return p, false
		}
		off := int(p.b[p.l4+12]>>4) * 4
		if off < 20 || p.l4+off > len(p.b) {
			return p, false
		}
		p.data = p.l4 + off
		p.tcpSeq = binary.BigEndian.Uint32(p.b[p.l4+4:])
	case protoUDP:
		if len(p.b) < p.l4+8 {
			return p, false
		}
		p.data = p.l4 + 8
	default:
		return p, false
	}
	p.sport = binary.BigEndian.Uint16(p.b[p.l4:])
	p.dport = binary.BigEndian.Uint16(p.b[p.l4+2:])
	return p, true
}

func (p ipPacket) payload() []byte { return p.b[p.data:] }

// isClientHello reports whether a TCP payload starts a TLS ClientHello record.
func isClientHello(pl []byte) bool {
	return len(pl) >= 6 && pl[0] == 0x16 && pl[1] == 0x03 && pl[5] == 0x01
}

// findSNI returns the offset and length of the server name inside a TLS
// ClientHello payload. Works even if the payload holds only the first part of
// the record (large post-quantum ClientHellos span several TCP segments), as
// long as the SNI itself is inside this segment.
func findSNI(pl []byte) (off, n int, ok bool) {
	if !isClientHello(pl) {
		return 0, 0, false
	}
	// 5 record header + 4 handshake header + 2 version + 32 random
	i := 5 + 4 + 2 + 32
	if i+1 > len(pl) {
		return 0, 0, false
	}
	i += 1 + int(pl[i]) // session id
	if i+2 > len(pl) {
		return 0, 0, false
	}
	i += 2 + int(binary.BigEndian.Uint16(pl[i:])) // cipher suites
	if i+1 > len(pl) {
		return 0, 0, false
	}
	i += 1 + int(pl[i]) // compression methods
	if i+2 > len(pl) {
		return 0, 0, false
	}
	i += 2 // extensions length
	for i+4 <= len(pl) {
		typ := binary.BigEndian.Uint16(pl[i:])
		elen := int(binary.BigEndian.Uint16(pl[i+2:]))
		body := i + 4
		if typ == 0 { // server_name
			// list length (2) + name type (1) + name length (2) + name
			if body+5 > len(pl) || pl[body+2] != 0 {
				return 0, 0, false
			}
			nlen := int(binary.BigEndian.Uint16(pl[body+3:]))
			start := body + 5
			if nlen == 0 || start+nlen > len(pl) {
				return 0, 0, false
			}
			return start, nlen, true
		}
		i = body + elen
	}
	return 0, 0, false
}

// splitPos picks where to cut the ClientHello payload.
// fixed > 0 forces a byte offset; otherwise cut in the middle of the hostname,
// falling back to offset 2 (GoodbyeDPI's classic default) when no SNI is seen.
func splitPos(pl []byte, fixed int) int {
	pos := 2
	if fixed > 0 {
		pos = fixed
	} else if off, n, ok := findSNI(pl); ok {
		pos = off + n/2
		if n < 2 {
			pos = off
		}
	}
	if pos <= 0 || pos >= len(pl) {
		return 0
	}
	return pos
}

// splitTCP cuts a TCP packet's payload at pos into two valid TCP packets
// (headers copied, lengths and sequence numbers fixed; checksums stale).
func splitTCP(p ipPacket, pos int) (first, second []byte) {
	hdr := p.b[:p.data]
	pl := p.payload()

	first = append(append(make([]byte, 0, len(hdr)+pos), hdr...), pl[:pos]...)
	second = append(append(make([]byte, 0, len(hdr)+len(pl)-pos), hdr...), pl[pos:]...)

	setIPLength(first, p.v6)
	setIPLength(second, p.v6)
	binary.BigEndian.PutUint32(second[p.l4+4:], p.tcpSeq+uint32(pos))

	if !p.v6 { // distinct IP IDs look more natural
		id := binary.BigEndian.Uint16(second[4:])
		binary.BigEndian.PutUint16(second[4:], id+1)
	}
	return first, second
}

// fakeClientHello returns a copy of the packet with the hostname overwritten by
// decoy letters and a low TTL, so it reaches the ISP's DPI box but expires
// before reaching the real server.
func fakeClientHello(p ipPacket, ttl int) []byte {
	f := append([]byte(nil), p.b...)
	if off, n, ok := findSNI(f[p.data:]); ok {
		const decoy = "wwwexampleorgcdnstaticassets"
		for i := 0; i < n; i++ {
			c := f[p.data+off+i]
			if c != '.' {
				f[p.data+off+i] = decoy[i%len(decoy)]
			}
		}
	}
	if p.v6 {
		f[7] = byte(ttl)
	} else {
		f[8] = byte(ttl)
	}
	return f
}

func setIPLength(b []byte, v6 bool) {
	if v6 {
		binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
	} else {
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	}
}

// buildUDPReply turns an outgoing UDP query packet into an incoming reply
// packet carrying data: addresses and ports swapped, lengths fixed.
func buildUDPReply(q ipPacket, data []byte) []byte {
	var ip []byte
	if q.v6 {
		ip = make([]byte, 40)
		copy(ip, q.b[:40])
		copy(ip[8:24], q.b[24:40]) // src <- old dst
		copy(ip[24:40], q.b[8:24]) // dst <- old src
		ip[6] = protoUDP
		ip[7] = 64
	} else {
		ip = make([]byte, 20)
		copy(ip, q.b[:20])
		ip[0] = 0x45           // drop any options
		ip[6], ip[7] = 0x40, 0 // DF, no fragment offset
		ip[8] = 64
		ip[9] = protoUDP
		copy(ip[12:16], q.b[16:20])
		copy(ip[16:20], q.b[12:16])
	}
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], q.dport)
	binary.BigEndian.PutUint16(udp[2:], q.sport)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(data)))

	out := append(append(ip, udp...), data...)
	setIPLength(out, q.v6)
	return out
}

// sniName extracts the hostname for logging, or "" if none.
func sniName(pl []byte) string {
	if off, n, ok := findSNI(pl); ok {
		return string(pl[off : off+n])
	}
	return ""
}
