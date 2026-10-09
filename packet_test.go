package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// realClientHello captures the first TLS record a real Go TLS client sends.
func realClientHello(t *testing.T, host string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		cl.SetDeadline(time.Now().Add(2 * time.Second))
		cl.Handshake()
	}()
	s.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	if _, err := ioReadFull(s, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := ioReadFull(s, body); err != nil {
		t.Fatal(err)
	}
	s.Close()
	return append(hdr, body...)
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func tcpHeader(seq uint32) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], 50123)
	binary.BigEndian.PutUint16(h[2:], 443)
	binary.BigEndian.PutUint32(h[4:], seq)
	h[12] = 5 << 4
	h[13] = 0x18 // PSH|ACK
	return h
}

func ipv4Packet(proto byte, l4 []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(ip[4:], 0x1234)
	ip[6] = 0x40
	ip[8] = 128
	ip[9] = proto
	copy(ip[12:], []byte{192, 168, 1, 10})
	copy(ip[16:], []byte{162, 159, 135, 232})
	return append(ip, l4...)
}

func ipv6Packet(proto byte, l4 []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6] = proto
	ip[7] = 64
	ip[8], ip[23] = 0xfe, 1
	ip[24], ip[39] = 0x26, 2
	return append(ip, l4...)
}

func TestFindSNIRealClientHello(t *testing.T) {
	for _, host := range []string{"discord.com", "gateway.discord.gg", "a.b"} {
		ch := realClientHello(t, host)
		if !isClientHello(ch) {
			t.Fatalf("%s: not detected as ClientHello", host)
		}
		if got := sniName(ch); got != host {
			t.Fatalf("SNI = %q, want %q", got, host)
		}
	}
}

func TestFindSNITruncatedSegment(t *testing.T) {
	ch := realClientHello(t, "discord.com")
	off, n, _ := findSNI(ch)
	// Segment ends right after the hostname: still found.
	if _, _, ok := findSNI(ch[:off+n]); !ok {
		t.Fatal("SNI not found in segment ending at hostname end")
	}
	// Segment ends inside the hostname: must not report a bogus name.
	if _, _, ok := findSNI(ch[:off+n-1]); ok {
		t.Fatal("reported SNI from a cut-off hostname")
	}
	// Garbage / non-TLS never panics.
	for i := 0; i < len(ch); i++ {
		findSNI(ch[:i])
	}
	findSNI([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff})
}

func checkSplit(t *testing.T, pkt []byte, v6 bool, wantSeq uint32) {
	t.Helper()
	p, ok := parsePacket(pkt)
	if !ok || p.proto != protoTCP || p.v6 != v6 {
		t.Fatalf("parse failed (ok=%v)", ok)
	}
	pl := p.payload()
	pos := splitPos(pl, 0)
	off, n, _ := findSNI(pl)
	if pos <= off || pos >= off+n {
		t.Fatalf("split %d not inside hostname [%d,%d)", pos, off, off+n)
	}

	first, second := splitTCP(p, pos)
	p1, ok1 := parsePacket(first)
	p2, ok2 := parsePacket(second)
	if !ok1 || !ok2 {
		t.Fatal("split halves don't parse")
	}
	if p1.tcpSeq != wantSeq || p2.tcpSeq != wantSeq+uint32(pos) {
		t.Fatalf("seq: got %d/%d want %d/%d", p1.tcpSeq, p2.tcpSeq, wantSeq, wantSeq+uint32(pos))
	}
	if !bytes.Equal(append(append([]byte{}, p1.payload()...), p2.payload()...), pl) {
		t.Fatal("halves don't reassemble to the original payload")
	}
	// Neither half alone contains the full hostname.
	host := []byte(sniName(pl))
	if bytes.Contains(first, host) || bytes.Contains(second, host) {
		t.Fatal("a half still contains the whole hostname")
	}
	// Original packet untouched.
	if q, _ := parsePacket(pkt); !bytes.Equal(q.payload(), pl) {
		t.Fatal("original modified")
	}
}

func TestSplitIPv4(t *testing.T) {
	ch := realClientHello(t, "discord.com")
	seq := uint32(0xfffffff0) // also exercises sequence wraparound
	checkSplit(t, ipv4Packet(protoTCP, append(tcpHeader(seq), ch...)), false, seq)
}

func TestSplitIPv6(t *testing.T) {
	ch := realClientHello(t, "cdn.discordapp.com")
	checkSplit(t, ipv6Packet(protoTCP, append(tcpHeader(1000), ch...)), true, 1000)
}

func TestFixedSplit(t *testing.T) {
	ch := realClientHello(t, "discord.com")
	if got := splitPos(ch, 2); got != 2 {
		t.Fatalf("fixed split = %d", got)
	}
	if got := splitPos(ch, len(ch)+5); got != 0 {
		t.Fatalf("out-of-range split should be 0, got %d", got)
	}
}

func TestFakeClientHello(t *testing.T) {
	ch := realClientHello(t, "discord.com")
	pkt := ipv4Packet(protoTCP, append(tcpHeader(5), ch...))
	p, _ := parsePacket(pkt)
	f := fakeClientHello(p, 4)
	if f[8] != 4 {
		t.Fatalf("TTL = %d", f[8])
	}
	fp, ok := parsePacket(f)
	if !ok || sniName(fp.payload()) == "discord.com" || sniName(fp.payload()) == "" {
		t.Fatalf("decoy SNI = %q", sniName(fp.payload()))
	}
	if pkt[8] != 128 || sniName(p.payload()) != "discord.com" {
		t.Fatal("original modified")
	}
}

func TestUDPReplyIPv4(t *testing.T) {
	q := make([]byte, 8)
	binary.BigEndian.PutUint16(q[0:], 61000)
	binary.BigEndian.PutUint16(q[2:], 53)
	dnsQ := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(q[4:], uint16(8+len(dnsQ)))
	pkt := ipv4Packet(protoUDP, append(q, dnsQ...))
	p, ok := parsePacket(pkt)
	if !ok {
		t.Fatal("parse")
	}
	ans := []byte{0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 9, 9, 9}
	r, ok := parsePacket(buildUDPReply(p, ans))
	if !ok || r.proto != protoUDP || r.sport != 53 || r.dport != 61000 {
		t.Fatalf("bad reply ports %d->%d", r.sport, r.dport)
	}
	if !bytes.Equal(r.b[12:16], pkt[16:20]) || !bytes.Equal(r.b[16:20], pkt[12:16]) {
		t.Fatal("addresses not swapped")
	}
	if !bytes.Equal(r.payload(), ans) || int(binary.BigEndian.Uint16(r.b[24:])) != 8+len(ans) {
		t.Fatal("payload/udp length wrong")
	}
}

func TestUDPReplyIPv6(t *testing.T) {
	q := make([]byte, 8)
	binary.BigEndian.PutUint16(q[0:], 61001)
	binary.BigEndian.PutUint16(q[2:], 53)
	pkt := ipv6Packet(protoUDP, append(q, make([]byte, 12)...))
	p, _ := parsePacket(pkt)
	r, ok := parsePacket(buildUDPReply(p, make([]byte, 40)))
	if !ok || r.dport != 61001 || !bytes.Equal(r.b[8:24], pkt[24:40]) || len(r.payload()) != 40 {
		t.Fatal("bad IPv6 reply")
	}
}

func TestParseRejectsJunk(t *testing.T) {
	for _, b := range [][]byte{nil, {0x45}, make([]byte, 19), bytes.Repeat([]byte{0xff}, 60)} {
		if _, ok := parsePacket(b); ok {
			t.Fatalf("accepted junk %x", b)
		}
	}
	// IPv4 fragment is skipped.
	pkt := ipv4Packet(protoTCP, append(tcpHeader(1), 0x16, 3, 1, 0, 5, 1))
	pkt[6] = 0x20 // MF
	if _, ok := parsePacket(pkt); ok {
		t.Fatal("accepted a fragment")
	}
}
