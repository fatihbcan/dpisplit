//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const version = "0.3.0"

// config holds the bypass settings. Defaults are the combination confirmed to
// get Discord through on the user's ISP.
type config struct {
	dns       bool
	split     int
	reverse   bool
	fakeTTL   int
	blockQUIC bool
}

func registerFlags(c *config) {
	flag.BoolVar(&c.dns, "dns", true, "answer DNS queries via Google DNS-over-HTTPS")
	flag.IntVar(&c.split, "split", 2, "split ClientHello at this byte offset (0 = middle of the hostname)")
	flag.BoolVar(&c.reverse, "reverse", true, "send the second half first")
	flag.IntVar(&c.fakeTTL, "fake-ttl", 5, "also send a decoy ClientHello with this TTL (0 = off)")
	flag.BoolVar(&c.blockQUIC, "block-quic", true, "drop QUIC (UDP 443) so apps fall back to TCP")
}

func (c config) describe() string {
	var parts []string
	if c.split > 0 {
		parts = append(parts, fmt.Sprintf("split at byte %d", c.split))
	} else {
		parts = append(parts, "split in hostname")
	}
	if c.reverse {
		parts = append(parts, "reversed")
	}
	if c.fakeTTL > 0 {
		parts = append(parts, fmt.Sprintf("decoy TTL %d", c.fakeTTL))
	}
	if c.dns {
		parts = append(parts, "Google DoH")
	}
	if c.blockQUIC {
		parts = append(parts, "QUIC off")
	}
	return strings.Join(parts, " · ")
}

// engine owns the WinDivert handles and the packet loops. Start/Stop can be
// called repeatedly (Connect/Disconnect).
type engine struct {
	mu       sync.Mutex
	handles  []*divert
	wg       sync.WaitGroup
	stopping atomic.Bool

	// onHost is called once per new hostname per session; onFail when the
	// engine dies on its own. Both may be called from any goroutine.
	onHost  func(host string)
	onFail  func(err error)
	verbose func(host, detail string)

	seenMu sync.Mutex
	seen   map[string]bool
}

func (e *engine) running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.handles) > 0
}

func (e *engine) Start(cfg config) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.handles) > 0 {
		return nil
	}
	if wdDLL == nil {
		if err := loadWinDivert(); err != nil {
			return err
		}
	}

	var opened []*divert
	defer func() {
		if err != nil {
			for _, h := range opened {
				h.close()
			}
		}
	}()

	tcp, err := openDivert(
		"outbound and !loopback and tcp.DstPort == 443 and tcp.PayloadLength > 5"+
			" and tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01", 0)
	if err != nil {
		// Fall back to a broader filter; the Go code re-checks every packet.
		if tcp, err = openDivert("outbound and !loopback and tcp.DstPort == 443 and tcp.PayloadLength > 0", 0); err != nil {
			return err
		}
	}
	opened = append(opened, tcp)

	var dns, quic *divert
	if cfg.dns {
		if dns, err = openDivert("outbound and !loopback and udp.DstPort == 53", 0); err != nil {
			return err
		}
		opened = append(opened, dns)
	}
	if cfg.blockQUIC {
		if quic, err = openDivert("outbound and !loopback and udp.DstPort == 443", 0); err != nil {
			return err
		}
		opened = append(opened, quic)
	}

	e.handles = opened
	e.stopping.Store(false)
	e.seenMu.Lock()
	e.seen = map[string]bool{}
	e.seenMu.Unlock()

	e.wg.Add(1)
	go func() { defer e.wg.Done(); e.tcpLoop(tcp, cfg) }()
	if dns != nil {
		doh := newDoHClient([]string{"8.8.8.8:443", "8.8.4.4:443"}, "dns.google")
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.dnsLoop(dns, doh) }()
	}
	if quic != nil {
		e.wg.Add(1)
		go func() { defer e.wg.Done(); e.dropLoop(quic) }()
	}
	return nil
}

// Stop disconnects. Blocks until the packet loops have exited.
func (e *engine) Stop() {
	e.mu.Lock()
	hs := e.handles
	e.handles = nil
	e.mu.Unlock()
	if len(hs) == 0 {
		return
	}
	e.stopping.Store(true)
	for _, h := range hs {
		h.shutdown()
	}
	e.wg.Wait()
	for _, h := range hs {
		h.close()
	}
}

func (e *engine) loopDied(what string, err error) {
	if e.stopping.Load() {
		return
	}
	go func() {
		e.Stop()
		if e.onFail != nil {
			e.onFail(fmt.Errorf("%s stopped: %v", what, err))
		}
	}()
}

func (e *engine) noteHost(host, detail string) {
	if host == "" {
		return
	}
	if e.verbose != nil {
		e.verbose(host, detail)
	}
	if e.onHost == nil {
		return
	}
	e.seenMu.Lock()
	isNew := !e.seen[host] && len(e.seen) < 10000
	if isNew {
		e.seen[host] = true
	}
	e.seenMu.Unlock()
	if isNew {
		e.onHost(host)
	}
}

func (e *engine) tcpLoop(d *divert, cfg config) {
	buf := make([]byte, 65575)
	var addr winDivertAddress
	for {
		n, err := d.recv(buf, &addr)
		if err != nil {
			e.loopDied("TLS splitter", err)
			return
		}
		pkt := buf[:n]

		p, ok := parsePacket(pkt)
		if !ok || p.proto != protoTCP || !isClientHello(p.payload()) {
			d.sendRaw(pkt, &addr)
			continue
		}
		pl := p.payload()
		pos := splitPos(pl, cfg.split)
		if pos == 0 {
			d.sendRaw(pkt, &addr)
			continue
		}
		if cfg.fakeTTL > 0 {
			d.send(fakeClientHello(p, cfg.fakeTTL), &addr)
		}
		first, second := splitTCP(p, pos)
		if cfg.reverse {
			d.send(second, &addr)
			d.send(first, &addr)
		} else {
			d.send(first, &addr)
			d.send(second, &addr)
		}
		e.noteHost(sniName(pl), fmt.Sprintf("cut at %d/%d", pos, len(pl)))
	}
}

func (e *engine) dnsLoop(d *divert, doh *dohClient) {
	sem := make(chan struct{}, 64)
	for {
		buf := make([]byte, 65575)
		var addr winDivertAddress
		n, err := d.recv(buf, &addr)
		if err != nil {
			e.loopDied("DNS", err)
			return
		}
		pkt := buf[:n]
		p, ok := parsePacket(pkt)
		if !ok || p.proto != protoUDP {
			d.sendRaw(pkt, &addr)
			continue
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			ans, err := doh.resolve(p.payload())
			if err != nil {
				d.sendRaw(pkt, &addr) // fall back to normal DNS for this query
				return
			}
			raddr := addr
			raddr.setOutbound(false)
			d.send(buildUDPReply(p, ans), &raddr)
		}()
	}
}

func (e *engine) dropLoop(d *divert) {
	buf := make([]byte, 65575)
	var addr winDivertAddress
	for {
		if _, err := d.recv(buf, &addr); err != nil {
			e.loopDied("QUIC blocker", err)
			return
		}
	}
}

// ---- process helpers ----

// acquireSingleInstance returns false if another dpisplit (app or console,
// including one started by a scheduled task) is already running.
func acquireSingleInstance() bool {
	name, _ := syscall.UTF16PtrFromString(`Global\dpisplit-instance`)
	k32 := syscall.NewLazyDLL(sysDLL("kernel32.dll"))
	h, _, e := k32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return true // can't tell; don't block the user
	}
	return e != syscall.ERROR_ALREADY_EXISTS
}

func isElevated() bool {
	t, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer t.Close()
	var elevation, n uint32
	const tokenElevation = 20
	err = syscall.GetTokenInformation(t, tokenElevation, (*byte)(unsafe.Pointer(&elevation)), 4, &n)
	return err == nil && elevation != 0
}

func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		args = append(args, syscall.EscapeArg(a))
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	shell32 := syscall.NewLazyDLL(sysDLL("shell32.dll"))
	r, _, e := shell32.NewProc("ShellExecuteW").Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), 0, 1)
	if r <= 32 {
		if e == syscall.Errno(1223) { // ERROR_CANCELLED: user said no
			return errors.New("administrator permission was declined")
		}
		return e
	}
	return nil
}

// sysDLL returns the full System32 path, so DLLs are never loaded from the
// program's folder or PATH.
func sysDLL(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}
