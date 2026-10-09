//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

// Minimal binding to WinDivert 2.2 (WinDivert.dll + WinDivert64.sys must sit
// next to the .exe). Only the five calls this tool needs.

// winDivertAddress mirrors WINDIVERT_ADDRESS (80 bytes). Kept opaque apart
// from the flag bits at offset 8.
type winDivertAddress [80]byte

const outboundBit = 1 << 1 // within byte 10: bit 17 of the flags word

func (a *winDivertAddress) setOutbound(out bool) {
	if out {
		a[10] |= outboundBit
	} else {
		a[10] &^= outboundBit
	}
}

const (
	layerNetwork  = 0
	shutdownBoth  = 3
	invalidHandle = ^uintptr(0)
)

var (
	wdDLL       *syscall.LazyDLL
	procOpen    *syscall.LazyProc
	procRecv    *syscall.LazyProc
	procSend    *syscall.LazyProc
	procClose   *syscall.LazyProc
	procShut    *syscall.LazyProc
	procCalcSum *syscall.LazyProc
)

// loadWinDivert loads WinDivert.dll by full path from the .exe's folder, so a
// planted DLL elsewhere on PATH is never picked up.
func loadWinDivert() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	for _, f := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return fmt.Errorf("%s not found next to the program (%s)", f, dir)
		}
	}
	wdDLL = syscall.NewLazyDLL(filepath.Join(dir, "WinDivert.dll"))
	if err := wdDLL.Load(); err != nil {
		return fmt.Errorf("loading WinDivert.dll: %w", err)
	}
	procOpen = wdDLL.NewProc("WinDivertOpen")
	procRecv = wdDLL.NewProc("WinDivertRecv")
	procSend = wdDLL.NewProc("WinDivertSend")
	procClose = wdDLL.NewProc("WinDivertClose")
	procShut = wdDLL.NewProc("WinDivertShutdown")
	procCalcSum = wdDLL.NewProc("WinDivertHelperCalcChecksums")
	return nil
}

type divert struct {
	h      uintptr
	sendMu sync.Mutex
	closed bool
}

func openDivert(filter string, priority int16) (*divert, error) {
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	h, _, e := procOpen.Call(uintptr(unsafe.Pointer(f)), layerNetwork, uintptr(priority), 0)
	if h == invalidHandle {
		switch e {
		case syscall.ERROR_ACCESS_DENIED:
			return nil, errors.New("access denied: run as administrator")
		case syscall.Errno(577): // ERROR_INVALID_IMAGE_HASH
			return nil, errors.New("driver signature rejected by Windows (WinDivert64.sys damaged or blocked)")
		case syscall.Errno(1275): // ERROR_DRIVER_BLOCKED
			return nil, errors.New("driver blocked by Windows/antivirus (check Core Isolation > vulnerable driver blocklist, or your antivirus)")
		}
		return nil, fmt.Errorf("WinDivertOpen(%q): %v", filter, e)
	}
	return &divert{h: h}, nil
}

func (d *divert) recv(buf []byte, addr *winDivertAddress) (int, error) {
	var n uint32
	r, _, e := procRecv.Call(d.h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return 0, e
	}
	return int(n), nil
}

// send recomputes all checksums, then injects the packet.
func (d *divert) send(pkt []byte, addr *winDivertAddress) error {
	if len(pkt) == 0 {
		return nil
	}
	procCalcSum.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(addr)), 0)
	return d.sendRaw(pkt, addr)
}

// sendRaw injects a packet as-is (checksums already valid).
func (d *divert) sendRaw(pkt []byte, addr *winDivertAddress) error {
	if len(pkt) == 0 {
		return nil
	}
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if d.closed {
		return errors.New("handle closed")
	}
	var n uint32
	r, _, e := procSend.Call(d.h, uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return e
	}
	return nil
}

// shutdown makes pending and future recv calls fail immediately.
func (d *divert) shutdown() { procShut.Call(d.h, shutdownBoth) }

// close releases the handle. Call after the recv loop has exited. Safe while
// other goroutines are still sending; later sends become no-ops.
func (d *divert) close() {
	d.shutdown()
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if !d.closed {
		d.closed = true
		procClose.Call(d.h)
	}
}
