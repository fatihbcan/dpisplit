//go:build windows && !cli

package main

import (
	"unicode/utf16"
	"unsafe"
)

// Notification-area (tray) icon with a right-click menu.

var (
	pShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
	pRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	pCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	pAppendMenuW            = user32.NewProc("AppendMenuW")
	pSetMenuDefaultItem     = user32.NewProc("SetMenuDefaultItem")
	pTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	pDestroyMenu            = user32.NewProc("DestroyMenu")
	pGetCursorPos           = user32.NewProc("GetCursorPos")
	pIsWindowVisible        = user32.NewProc("IsWindowVisible")
	msgTaskbarCreated       uintptr // sent to all windows when Explorer restarts
)

const (
	msgTray = wmApp + 10

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 0x1
	nifIcon   = 0x2
	nifTip    = 0x4
	nifInfo   = 0x10
	niifInfo  = 0x1

	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmNull          = 0x0000

	mfString    = 0x0
	mfGrayed    = 0x1
	mfSeparator = 0x800
	tpmRightBtn = 0x2
	tpmBottom   = 0x20
	tpmNoNotify = 0x80
	tpmRetCmd   = 0x100
	swHide      = 0

	cmdOpen   = 201
	cmdToggle = 202
	cmdExit   = 203
)

// notifyIconData mirrors NOTIFYICONDATAW (976 bytes on x64).
type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

var trayHintShown bool

func copyU16(dst []uint16, s string) {
	n := copy(dst[:len(dst)-1], utf16.Encode([]rune(s)))
	dst[n] = 0
}

func trayCall(op uintptr, flags uint32, fill func(*notifyIconData)) {
	nid := notifyIconData{hWnd: hwndMain, uID: 1, uFlags: flags, uCallbackMessage: msgTray}
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	if fill != nil {
		fill(&nid)
	}
	pShellNotifyIconW.Call(op, uintptr(unsafe.Pointer(&nid)))
}

func trayAdd() {
	if msgTaskbarCreated == 0 {
		msgTaskbarCreated, _, _ = pRegisterWindowMessageW.Call(ptr(u16("TaskbarCreated")))
	}
	trayCall(nimAdd, nifMsg|nifIcon|nifTip, trayFill)
}

func trayUpdate() { trayCall(nimModify, nifIcon|nifTip, trayFill) }

func trayRemove() { trayCall(nimDelete, 0, nil) }

func trayFill(n *notifyIconData) {
	n.hIcon = iconOffSm
	tip := "dpisplit - Disconnected"
	switch state {
	case stConnected:
		n.hIcon = iconOnSm
		tip = "dpisplit - Connected"
	case stConnecting:
		tip = "dpisplit - Connecting…"
	case stDisconnecting:
		tip = "dpisplit - Disconnecting…"
	}
	copyU16(n.szTip[:], tip)
}

func trayBalloon(title, text string) {
	trayCall(nimModify, nifInfo, func(n *notifyIconData) {
		copyU16(n.szInfoTitle[:], title)
		copyU16(n.szInfo[:], text)
		n.dwInfoFlags = niifInfo
	})
}

// hideToTray is what the X button does.
func hideToTray() {
	pShowWindow.Call(hwndMain, swHide)
	if !trayHintShown {
		trayHintShown = true
		msg := "Still running in the background. Right-click the tray icon to disconnect or exit."
		if state != stConnected {
			msg = "Still here in the tray. Click the icon to open, right-click for options."
		}
		trayBalloon("dpisplit", msg)
	}
}

func showFromTray() {
	pShowWindow.Call(hwndMain, swShow)
	pShowWindow.Call(hwndMain, swRestore)
	pSetForegroundWindow.Call(hwndMain)
}

func trayEvent(lParam uintptr) {
	switch lParam & 0xffff {
	case wmLButtonUp, wmLButtonDblClk:
		showFromTray()
	case wmRButtonUp:
		trayMenu()
	}
}

func trayMenu() {
	m, _, _ := pCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer pDestroyMenu.Call(m)

	toggle, toggleFlags := "Connect", uintptr(mfString)
	switch state {
	case stConnected:
		toggle = "Disconnect"
	case stConnecting, stDisconnecting:
		toggleFlags |= mfGrayed
	}
	pAppendMenuW.Call(m, mfString, cmdOpen, ptr(u16("Open dpisplit")))
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	pAppendMenuW.Call(m, toggleFlags, cmdToggle, ptr(u16(toggle)))
	pAppendMenuW.Call(m, mfSeparator, 0, 0)
	pAppendMenuW.Call(m, mfString, cmdExit, ptr(u16("Exit")))
	pSetMenuDefaultItem.Call(m, cmdOpen, 0)

	var pt struct{ x, y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(hwndMain) // required, or the menu won't close on outside click
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmRightBtn|tpmBottom|tpmNoNotify|tpmRetCmd,
		uintptr(pt.x), uintptr(pt.y), 0, hwndMain, 0)
	postMessage(hwndMain, wmNull, 0, 0)

	switch cmd {
	case cmdOpen:
		showFromTray()
	case cmdToggle:
		toggleConnection()
	case cmdExit:
		exitApp()
	}
}
