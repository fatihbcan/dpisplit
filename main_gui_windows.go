//go:build windows && !cli

package main

import (
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	className = "dpisplitWindow"
	taskName  = "dpisplit"

	idButton = 101
	idCheck  = 102

	msgLog       = wmApp + 1 // new activity lines queued
	msgResult    = wmApp + 2 // connect/disconnect finished; wParam = 1 if now connected; lParam 1 = connect failed, 2 = dropped
	msgAutostart = wmApp + 3 // autostart state known; wParam = 1 if enabled, lParam = 1 if from a failed change
)

const (
	stIdle = iota
	stConnecting
	stConnected
	stDisconnecting
)

var (
	cfg       config
	eng       *engine
	hInstance uintptr
	hwndMain  uintptr
	hStatus   uintptr
	hDetail   uintptr
	hButton   uintptr
	hCheck    uintptr
	hLogLabel uintptr
	hLog      uintptr
	state     = stIdle

	iconOff, iconOn, iconOffSm, iconOnSm uintptr

	logMu      sync.Mutex
	logPending []string
	errMu      sync.Mutex
	lastErr    error
	wndProcCB  = syscall.NewCallback(wndProc)
)

func main() {
	runtime.LockOSThread() // all window calls stay on this thread

	registerFlags(&cfg)
	autostart := flag.Bool("autostart", false, "start in the tray and connect immediately (used by Start with Windows)")
	flag.Parse()

	if !isElevated() {
		if err := relaunchElevated(); err != nil {
			messageBox(0, "dpisplit needs administrator rights to filter network packets.\n\n"+err.Error(), "dpisplit", mbIconWarning)
		}
		return
	}
	if !acquireSingleInstance() {
		if w, _, _ := pFindWindowW.Call(ptr(u16(className)), 0); w != 0 {
			pShowWindow.Call(w, 5) // SW_SHOW (it may be hidden in the tray)
			pShowWindow.Call(w, swRestore)
			pSetForegroundWindow.Call(w)
		} else {
			messageBox(0, "dpisplit is already running in the background (a console window or the scheduled task you created). Stop it first.", "dpisplit", mbIconWarning)
		}
		return
	}

	enableVisualStyles()
	setupDPI()

	eng = &engine{
		onHost: func(h string) { addLog("split   " + h) },
		onFail: func(err error) {
			setLastErr(err)
			postMessage(hwndMain, msgResult, 0, 2)
		},
	}

	createMainWindow(*autostart)
	go func() { // schtasks takes a moment; don't hold up the window
		on := autostartEnabled()
		postMessage(hwndMain, msgAutostart, b2u(on), 0)
	}()
	if *autostart {
		connect()
	}

	var m msgT
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if r == 0 || int32(r) == -1 {
			break
		}
		if d, _, _ := pIsDialogMessageW.Call(hwndMain, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	eng.Stop()
}

func createMainWindow(trayOnly bool) {
	hInstance, _, _ = pGetModuleHandleW.Call(0)
	iconOff, iconOn = makeIcon(scale(32), 0x8a, 0x8a, 0x8a), makeIcon(scale(32), 0x2e, 0x7d, 0x32)
	iconOffSm, iconOnSm = makeIcon(scale(16), 0x8a, 0x8a, 0x8a), makeIcon(scale(16), 0x2e, 0x7d, 0x32)
	cursor, _, _ := pLoadCursorW.Call(0, idcArrow)
	bg, _, _ := pGetSysColorBrush.Call(colorWindow)

	wc := wndClassEx{
		lpfnWndProc:   wndProcCB,
		hInstance:     hInstance,
		hIcon:         iconOff,
		hIconSm:       iconOffSm,
		hCursor:       cursor,
		hbrBackground: bg,
		lpszClassName: u16(className),
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	const style = wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox
	r := rect{0, 0, int32(scale(380)), int32(scale(384))}
	pAdjustWindowRect.Call(uintptr(unsafe.Pointer(&r)), style, 0)

	hwndMain, _, _ = pCreateWindowExW.Call(0, ptr(u16(className)), ptr(u16("dpisplit")), style,
		cwUseDefault, cwUseDefault, uintptr(r.right-r.left), uintptr(r.bottom-r.top),
		0, 0, hInstance, 0)

	fStatus := createFont(15, 600, "Segoe UI")
	fButton := createFont(11, 600, "Segoe UI")
	fText := createFont(9, 400, "Segoe UI")
	fMono := createFont(9, 400, "Consolas")

	hStatus = child("STATIC", "", 0, 0, 20, 16, 340, 34, 0, fStatus)
	hDetail = child("STATIC", cfg.describe(), 0, 0, 20, 52, 340, 20, 0, fText)
	hButton = child("BUTTON", "Connect", wsTabStop|bsDefPushButton, 0, 20, 84, 340, 44, idButton, fButton)
	hCheck = child("BUTTON", "Start with Windows (connects automatically)", wsTabStop|bsAutoCheckbox, 0, 20, 140, 340, 24, idCheck, fText)
	hLogLabel = child("STATIC", "Activity", 0, 0, 20, 174, 340, 18, 0, fText)
	hLog = child("EDIT", "", wsVScroll|esMultiline|esReadOnly|esAutoVScroll, wsExClientEdg, 20, 194, 340, 170, 0, fMono)
	enable(hCheck, false) // until we know the current state

	trayAdd()
	setState(stIdle)
	if !trayOnly {
		pShowWindow.Call(hwndMain, swShow)
		pUpdateWindow.Call(hwndMain)
	}
}

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	if msg == msgTaskbarCreated && msgTaskbarCreated != 0 {
		trayAdd() // Explorer restarted: put the icon back
		return 0
	}
	switch msg {
	case wmCommand:
		switch wParam & 0xffff {
		case idButton:
			toggleConnection()
			return 0
		case idCheck:
			on := sendMessage(hCheck, bmGetCheck, 0, 0) == 1
			enable(hCheck, false)
			go func() {
				err := setAutostart(on)
				if err != nil {
					setLastErr(err)
					postMessage(hwndMain, msgAutostart, b2u(!on), 1)
					return
				}
				postMessage(hwndMain, msgAutostart, b2u(on), 0)
			}()
			return 0
		}

	case msgResult:
		if wParam == 1 {
			setState(stConnected)
			addLog("Connected  (" + cfg.describe() + ")")
		} else {
			setState(stIdle)
			if err := takeLastErr(); err != nil {
				addLog("ERROR   " + err.Error())
				what := "Could not connect"
				if lParam == 2 {
					what = "Disconnected because of an error"
				}
				showFromTray()
				messageBox(hwndMain, what+":\n\n"+err.Error(), "dpisplit", mbIconError)
			} else if lParam == 0 {
				addLog("Disconnected")
			}
		}
		return 0

	case msgAutostart:
		sendMessage(hCheck, bmSetCheck, wParam, 0)
		enable(hCheck, true)
		if lParam == 1 {
			if err := takeLastErr(); err != nil {
				messageBox(hwndMain, "Could not change the startup setting:\n\n"+err.Error(), "dpisplit", mbIconError)
			}
		}
		return 0

	case msgLog:
		flushLog()
		return 0

	case wmCtlColorStatic:
		hdc := wParam
		bg, _, _ := pGetSysColor.Call(colorWindow)
		pSetBkColor.Call(hdc, bg)
		switch lParam {
		case hStatus:
			pSetTextColor.Call(hdc, statusColor())
		case hDetail, hLogLabel:
			c, _, _ := pGetSysColor.Call(colorGrayText)
			pSetTextColor.Call(hdc, c)
		}
		brush, _, _ := pGetSysColorBrush.Call(colorWindow)
		return brush

	case wmClose: // X button: keep running in the tray
		hideToTray()
		return 0

	case msgTray:
		trayEvent(lParam)
		return 0

	case wmDestroy:
		trayRemove()
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func toggleConnection() {
	switch state {
	case stIdle:
		connect()
	case stConnected:
		disconnect()
	}
}

// exitApp disconnects, removes the tray icon and quits.
func exitApp() {
	eng.Stop()
	trayRemove()
	pDestroyWindow.Call(hwndMain)
}

func connect() {
	setState(stConnecting)
	go func() {
		err := eng.Start(cfg)
		if err != nil {
			setLastErr(err)
			postMessage(hwndMain, msgResult, 0, 1)
			return
		}
		postMessage(hwndMain, msgResult, 1, 0)
	}()
}

func disconnect() {
	setState(stDisconnecting)
	go func() {
		eng.Stop()
		postMessage(hwndMain, msgResult, 0, 0)
	}()
}

func setState(s int) {
	state = s
	icon, iconSm := iconOff, iconOffSm
	switch s {
	case stIdle:
		setText(hStatus, "●  Disconnected")
		setText(hButton, "Connect")
		enable(hButton, true)
	case stConnecting:
		setText(hStatus, "●  Connecting…")
		enable(hButton, false)
	case stConnected:
		setText(hStatus, "●  Connected")
		setText(hButton, "Disconnect")
		enable(hButton, true)
		icon, iconSm = iconOn, iconOnSm
	case stDisconnecting:
		setText(hStatus, "●  Disconnecting…")
		enable(hButton, false)
	}
	sendMessage(hwndMain, wmSetIcon, 1, icon)   // ICON_BIG
	sendMessage(hwndMain, wmSetIcon, 0, iconSm) // ICON_SMALL
	title := "dpisplit"
	if s == stConnected {
		title = "dpisplit - connected"
	}
	setText(hwndMain, title)
	pInvalidateRect.Call(hStatus, 0, 1)
	trayUpdate()
}

func statusColor() uintptr {
	rgb := func(r, g, b uint32) uintptr { return uintptr(r | g<<8 | b<<16) }
	switch state {
	case stConnected:
		return rgb(0x2e, 0x7d, 0x32)
	case stConnecting, stDisconnecting:
		return rgb(0xc8, 0x78, 0x00)
	}
	return rgb(0x6e, 0x6e, 0x6e)
}

// ---- activity log ----

func addLog(line string) {
	logMu.Lock()
	logPending = append(logPending, time.Now().Format("15:04:05")+"  "+line)
	logMu.Unlock()
	postMessage(hwndMain, msgLog, 0, 0)
}

func flushLog() {
	logMu.Lock()
	lines := logPending
	logPending = nil
	logMu.Unlock()
	if len(lines) == 0 {
		return
	}
	if n, _, _ := pGetWindowTextLengthW.Call(hLog); n > 60000 {
		setText(hLog, "")
	}
	n, _, _ := pGetWindowTextLengthW.Call(hLog)
	sendMessage(hLog, emSetSel, n, n)
	sendMessage(hLog, emReplaceSel, 0, ptr(u16(strings.Join(lines, "\r\n")+"\r\n")))
}

func setLastErr(err error) {
	errMu.Lock()
	lastErr = err
	errMu.Unlock()
}

func takeLastErr() error {
	errMu.Lock()
	defer errMu.Unlock()
	err := lastErr
	lastErr = nil
	return err
}

func b2u(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

// ---- Start with Windows (Task Scheduler) ----
//
// A logon task with "highest privileges" starts the app elevated without a
// UAC prompt. Runs on battery, never times out, one instance only.

func autostartEnabled() bool {
	_, err := runHidden(sysDLL("schtasks.exe"), "/Query", "/TN", taskName)
	return err == nil
}

func setAutostart(on bool) error {
	if !on {
		out, err := runHidden(sysDLL("schtasks.exe"), "/Delete", "/TN", taskName, "/F")
		if err != nil && autostartEnabled() {
			return fmt.Errorf("%v\n%s", err, out)
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	// Keep any options the app was started with (e.g. -fake-ttl 4).
	args := []string{"-autostart"}
	flag.Visit(func(f *flag.Flag) {
		if f.Name != "autostart" {
			args = append(args, syscall.EscapeArg("-"+f.Name+"="+f.Value.String()))
		}
	})

	esc := func(s string) string {
		var b strings.Builder
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	task := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>dpisplit - start at logon and connect</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + esc(u.Username) + `</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>` + esc(u.Username) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + esc(exe) + `</Command><Arguments>` + esc(strings.Join(args, " ")) + `</Arguments><WorkingDirectory>` + esc(filepath.Dir(exe)) + `</WorkingDirectory></Exec></Actions>
</Task>`

	// schtasks wants UTF-16LE with a BOM.
	enc := utf16.Encode([]rune(task))
	buf := make([]byte, 2+2*len(enc))
	buf[0], buf[1] = 0xFF, 0xFE
	for i, c := range enc {
		buf[2+2*i], buf[3+2*i] = byte(c), byte(c>>8)
	}
	f, err := os.CreateTemp("", "dpisplit-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return err
	}
	f.Close()

	out, err := runHidden(sysDLL("schtasks.exe"), "/Create", "/TN", taskName, "/XML", f.Name(), "/F")
	if err != nil {
		return fmt.Errorf("%v\n%s", err, out)
	}
	return nil
}

func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil && s == "" {
		return s, err
	}
	if err != nil {
		return s, errors.New(s)
	}
	return s, nil
}
