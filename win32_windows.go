//go:build windows && !cli

package main

import (
	"math"
	"os"
	"syscall"
	"unsafe"
)

// Just enough Win32 for one small window. Standard library only.

var (
	user32   = syscall.NewLazyDLL(sysDLL("user32.dll"))
	gdi32    = syscall.NewLazyDLL(sysDLL("gdi32.dll"))
	kernel32 = syscall.NewLazyDLL(sysDLL("kernel32.dll"))
	shell32  = syscall.NewLazyDLL(sysDLL("shell32.dll"))

	pRegisterClassExW     = user32.NewProc("RegisterClassExW")
	pCreateWindowExW      = user32.NewProc("CreateWindowExW")
	pDefWindowProcW       = user32.NewProc("DefWindowProcW")
	pDestroyWindow        = user32.NewProc("DestroyWindow")
	pGetMessageW          = user32.NewProc("GetMessageW")
	pIsDialogMessageW     = user32.NewProc("IsDialogMessageW")
	pTranslateMessage     = user32.NewProc("TranslateMessage")
	pDispatchMessageW     = user32.NewProc("DispatchMessageW")
	pPostMessageW         = user32.NewProc("PostMessageW")
	pSendMessageW         = user32.NewProc("SendMessageW")
	pPostQuitMessage      = user32.NewProc("PostQuitMessage")
	pShowWindow           = user32.NewProc("ShowWindow")
	pUpdateWindow         = user32.NewProc("UpdateWindow")
	pSetWindowTextW       = user32.NewProc("SetWindowTextW")
	pGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	pEnableWindow         = user32.NewProc("EnableWindow")
	pInvalidateRect       = user32.NewProc("InvalidateRect")
	pLoadCursorW          = user32.NewProc("LoadCursorW")
	pMessageBoxW          = user32.NewProc("MessageBoxW")
	pAdjustWindowRect     = user32.NewProc("AdjustWindowRect")
	pFindWindowW          = user32.NewProc("FindWindowW")
	pSetForegroundWindow  = user32.NewProc("SetForegroundWindow")
	pGetSysColor          = user32.NewProc("GetSysColor")
	pGetSysColorBrush     = user32.NewProc("GetSysColorBrush")
	pCreateIconIndirect   = user32.NewProc("CreateIconIndirect")
	pSetProcessDPIAware   = user32.NewProc("SetProcessDPIAware")
	pSetDpiAwarenessCtx   = user32.NewProc("SetProcessDpiAwarenessContext")
	pGetDpiForSystem      = user32.NewProc("GetDpiForSystem")

	pCreateFontW      = gdi32.NewProc("CreateFontW")
	pSetTextColor     = gdi32.NewProc("SetTextColor")
	pSetBkColor       = gdi32.NewProc("SetBkColor")
	pCreateDIBSection = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap     = gdi32.NewProc("CreateBitmap")
	pGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	pCreateActCtxW    = kernel32.NewProc("CreateActCtxW")
	pActivateActCtx   = kernel32.NewProc("ActivateActCtx")
)

const (
	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsChild       = 0x40000000
	wsVisible     = 0x10000000
	wsTabStop     = 0x00010000
	wsVScroll     = 0x00200000
	wsExClientEdg = 0x00000200

	bsDefPushButton = 0x1
	bsAutoCheckbox  = 0x3
	esMultiline     = 0x4
	esAutoVScroll   = 0x40
	esReadOnly      = 0x800

	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmSetIcon          = 0x0080
	wmSetFont          = 0x0030
	wmCommand          = 0x0111
	wmCtlColorStatic   = 0x0138
	wmApp              = 0x8000
	emSetSel           = 0x00B1
	emReplaceSel       = 0x00C2
	bmGetCheck         = 0x00F0
	bmSetCheck         = 0x00F1
	swShow             = 5
	swShowMinNoActive  = 7
	swRestore          = 9
	colorWindow        = 5
	colorGrayText      = 17
	cwUseDefault       = 0x80000000
	mbOK               = 0x0
	mbIconError        = 0x10
	mbIconWarning      = 0x30
	mbIconInformation  = 0x40
	idcArrow           = 32512
	errorAlreadyExists = 183
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type msgT struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
	private uint32
}

type rect struct{ left, top, right, bottom int32 }

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func ptr(p *uint16) uintptr { return uintptr(unsafe.Pointer(p)) }

func sendMessage(h, msg, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(h, msg, w, l)
	return r
}

func postMessage(h, msg, w, l uintptr) {
	pPostMessageW.Call(h, msg, w, l)
}

func setText(h uintptr, s string) { pSetWindowTextW.Call(h, ptr(u16(s))) }

func enable(h uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pEnableWindow.Call(h, v)
}

func messageBox(owner uintptr, text, caption string, flags uintptr) {
	pMessageBoxW.Call(owner, ptr(u16(text)), ptr(u16(caption)), flags)
}

func createFont(points int, weight int, face string) uintptr {
	h := -(points * dpi / 72)
	r, _, _ := pCreateFontW.Call(uintptr(h), 0, 0, 0, uintptr(weight), 0, 0, 0,
		1 /*DEFAULT_CHARSET*/, 0, 0, 5 /*CLEARTYPE_QUALITY*/, 0, ptr(u16(face)))
	return r
}

func child(class, text string, style, exStyle uintptr, x, y, w, h int, id uintptr, font uintptr) uintptr {
	hwnd, _, _ := pCreateWindowExW.Call(exStyle, ptr(u16(class)), ptr(u16(text)),
		wsChild|wsVisible|style, uintptr(scale(x)), uintptr(scale(y)), uintptr(scale(w)), uintptr(scale(h)),
		hwndMain, id, hInstance, 0)
	sendMessage(hwnd, wmSetFont, font, 1)
	return hwnd
}

var dpi = 96

func scale(v int) int { return v * dpi / 96 }

func setupDPI() {
	if pSetDpiAwarenessCtx.Find() == nil {
		pSetDpiAwarenessCtx.Call(^uintptr(1)) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE (-2)
	} else if pSetProcessDPIAware.Find() == nil {
		pSetProcessDPIAware.Call()
	}
	if pGetDpiForSystem.Find() == nil {
		if d, _, _ := pGetDpiForSystem.Call(); d >= 96 {
			dpi = int(d)
		}
	}
}

// enableVisualStyles activates Common Controls v6 (modern-looking buttons and
// checkboxes) through an activation context, since a Go binary has no
// embedded manifest.
func enableVisualStyles() {
	const manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency>
</assembly>`
	f, err := os.CreateTemp("", "dpisplit-*.manifest")
	if err != nil {
		return
	}
	name := f.Name()
	f.WriteString(manifest)
	f.Close()
	defer os.Remove(name)

	type actCtx struct {
		cbSize                 uint32
		dwFlags                uint32
		lpSource               *uint16
		wProcessorArchitecture uint16
		wLangID                uint16
		lpAssemblyDirectory    *uint16
		lpResourceName         *uint16
		lpApplicationName      *uint16
		hModule                uintptr
	}
	ac := actCtx{lpSource: u16(name)}
	ac.cbSize = uint32(unsafe.Sizeof(ac))
	h, _, _ := pCreateActCtxW.Call(uintptr(unsafe.Pointer(&ac)))
	if h == ^uintptr(0) {
		return
	}
	var cookie uintptr
	pActivateActCtx.Call(h, uintptr(unsafe.Pointer(&cookie)))
	// Load comctl32 v6 while the context is active (SxS-redirected, not from PATH).
	syscall.NewLazyDLL("comctl32.dll").NewProc("InitCommonControls").Call()
}

// makeIcon draws the app icon: a circle cut by a diagonal gap (the "split"),
// antialiased, in the given RGB color.
func makeIcon(size int, r, g, b byte) uintptr {
	type bmiHeader struct {
		size          uint32
		width, height int32
		planes, bits  uint16
		compression   uint32
		sizeImage     uint32
		xppm, yppm    int32
		clrUsed       uint32
		clrImportant  uint32
	}
	hdr := bmiHeader{width: int32(size), height: -int32(size), planes: 1, bits: 32}
	hdr.size = uint32(unsafe.Sizeof(hdr))
	var bits unsafe.Pointer
	hbmColor, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&hdr)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hbmColor == 0 || bits == nil {
		return 0
	}
	px := unsafe.Slice((*byte)(bits), size*size*4)

	c := float64(size) / 2
	rad := c - 0.5
	gap := float64(size) / 14
	const ss = 4 // 4x4 supersampling
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			cover := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					fx := float64(x) + (float64(sx)+0.5)/ss - c
					fy := float64(y) + (float64(sy)+0.5)/ss - c
					in := fx*fx+fy*fy <= rad*rad
					onGap := math.Abs(fx+fy)/math.Sqrt2 < gap
					if in && !onGap {
						cover++
					}
				}
			}
			a := cover * 255 / (ss * ss)
			i := (y*size + x) * 4
			// premultiplied BGRA
			px[i+0] = byte(int(b) * a / 255)
			px[i+1] = byte(int(g) * a / 255)
			px[i+2] = byte(int(r) * a / 255)
			px[i+3] = byte(a)
		}
	}
	hbmMask, _, _ := pCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, 0)
	type iconInfo struct {
		fIcon    int32
		xHotspot uint32
		yHotspot uint32
		hbmMask  uintptr
		hbmColor uintptr
	}
	ii := iconInfo{fIcon: 1, hbmMask: hbmMask, hbmColor: hbmColor}
	h, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	return h
}
