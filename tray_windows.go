// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

// The icon in the notification area, its menu, the Windows session lock and
// the clipboard. An invisible window on its own thread receives everything
// Windows reports; the Wails window runs on the main thread and is reached
// through the hooks. Only syscall, no modules (like the go-tray template).
package main

import (
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	wtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")

	procRegisterClassExW        = user32.NewProc("RegisterClassExW")
	procCreateWindowExW         = user32.NewProc("CreateWindowExW")
	procDestroyWindow           = user32.NewProc("DestroyWindow")
	procDefWindowProcW          = user32.NewProc("DefWindowProcW")
	procGetMessageW             = user32.NewProc("GetMessageW")
	procTranslateMessage        = user32.NewProc("TranslateMessage")
	procDispatchMessageW        = user32.NewProc("DispatchMessageW")
	procPostQuitMessage         = user32.NewProc("PostQuitMessage")
	procPostMessageW            = user32.NewProc("PostMessageW")
	procRegisterWindowMessageW  = user32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu         = user32.NewProc("CreatePopupMenu")
	procAppendMenuW             = user32.NewProc("AppendMenuW")
	procTrackPopupMenu          = user32.NewProc("TrackPopupMenu")
	procDestroyMenu             = user32.NewProc("DestroyMenu")
	procSetMenuDefaultItem      = user32.NewProc("SetMenuDefaultItem")
	procGetCursorPos            = user32.NewProc("GetCursorPos")
	procSetForegroundWindow     = user32.NewProc("SetForegroundWindow")
	procLoadImageW              = user32.NewProc("LoadImageW")
	procLoadIconW               = user32.NewProc("LoadIconW")
	procGetSystemMetrics        = user32.NewProc("GetSystemMetrics")
	procSetTimer                = user32.NewProc("SetTimer")
	procOpenClipboard           = user32.NewProc("OpenClipboard")
	procCloseClipboard          = user32.NewProc("CloseClipboard")
	procEmptyClipboard          = user32.NewProc("EmptyClipboard")
	procSetClipboardData        = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormat = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequenceNum = user32.NewProc("GetClipboardSequenceNumber")

	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalFree       = kernel32.NewProc("GlobalFree")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	procRtlMoveMemory    = kernel32.NewProc("RtlMoveMemory")
	procSleep            = kernel32.NewProc("Sleep")

	procRegSetValueExW  = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW = advapi32.NewProc("RegDeleteValueW")

	procWTSRegisterSessionNotification   = wtsapi32.NewProc("WTSRegisterSessionNotification")
	procWTSUnRegisterSessionNotification = wtsapi32.NewProc("WTSUnRegisterSessionNotification")
)

const (
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmNull             = 0x0000
	wmTimer            = 0x0113
	wmLButtonUp        = 0x0202
	wmRButtonUp        = 0x0205
	wmContextMenu      = 0x007B
	wmWTSSessionChange = 0x02B1
	wmApp              = 0x8000
	trayCallback       = wmApp + 1
	trayIconID         = 1
	wtsSessionLock     = 0x7

	nimAdd     = 0x0
	nimModify  = 0x1
	nimDelete  = 0x2
	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04

	mfString    = 0x0000
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmBottomAlign = 0x0020

	imageIcon      = 1
	lrDefaultColor = 0x0
	smCxSmIcon     = 49
	smCySmIcon     = 50
	idiApplication = 32512
	// wailsIconID: wails build stores the icon as group 3, the window uses it.
	wailsIconID = 3

	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	timerIcon = 1 // adds the icon again whenever it is missing (see checkIcon)

	iconRetry = 2000  // ms, while the icon is missing (Explorer not ready at autostart)
	iconCheck = 30000 // ms, while it is there: Windows may drop it without a word

	menuShow = 1
	menuLock = 2
	menuQuit = 3
)

// trayHooks is how the tray reaches the window and the vault.
type trayHooks struct {
	toggle        func()            // left click: show or hide the window
	show          func()            // menu: open
	lock          func()            // menu or session lock
	quit          func()            // menu: quit
	labels        func() trayLabels // menu texts in the current language
	sessionLocked func() bool       // should a Windows lock lock the vault
	logger        *slog.Logger
}

type trayLabels struct {
	Show, Lock, Quit, Tooltip string
}

type tray struct {
	hooks          trayHooks
	hwnd           uintptr
	icon           uintptr
	taskbarCreated uintptr
	iconAdded      bool
}

var (
	theTray   *tray
	trayReady = make(chan struct{})
	trayMu    sync.Mutex // guards theTray.hwnd for the clipboard
)

// startTray runs the tray on its own locked thread. It returns at once; a
// failure only goes to the log, the window works without the tray.
func startTray(h trayHooks) {
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := runTray(h); err != nil {
			h.logger.Error("tray", "err", err)
		}
	}()
}

// stopTray removes the icon at the end; Windows would leave a ghost icon
// until the mouse moves over it.
func stopTray() {
	trayMu.Lock()
	t := theTray
	trayMu.Unlock()
	if t != nil && t.hwnd != 0 {
		procPostMessageW.Call(t.hwnd, wmClose, 0, 0)
	}
}

func runTray(h trayHooks) error {
	t := &tray{hooks: h}
	className := utf16Ptr("OtpVaultTrayWindow")
	hinst, _, _ := procGetModuleHandleW.Call(0)
	wc := wndClassEx{lpfnWndProc: syscall.NewCallback(trayWndProc), hInstance: hinst, lpszClassName: className}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassEx: %w", err)
	}
	// A normal window that is never shown, not a message-only window: only
	// normal windows get "TaskbarCreated" and session notifications.
	title := utf16Ptr(appName + " tray")
	hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)),
		0, 0, 0, 0, 0, 0, 0, hinst, 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %w", err)
	}
	t.hwnd = hwnd
	trayMu.Lock()
	theTray = t
	trayMu.Unlock()
	close(trayReady)

	tc := utf16Ptr("TaskbarCreated")
	t.taskbarCreated, _, _ = procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tc)))
	const notifyForThisSession = 0
	if r, _, err := procWTSRegisterSessionNotification.Call(hwnd, notifyForThisSession); r == 0 {
		h.logger.Warn("session notifications not available", "err", err)
	}
	t.icon = loadAppIcon()
	t.checkIcon()

	var m winMsg
	for {
		r, _, err := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) == -1 {
			return fmt.Errorf("GetMessage: %w", err)
		}
		if r == 0 {
			return nil
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func trayWndProc(hwnd, msg, wParam, lParam uintptr) (result uintptr) {
	t := theTray
	if t == nil || hwnd != t.hwnd {
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
		return r
	}
	// A panic must not leave this callback: it would end the whole program
	// and take the icon with it.
	defer func() {
		if p := recover(); p != nil {
			t.hooks.logger.Error("tray: panic", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			result = 0
		}
	}()
	switch {
	case msg == trayCallback:
		switch lParam & 0xFFFF {
		case wmLButtonUp:
			t.run("toggle", t.hooks.toggle)
		case wmRButtonUp, wmContextMenu:
			t.showMenu()
		}
		return 0
	case msg == wmWTSSessionChange:
		if wParam == wtsSessionLock && t.hooks.sessionLocked() {
			t.run("lock", t.hooks.lock)
		}
		return 0
	case msg == wmTimer && wParam == timerIcon:
		t.checkIcon()
		return 0
	case msg == wmClose:
		t.removeIcon()
		procWTSUnRegisterSessionNotification.Call(hwnd)
		procDestroyWindow.Call(hwnd)
		return 0
	case msg == wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	case t.taskbarCreated != 0 && msg == t.taskbarCreated:
		t.iconAdded = false // Explorer restarted, every icon is gone
		t.checkIcon()
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

// run calls a hook on its own goroutine. A panic there is logged instead of
// ending the program (a panic in any goroutine ends a Go program).
func (t *tray) run(name string, f func()) {
	go func() {
		defer func() {
			if p := recover(); p != nil {
				t.hooks.logger.Error("tray: panic in "+name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			}
		}()
		f()
	}()
}

// checkIcon makes sure the icon is there: it adds a missing one and asks
// Windows about one it thinks is there. Windows can drop an icon without
// telling the program (Explorer hung, display or DPI change), and the
// TaskbarCreated message may come before Explorer accepts icons again. The
// timer then retries every 2 seconds until it works, later it checks every
// 30 seconds.
func (t *tray) checkIcon() {
	if t.iconAdded {
		nid := t.iconData()
		nid.uFlags = nifTip
		copyUTF16(nid.szTip[:], t.hooks.labels().Tooltip)
		if r, _, _ := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid))); r == 0 {
			t.hooks.logger.Warn("tray icon was gone, adding it again")
			t.iconAdded = false
		}
	}
	t.addIcon()
	every := uintptr(iconCheck)
	if !t.iconAdded {
		every = iconRetry
	}
	procSetTimer.Call(t.hwnd, timerIcon, every, 0) // same id: replaces the previous interval
}

func loadAppIcon() uintptr {
	hinst, _, _ := procGetModuleHandleW.Call(0)
	cx, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	cy, _, _ := procGetSystemMetrics.Call(smCySmIcon)
	if h, _, _ := procLoadImageW.Call(hinst, wailsIconID, imageIcon, cx, cy, lrDefaultColor); h != 0 {
		return h
	}
	h, _, _ := procLoadIconW.Call(0, idiApplication)
	return h
}

func (t *tray) iconData() notifyIconData {
	var nid notifyIconData
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = t.hwnd
	nid.uID = trayIconID
	return nid
}

func (t *tray) addIcon() {
	if t.iconAdded {
		return
	}
	nid := t.iconData()
	nid.uFlags = nifMessage | nifIcon | nifTip
	nid.uCallbackMessage = trayCallback
	nid.hIcon = t.icon
	copyUTF16(nid.szTip[:], t.hooks.labels().Tooltip)
	if r, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid))); r != 0 {
		t.iconAdded = true
		t.hooks.logger.Info("tray icon added")
		return
	}
	// NIM_ADD can time out while Explorer is busy and still add the icon; a
	// second add then fails because it exists. Modify tells the two apart.
	if r, _, _ := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid))); r != 0 {
		t.iconAdded = true
		t.hooks.logger.Info("tray icon was there already")
	}
}

func (t *tray) removeIcon() {
	if !t.iconAdded {
		return
	}
	nid := t.iconData()
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	t.iconAdded = false
}

func (t *tray) showMenu() {
	l := t.hooks.labels()
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	add := func(id uintptr, text string) {
		procAppendMenuW.Call(menu, mfString, id, uintptr(unsafe.Pointer(utf16Ptr(text))))
	}
	add(menuShow, l.Show)
	add(menuLock, l.Lock)
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	add(menuQuit, l.Quit)
	procSetMenuDefaultItem.Call(menu, menuShow, 0)
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// Without SetForegroundWindow the menu does not close on a click beside it.
	procSetForegroundWindow.Call(t.hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmRightButton|tpmReturnCmd|tpmBottomAlign,
		uintptr(pt.x), uintptr(pt.y), 0, t.hwnd, 0)
	procPostMessageW.Call(t.hwnd, wmNull, 0, 0)
	switch cmd {
	case menuShow:
		t.run("show", t.hooks.show)
	case menuLock:
		t.run("lock", t.hooks.lock)
	case menuQuit:
		t.run("quit", t.hooks.quit)
	}
}

func utf16Ptr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("") // ignore: empty text has no NUL
	}
	return p
}

func copyUTF16(dst []uint16, s string) {
	u := syscall.StringToUTF16(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

// ---- clipboard ------------------------------------------------------------

// setClipboardSecret puts a code on the clipboard and marks it as private:
// Windows keeps it out of the clipboard history (Win+V) and the cloud
// clipboard. It returns the clipboard's sequence number, so clearing later
// only happens if nothing else was copied meanwhile.
func setClipboardSecret(text string) (uint32, error) {
	select {
	case <-trayReady:
	default:
		return 0, errNoNativeClipboard
	}
	trayMu.Lock()
	hwnd := theTray.hwnd
	trayMu.Unlock()
	if err := openClipboard(hwnd); err != nil {
		return 0, err
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	data := syscall.StringToUTF16(text)
	if err := setClipboardBytes(cfUnicodeText, unsafe.Pointer(&data[0]), uintptr(len(data)*2)); err != nil {
		return 0, err
	}
	zero := uint32(0)
	for _, name := range []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
		f, _, _ := procRegisterClipboardFormat.Call(uintptr(unsafe.Pointer(utf16Ptr(name))))
		if f != 0 {
			setClipboardBytes(f, unsafe.Pointer(&zero), 4) // best effort: the code is copied either way
		}
	}
	seq, _, _ := procGetClipboardSequenceNum.Call()
	return uint32(seq), nil
}

// clearClipboardIf empties the clipboard if it still holds what we put there.
func clearClipboardIf(seq uint32) {
	select {
	case <-trayReady:
	default:
		return
	}
	if now, _, _ := procGetClipboardSequenceNum.Call(); uint32(now) != seq {
		return
	}
	trayMu.Lock()
	hwnd := theTray.hwnd
	trayMu.Unlock()
	if openClipboard(hwnd) == nil {
		procEmptyClipboard.Call()
		procCloseClipboard.Call()
	}
}

// openClipboard retries: another program may hold the clipboard briefly.
func openClipboard(hwnd uintptr) error {
	var err error
	for i := 0; i < 10; i++ {
		var r uintptr
		if r, _, err = procOpenClipboard.Call(hwnd); r != 0 {
			return nil
		}
		procSleep.Call(20)
	}
	return fmt.Errorf("OpenClipboard: %w", err)
}

func setClipboardBytes(format uintptr, src unsafe.Pointer, n uintptr) error {
	h, _, err := procGlobalAlloc.Call(gmemMoveable, n)
	if h == 0 {
		return fmt.Errorf("GlobalAlloc: %w", err)
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("GlobalLock: %w", err)
	}
	procRtlMoveMemory.Call(p, uintptr(src), n)
	procGlobalUnlock.Call(h)
	if r, _, err := procSetClipboardData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("SetClipboardData: %w", err)
	}
	return nil // the clipboard owns the memory now
}
