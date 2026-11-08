// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

// Structures of the Windows API as they are laid out on 64 bit (x64 and
// ARM64). They have no build tag, so a test under Linux checks their size
// against the Windows headers: a wrong size fails silently on Windows (no
// icon, no messages). Same approach as the go-tray template of the kit.
package main

// notifyIconData is NOTIFYICONDATAW (shellapi.h), 976 bytes on 64 bit.
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
	uVersion         uint32 // union with uTimeout
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         guid
	hBalloonIcon     uintptr
}

type guid struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 [8]byte
}

// wndClassEx is WNDCLASSEXW, 80 bytes on 64 bit.
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

// winMsg is MSG, 48 bytes on 64 bit.
type winMsg struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	ptX      int32
	ptY      int32
	lPrivate uint32
}

// point is POINT.
type point struct{ x, y int32 }
