// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"testing"
	"unsafe"
)

func TestWin32StructSizes(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64 bit only")
	}
	cases := []struct {
		name      string
		got, want uintptr
	}{
		{"NOTIFYICONDATAW", unsafe.Sizeof(notifyIconData{}), 976},
		{"WNDCLASSEXW", unsafe.Sizeof(wndClassEx{}), 80},
		{"MSG", unsafe.Sizeof(winMsg{}), 48},
		{"POINT", unsafe.Sizeof(point{}), 8},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %d bytes, Windows expects %d", c.name, c.got, c.want)
		}
	}
	var n notifyIconData
	if off := unsafe.Offsetof(n.szInfo); off != 304 {
		t.Errorf("szInfo at %d, expected 304", off)
	}
	if off := unsafe.Offsetof(n.hBalloonIcon); off != 968 {
		t.Errorf("hBalloonIcon at %d, expected 968", off)
	}
}
