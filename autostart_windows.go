// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

// "Start with Windows": an entry under HKCU\...\Run, for the signed in user
// only, without admin rights. The same place Windows shows under
// Settings > Apps > Startup, where it can be switched off as well.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// autostartCommand is what goes into the Run entry: the path of this exe
// in quotes (paths with spaces), started into the tray without a window.
func autostartCommand() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return `"` + exe + `" ` + flagMinimized, nil
}

// autostartEnabled: there is an entry and it points to this exe. If it
// points to another one (an old copy), it counts as off; switching it on
// writes the right path.
func autostartEnabled() bool {
	want, err := autostartCommand()
	if err != nil {
		return false
	}
	have, err := regString(runKey, appName)
	return err == nil && strings.EqualFold(have, want)
}

func setAutostart(on bool) error {
	var key syscall.Handle
	const keySetValue = 0x0002
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, utf16Ptr(runKey), 0, keySetValue, &key); err != nil {
		return fmt.Errorf("open the Run key: %w", err)
	}
	defer syscall.RegCloseKey(key) // a failed close does not change the value written

	name := utf16Ptr(appName)
	if !on {
		r, _, _ := procRegDeleteValueW.Call(uintptr(key), uintptr(unsafe.Pointer(name)))
		if r != 0 && syscall.Errno(r) != syscall.ERROR_FILE_NOT_FOUND {
			return fmt.Errorf("delete the autostart entry: %w", syscall.Errno(r))
		}
		return nil
	}
	cmd, err := autostartCommand()
	if err != nil {
		return fmt.Errorf("path of the exe: %w", err)
	}
	data := syscall.StringToUTF16(cmd)
	r, _, _ := procRegSetValueExW.Call(uintptr(key), uintptr(unsafe.Pointer(name)), 0, syscall.REG_SZ,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	if r != 0 {
		return fmt.Errorf("write the autostart entry: %w", syscall.Errno(r))
	}
	return nil
}

// regString reads a REG_SZ value under HKEY_CURRENT_USER.
func regString(path, name string) (string, error) {
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, utf16Ptr(path), 0, syscall.KEY_READ, &key); err != nil {
		return "", fmt.Errorf("open registry key: %w", err)
	}
	defer syscall.RegCloseKey(key) // only read: a failed close changes nothing

	n := utf16Ptr(name)
	var typ, size uint32
	if err := syscall.RegQueryValueEx(key, n, nil, &typ, nil, &size); err != nil {
		return "", fmt.Errorf("read registry value %s: %w", name, err)
	}
	if typ != syscall.REG_SZ || size < 2 {
		return "", errors.New("not a text value")
	}
	buf := make([]uint16, size/2)
	if err := syscall.RegQueryValueEx(key, n, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return "", fmt.Errorf("read registry value %s: %w", name, err)
	}
	return syscall.UTF16ToString(buf), nil
}
