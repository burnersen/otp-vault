// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

//go:build !windows

// Stand-ins for other systems: the tray, the private clipboard and
// autostart are Windows only. They exist so the logic and tests build
// under Linux (the CI tests there).
package main

import "log/slog"

type trayHooks struct {
	toggle, show, lock, quit func()
	labels                   func() trayLabels
	sessionLocked            func() bool
	logger                   *slog.Logger
}

type trayLabels struct {
	Show, Lock, Quit, Tooltip string
}

func startTray(trayHooks) {}
func stopTray()           {}

func setClipboardSecret(string) (uint32, error) { return 0, errNoNativeClipboard }
func clearClipboardIf(uint32)                   {}

func autostartEnabled() bool  { return false }
func setAutostart(bool) error { return errNoNativeClipboard } // same meaning: Windows only
