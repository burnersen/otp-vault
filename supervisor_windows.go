// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

// The watcher: a started otp-vault.exe runs the window in a second process
// of itself and waits for it. If that process dies (a crash of the WebView2
// browser process makes Wails end the whole program, a Go panic ends it as
// well), the watcher starts it again in the tray, so the icon comes back by
// itself. The watcher has no window and no tray icon; it only waits.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"time"
	"unsafe"
)

// supervisedEnv marks the window process, so it does not start a watcher of
// its own.
const supervisedEnv = "OTP_VAULT_SUPERVISED"

var (
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procGetDpiForSystem       = user32.NewProc("GetDpiForSystem")
)

// isSupervised: this process is the window process started by a watcher.
func isSupervised() bool { return os.Getenv(supervisedEnv) == "1" }

// supervise runs the window process until it ends normally and returns the
// exit code for the watcher. It returns ok=false if the window process could
// not be started at all; the caller then runs the window itself.
func supervise(paths appPaths, args []string) (code int, ok bool) {
	exe, err := os.Executable()
	if err != nil {
		logOnce(paths, slog.LevelWarn, "watcher: own path unknown, running without it", "err", err)
		return 0, false
	}
	policy := newRestartPolicy()
	for {
		cmd := exec.Command(exe, args...)
		cmd.Env = append(os.Environ(), supervisedEnv+"=1")
		started := time.Now()
		if err := cmd.Start(); err != nil {
			logOnce(paths, slog.LevelWarn, "watcher: window process not started, running without it", "err", err)
			return 0, false
		}
		err := cmd.Wait()
		code = 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else if err != nil {
			code = 1
		}
		ran := time.Since(started)
		if code == 0 {
			return 0, true
		}
		if shuttingDown() {
			return code, true
		}
		restart, why := policy.allow(code, ran, time.Now())
		if !restart {
			logOnce(paths, slog.LevelError, "window process ended, not restarted",
				"code", fmt.Sprintf("%#x", uint32(code)), "ran", ran.Round(time.Second).String(), "why", why)
			return code, true
		}
		logOnce(paths, slog.LevelError, "window process ended unexpectedly, restarting in the tray",
			"code", fmt.Sprintf("%#x", uint32(code)), "ran", ran.Round(time.Second).String(),
			"details", filepath.Join(filepath.Dir(paths.LogFile), crashLogName))
		if !slices.Contains(args, flagMinimized) {
			args = append(slices.Clone(args), flagMinimized)
		}
		time.Sleep(time.Second) // let Windows remove the old tray icon and the single instance lock
	}
}

// logOnce writes one line to the log and closes it again: the watcher runs
// for days, an open log file would keep the window process from rotating it.
func logOnce(paths appPaths, level slog.Level, msg string, args ...any) {
	l, closeLog, err := openLog(paths.LogFile, slog.LevelInfo)
	if err != nil {
		return
	}
	l.Log(context.Background(), level, msg, append(args, "process", "watcher")...)
	_ = closeLog() // ignore: nothing left to tell anyone
}

const crashLogName = "crash.log"

// keepCrashOutput sends what Go prints when the process dies (a panic in
// any goroutine, a fatal error) to logs/crash.log. A window program has no
// console, without this the reason would be lost.
func keepCrashOutput(paths appPaths, logger *slog.Logger) {
	path := filepath.Join(filepath.Dir(paths.LogFile), crashLogName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logger.Warn("crash log not opened", "err", err)
		return
	}
	fmt.Fprintf(f, "---- %s start %s\n", time.Now().Format(time.RFC3339), version)
	if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
		logger.Warn("crash log not set", "err", err)
	}
	f.Close() // SetCrashOutput keeps its own copy of the handle
}

// shuttingDown: Windows is shutting down or logging off; nothing restarts.
func shuttingDown() bool {
	const smShuttingDown = 0x2000
	r, _, _ := procGetSystemMetrics.Call(smShuttingDown)
	return r != 0
}

// workArea is the size of the primary screen without the taskbar, in Wails'
// units (pixels at 100 % scaling). 0, 0 if Windows does not say.
func workArea() (int, int) {
	const spiGetWorkArea = 0x0030
	var r struct{ left, top, right, bottom int32 }
	if ok, _, _ := procSystemParametersInfoW.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&r)), 0); ok == 0 {
		return 0, 0
	}
	dpi := uintptr(96)
	if procGetDpiForSystem.Find() == nil {
		if d, _, _ := procGetDpiForSystem.Call(); d != 0 {
			dpi = d
		}
	}
	w := int(r.right-r.left) * 96 / int(dpi)
	h := int(r.bottom-r.top) * 96 / int(dpi)
	return w, h
}
