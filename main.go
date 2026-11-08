// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

// otp-vault keeps two-factor codes (TOTP, HOTP, Steam) in an encrypted
// vault on Windows: a window with the codes, an icon in the tray, import
// from nearly every authenticator app, export and printed recovery sheets.
//
// Where things are (template go-wails of dev-starterkit, tray part from
// go-tray):
//
//	main.go          start of the window; a failed start shows a message box
//	app.go           what the page may call: lock, entries, codes, clipboard
//	app_transfer.go  what the page may call: import and export
//	otp.go           entries and code generation (RFC 4226, 6238, Steam)
//	otpauth.go       otpauth:// links, website guess for icons
//	vault.go         the encrypted file (Argon2id, XChaCha20-Poly1305)
//	store.go         the open vault in memory, every change saved at once
//	importers.go     Aegis, 2FAS, andOTP, Bitwarden, CSV, text, backups
//	migration.go     Google Authenticator export links (protobuf by hand)
//	exporters.go     backup, links, CSV, Aegis JSON
//	pdf.go           A4 recovery sheets with QR codes, QR as SVG
//	favicon.go       icons from the service's own website, on request
//	settings.go      the switches of the settings page (JSON)
//	tray_windows.go  tray icon, menu, Windows lock, private clipboard
//	internal/qr/     QR encoder (copy of rsc.io/qr, BSD)
//	errors.go logging.go paths.go files.go   same as the kit templates
//	frontend/        plain HTML, CSS and JavaScript, no npm, no build step
package main

import (
	"embed"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"unsafe"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// singleInstanceID must never change, or a new version would not find an
// older one that is still running.
const singleInstanceID = "otp-vault-6f1d2c7e-3b9a-4f58-9e21-8c4b7a0d5e13"

func main() {
	minimized, selfTest := false, false
	for _, arg := range os.Args[1:] {
		switch arg {
		case flagMinimized:
			minimized = true
		case flagSelfTest:
			selfTest = true
		}
	}
	paths, err := defaultPaths()
	if err != nil {
		showFatal("could not find its folders", err)
		return
	}
	logger := slog.New(slog.DiscardHandler)
	if l, closeLog, err := openLog(paths.LogFile, slog.LevelInfo); err == nil {
		logger = l
		defer closeLog()
	}
	logger.Info("start", "version", version, "minimized", minimized, "selftest", selfTest)

	app := NewApp(paths, logger)
	app.selfTest = selfTest
	app.hidden = minimized
	if !selfTest {
		startTray(app.trayHooks())
	}
	single := &options.SingleInstanceLock{UniqueId: singleInstanceID, OnSecondInstanceLaunch: app.onSecondInstance}
	if selfTest {
		single = nil // the CI may start it while nothing else runs; keep it independent
	}
	err = wails.Run(&options.App{
		Title:     appName,
		Width:     980,
		Height:    700,
		MinWidth:  420,
		MinHeight: 480,
		// Must match --bg in style.css, or the window flashes white.
		BackgroundColour:   &options.RGBA{R: 243, G: 245, B: 249, A: 255},
		AssetServer:        &assetserver.Options{Assets: assets},
		StartHidden:        minimized,
		OnStartup:          app.startup,
		OnBeforeClose:      app.beforeClose,
		OnShutdown:         app.shutdown,
		SingleInstanceLock: single,
		DragAndDrop:        &options.DragAndDrop{DisableWebViewDrop: false},
		Windows: &windows.Options{
			Theme:    windows.SystemDefault,
			Messages: windowMessages(),
		},
		Bind: []any{app},
	})
	if err != nil {
		logger.Error("window failed", "err", err)
		showFatal("could not open its window", err)
		stopTray()
		os.Exit(1)
	}
	stopTray()
}

// windowMessages replaces Wails' wording for a crash of the Windows web view,
// which reads as if the program itself had crashed. The other messages (for
// example the WebView2 download) stay as Wails has them.
func windowMessages() *windows.Messages {
	m := windows.DefaultMessages()
	m.WebView2ProcessCrash = "The Windows web view (WebView2) stopped. " + appName + " itself did not crash, " +
		"and your vault was not changed. Please start it again. If this keeps happening, repair the web view: " +
		"Settings > Apps > Installed apps > Microsoft Edge WebView2 Runtime > Modify > Repair."
	return m
}

// showFatal tells the user why the window cannot start. A window program has
// no console: log.Fatal or a panic here would end it without a word.
func showFatal(what string, err error) {
	text := fmt.Sprintf("%s %s.\n\n%v\n\nPlease report this at https://github.com/burnersen/%s/issues", appName, what, err, appName)
	title, _ := syscall.UTF16PtrFromString(appName) // ignore: constant text without NUL
	body, perr := syscall.UTF16PtrFromString(text)
	if perr != nil {
		body, _ = syscall.UTF16PtrFromString(appName + " " + what + ".") // ignore: constant text
	}
	const mbIconError = 0x10
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0,
		uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), mbIconError)
}
