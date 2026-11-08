// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// errNoNativeClipboard: the Windows part is not there (other system, or the
// tray thread has not started yet); the caller falls back.
var errNoNativeClipboard = errors.New("only available on Windows")

// Settings are the switches of the settings page. They hold nothing
// secret and live next to the vault as plain JSON (the program writes them,
// the page edits them). An invalid file means: warn and use the defaults.
type Settings struct {
	Language          string `json:"language"`          // "en" or "de"
	Theme             string `json:"theme"`             // "system", "light", "dark"
	AutoLockMinutes   int    `json:"autoLockMinutes"`   // 0: never
	ClipboardSeconds  int    `json:"clipboardSeconds"`  // 0: never clear
	LockOnWindowsLock bool   `json:"lockOnWindowsLock"` // lock when Windows is locked
	LockOnHide        bool   `json:"lockOnHide"`        // lock when the window goes to the tray
	CloseToTray       bool   `json:"closeToTray"`       // X hides the window instead of quitting
	ShowNext          bool   `json:"showNext"`          // show the next code too
	HideCodes         bool   `json:"hideCodes"`         // codes blurred until the mouse is over them
	HideAfterCopy     bool   `json:"hideAfterCopy"`     // hide the window after a copy
}

func defaultSettings() Settings {
	return Settings{
		Language: "en", Theme: "system", AutoLockMinutes: 5, ClipboardSeconds: 30,
		LockOnWindowsLock: true, CloseToTray: true, ShowNext: true,
	}
}

// clean puts every value back into its range; it returns what it changed.
func (s *Settings) clean() []string {
	var fixed []string
	d := defaultSettings()
	if s.Language != "en" && s.Language != "de" {
		fixed = append(fixed, "language")
		s.Language = d.Language
	}
	if s.Theme != "system" && s.Theme != "light" && s.Theme != "dark" {
		fixed = append(fixed, "theme")
		s.Theme = d.Theme
	}
	if s.AutoLockMinutes < 0 || s.AutoLockMinutes > 240 {
		fixed = append(fixed, "autoLockMinutes")
		s.AutoLockMinutes = d.AutoLockMinutes
	}
	if s.ClipboardSeconds < 0 || s.ClipboardSeconds > 600 {
		fixed = append(fixed, "clipboardSeconds")
		s.ClipboardSeconds = d.ClipboardSeconds
	}
	return fixed
}

// loadSettings never fails: a missing file gives the defaults, a broken one
// the defaults plus a warning for the log and the page.
func loadSettings(path string) (Settings, string) {
	s := defaultSettings()
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, ""
	}
	if err != nil {
		return s, fmt.Sprintf("settings not read (%v), using defaults", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return defaultSettings(), fmt.Sprintf("settings file is damaged (%v), using defaults", err)
	}
	if fixed := s.clean(); len(fixed) > 0 {
		return s, fmt.Sprintf("invalid settings %v replaced by defaults", fixed)
	}
	return s, ""
}

func saveSettings(path string, s Settings) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return fileError(err, "save the settings in", path)
	}
	return nil
}
