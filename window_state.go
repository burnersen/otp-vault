// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"time"
)

// The window remembers its size: the page reports every resize, Go reads
// the size from Windows and keeps it in window.json next to the vault. The
// next start opens the window with it. Sizes are in Wails' units (pixels at
// 100 % scaling), the same as Width and Height in main.go.
const (
	windowStateName = "window.json"
	defaultWidth    = 980
	defaultHeight   = 700
	minWidth        = 420
	minHeight       = 480
)

type windowState struct {
	Width     int  `json:"width"`
	Height    int  `json:"height"`
	Maximised bool `json:"maximised"`
}

// loadWindowState never fails: a missing or broken file gives the default.
func loadWindowState(path string) windowState {
	ws := windowState{Width: defaultWidth, Height: defaultHeight}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ws
	}
	var saved windowState
	if json.Unmarshal(raw, &saved) != nil {
		return ws
	}
	return saved.fit(0, 0)
}

func saveWindowState(path string, ws windowState) error {
	raw, err := json.MarshalIndent(ws, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o600)
}

// fit keeps the size between the window's minimum and the screen's work
// area (maxW, maxH; 0 means unknown). A size from a larger monitor that is
// no longer there would otherwise open a window beyond the screen.
func (ws windowState) fit(maxW, maxH int) windowState {
	if ws.Width <= 0 || ws.Height <= 0 {
		ws.Width, ws.Height = defaultWidth, defaultHeight
	}
	ws.Width = clampInt(ws.Width, minWidth, maxW)
	ws.Height = clampInt(ws.Height, minHeight, maxH)
	return ws
}

func clampInt(v, lo, hi int) int {
	if hi > 0 && v > hi {
		v = hi
	}
	if v < lo {
		v = lo
	}
	return v
}

// ---- restart after a crash ------------------------------------------------

// exitNoRestart is the exit code for a failure the user was already told
// about (showFatal): starting again would only show the same message.
const exitNoRestart = 3

// restartPolicy decides whether the watcher starts the window process again
// after it ended. A clean end (Quit, second start) is never restarted, nor a
// process that died right at start (it would only die again), nor one that
// keeps dying.
type restartPolicy struct {
	minRun   time.Duration // a shorter run counts as a failed start
	window   time.Duration
	maxTimes int // restarts allowed within window
	restarts []time.Time
}

func newRestartPolicy() *restartPolicy {
	return &restartPolicy{minRun: 15 * time.Second, window: time.Hour, maxTimes: 5}
}

func (p *restartPolicy) allow(code int, ran time.Duration, now time.Time) (bool, string) {
	switch {
	case code == 0:
		return false, "ended normally"
	case code == exitNoRestart:
		return false, "start failed, the user was told"
	case ran < p.minRun:
		return false, "ended right after start"
	}
	recent := p.restarts[:0]
	for _, t := range p.restarts {
		if now.Sub(t) < p.window {
			recent = append(recent, t)
		}
	}
	p.restarts = recent
	if len(p.restarts) >= p.maxTimes {
		return false, "ended too often within an hour"
	}
	p.restarts = append(p.restarts, now)
	return true, ""
}
