// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), windowStateName)
	if got := loadWindowState(path); got != (windowState{Width: defaultWidth, Height: defaultHeight}) {
		t.Fatalf("missing file: got %+v", got)
	}
	want := windowState{Width: 1234, Height: 876, Maximised: true}
	if err := saveWindowState(path, want); err != nil {
		t.Fatal(err)
	}
	if got := loadWindowState(path); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadWindowState(path); got.Width != defaultWidth || got.Height != defaultHeight {
		t.Fatalf("broken file: got %+v", got)
	}
}

func TestWindowStateFit(t *testing.T) {
	cases := []struct {
		in         windowState
		maxW, maxH int
		w, h       int
	}{
		{windowState{Width: 1000, Height: 800}, 0, 0, 1000, 800},
		{windowState{Width: 100, Height: 100}, 0, 0, minWidth, minHeight},
		{windowState{Width: 0, Height: 900}, 0, 0, defaultWidth, defaultHeight},
		{windowState{Width: 3000, Height: 2000}, 1920, 1040, 1920, 1040},
		{windowState{Width: 900, Height: 700}, 300, 300, minWidth, minHeight}, // minimum wins
	}
	for _, c := range cases {
		got := c.in.fit(c.maxW, c.maxH)
		if got.Width != c.w || got.Height != c.h {
			t.Errorf("%+v fit(%d,%d) = %dx%d, want %dx%d", c.in, c.maxW, c.maxH, got.Width, got.Height, c.w, c.h)
		}
	}
}

func TestRestartPolicy(t *testing.T) {
	p := newRestartPolicy()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	long := time.Hour
	if ok, _ := p.allow(0, long, now); ok {
		t.Error("clean exit restarted")
	}
	if ok, _ := p.allow(exitNoRestart, long, now); ok {
		t.Error("reported start failure restarted")
	}
	if ok, _ := p.allow(2, time.Second, now); ok {
		t.Error("crash right at start restarted")
	}
	for i := 0; i < 5; i++ {
		if ok, why := p.allow(2, long, now.Add(time.Duration(i)*time.Minute)); !ok {
			t.Fatalf("restart %d refused: %s", i, why)
		}
	}
	if ok, _ := p.allow(2, long, now.Add(10*time.Minute)); ok {
		t.Error("sixth crash within an hour restarted")
	}
	if ok, why := p.allow(-1, long, now.Add(2*time.Hour)); !ok {
		t.Errorf("crash an hour later refused: %s", why)
	}
}
