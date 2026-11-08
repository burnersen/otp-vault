// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	cheapKDF(t)
	dir := t.TempDir()
	a := NewApp(appPaths{DataDir: dir, LogFile: filepath.Join(dir, "x.log")}, slog.New(slog.DiscardHandler))
	a.emit = func(string, ...any) {}
	return a
}

// The page gets message and hint on two lines, never the technical cause.
func TestUIErrorShowsMessageAndHint(t *testing.T) {
	a := testApp(t)
	err := a.Unlock("whatever password")
	if err == nil {
		t.Fatal("unlock without a vault")
	}
	lines := strings.Split(err.Error(), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "does not exist") {
		t.Fatalf("text for the page: %q", err.Error())
	}
	if strings.Contains(err.Error(), "no such file") {
		t.Fatalf("technical cause reached the page: %q", err.Error())
	}
}

func TestUIErrorUnknownPointsToLog(t *testing.T) {
	a := testApp(t)
	a.paths.LogFile = `C:\logs\otp-vault.log`
	err := a.uiError(errors.New("boom"))
	if !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), `C:\logs\otp-vault.log`) {
		t.Fatalf("%q", err.Error())
	}
}

func TestAppFlow(t *testing.T) {
	a := testApp(t)
	st, err := a.State()
	if err != nil || st.HasVault || st.Unlocked || st.Settings.Language != "en" {
		t.Fatalf("%+v %v", st, err)
	}
	if err := a.Create("long enough password"); err != nil {
		t.Fatal(err)
	}
	p, err := a.ParseInput("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP")
	if err != nil || p.Count != 1 || p.Entry.Issuer != "GitHub" || p.Website != "github.com" {
		t.Fatalf("%+v %v", p, err)
	}
	v, err := a.AddEntry(EntryInput{Secret: "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP", Issuer: "GitHub (work)"})
	if err != nil || v.Issuer != "GitHub (work)" || v.Account != "me" {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := a.AddEntry(EntryInput{Secret: "MFRGGZDF"}); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Fatalf("no name: %v", err)
	}
	codes, err := a.Codes()
	if err != nil || len(codes) != 1 || len(codes[0].Current) != 6 || len(codes[0].Next) != 6 {
		t.Fatalf("%+v %v", codes, err)
	}
	d, err := a.Details(v.ID)
	if err != nil || d.Secret != "JBSWY3DPEHPK3PXP" || !strings.HasPrefix(d.QR, "data:image/svg+xml;base64,") {
		t.Fatalf("%+v %v", d, err)
	}

	// import: one duplicate, one without a name, one new
	text := "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP\notpauth://totp/x?secret=MFRGGZDF\notpauth://totp/Discord:me?secret=MZXW6YTBOI"
	pv, err := a.ImportText(text, "")
	if err != nil || len(pv.Items) != 3 || !pv.Items[0].Duplicate || pv.Items[1].Missing || pv.Items[1].Account != "x" {
		t.Fatalf("%+v %v", pv, err)
	}
	pv, err = a.ImportText("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP\nMFRGGZDF", "")
	if err == nil {
		t.Fatal("mixed bad text accepted")
	}
	pv, err = a.ImportText(text, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.CommitImport([]ImportChoice{{Index: 0, Include: true}, {Index: 1, Include: true, Issuer: "Named"}, {Index: 2, Include: false}})
	if err != nil || res.Added != 1 || res.Skipped != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	list, _ := a.List()
	if len(list) != 2 {
		t.Fatalf("%d", len(list))
	}

	// a bare secret: the page must ask for the name
	pv, err = a.ImportText("JBSWY3DPEHPK3PXQ", "")
	if err != nil || len(pv.Items) != 1 || !pv.Items[0].Missing {
		t.Fatalf("%+v %v", pv, err)
	}
	a.CancelImport()

	// backup with the vault's own password opens with that password
	data, err := a.exportData(ExportRequest{Kind: exportBackup})
	if err != nil {
		t.Fatal(err)
	}
	pv, err = a.ImportText(string(data), "")
	if err != nil || !pv.NeedsPassword {
		t.Fatalf("%+v %v", pv, err)
	}
	pv, err = a.ImportText(string(data), "long enough password")
	if err != nil || len(pv.Items) != 2 || !pv.Items[0].Duplicate {
		t.Fatalf("%+v %v", pv, err)
	}
	if _, err := a.exportData(ExportRequest{Kind: exportBackupNew, Password: "short"}); err == nil {
		t.Fatal("short backup password")
	}
	for _, k := range []string{exportURIs, exportCSV, exportAegisJSON, exportPDF} {
		if b, err := a.exportData(ExportRequest{Kind: k, IDs: []string{list[0].ID}}); err != nil || len(b) == 0 {
			t.Fatalf("%s: %v", k, err)
		}
	}
	qrs, err := a.GoogleExport(nil)
	if err != nil || len(qrs) != 1 {
		t.Fatalf("%d %v", len(qrs), err)
	}

	// auto lock after the idle time
	clock := time.Now()
	a.now = func() time.Time { return clock }
	a.Touch()
	clock = clock.Add(4 * time.Minute)
	a.checkAutoLock()
	if !a.store.unlocked() {
		t.Fatal("locked too early")
	}
	clock = clock.Add(2 * time.Minute)
	a.checkAutoLock()
	if a.store.unlocked() {
		t.Fatal("not locked after 6 minutes")
	}
	if _, err := a.Codes(); err == nil {
		t.Fatal("codes while locked")
	}
	if err := a.Unlock("wrong password here"); err == nil || !strings.HasPrefix(err.Error(), "Wrong password") {
		t.Fatalf("%v", err)
	}
	if err := a.Unlock("long enough password"); err != nil {
		t.Fatal(err)
	}
}

func TestSettings(t *testing.T) {
	a := testApp(t)
	s := a.settings
	s.Language, s.AutoLockMinutes, s.Theme = "de", 999, "neon"
	got, err := a.SaveSettings(s)
	if err != nil || got.Language != "de" || got.AutoLockMinutes != 5 || got.Theme != "system" {
		t.Fatalf("%+v %v", got, err)
	}
	again, warn := loadSettings(filepath.Join(a.paths.DataDir, settingsName))
	if warn != "" || again != got {
		t.Fatalf("%+v %q", again, warn)
	}
	if err := writeFileAtomic(filepath.Join(a.paths.DataDir, settingsName), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, warn := loadSettings(filepath.Join(a.paths.DataDir, settingsName)); warn == "" || s != defaultSettings() {
		t.Fatalf("%+v %q", s, warn)
	}
}
