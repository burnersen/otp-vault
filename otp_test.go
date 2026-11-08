// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/base32"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func b32(s string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s))
}

// Test vectors of RFC 6238, appendix B.
func TestTOTPRFC6238(t *testing.T) {
	keys := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	cases := []struct {
		unix int64
		alg  string
		want string
	}{
		{59, "SHA1", "94287082"}, {59, "SHA256", "46119246"}, {59, "SHA512", "90693936"},
		{1111111109, "SHA1", "07081804"}, {1111111109, "SHA256", "68084774"}, {1111111109, "SHA512", "25091201"},
		{1234567890, "SHA1", "89005924"}, {2000000000, "SHA256", "90698825"}, {20000000000, "SHA512", "47863826"},
	}
	for _, c := range cases {
		e := Entry{Kind: kindTOTP, Issuer: "x", Secret: b32(keys[c.alg]), Algorithm: c.alg, Digits: 8}
		if err := normalizeEntry(&e); err != nil {
			t.Fatal(err)
		}
		got, err := codeAt(e, time.Unix(c.unix, 0))
		if err != nil || got != c.want {
			t.Errorf("%s at %d: got %q %v, want %q", c.alg, c.unix, got, err, c.want)
		}
	}
}

// Test vectors of RFC 4226, appendix D.
func TestHOTPRFC4226(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		e := Entry{Kind: kindHOTP, Issuer: "x", Secret: b32("12345678901234567890"), Counter: uint64(i)}
		if err := normalizeEntry(&e); err != nil {
			t.Fatal(err)
		}
		if got, _ := codeAt(e, time.Now()); got != w {
			t.Errorf("counter %d: %s, want %s", i, got, w)
		}
	}
}

func TestSteamCode(t *testing.T) {
	e := Entry{Kind: kindSteam, Issuer: "Steam", Secret: b32("12345678901234567890")}
	if err := normalizeEntry(&e); err != nil {
		t.Fatal(err)
	}
	got, _ := codeAt(e, time.Unix(59, 0))
	if len(got) != 5 || strings.Trim(got, steamAlphabet) != "" {
		t.Fatalf("steam code %q", got)
	}
	if e.Digits != 5 || e.Period != 30 {
		t.Fatalf("%+v", e)
	}
}

func TestNormalizeSecret(t *testing.T) {
	got, err := normalizeSecret("jbsw y3dp-ehpk 3pxp====")
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "   ", "JBSW1", "äbc", "A"} {
		if _, err := normalizeSecret(bad); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
}

func TestCodeViewNext(t *testing.T) {
	e := Entry{Kind: kindTOTP, Issuer: "x", Secret: "JBSWY3DPEHPK3PXP"}
	normalizeEntry(&e) // valid by construction
	now := time.Unix(1000, 0)
	v := codeView(e, now)
	next, _ := codeAt(e, now.Add(30*time.Second))
	if v.Next != next || v.Remaining != 30-1000%30 || v.Period != 30 {
		t.Fatalf("%+v", v)
	}
}

func TestOTPAuthRoundTrip(t *testing.T) {
	cases := []string{
		"otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
		"otpauth://totp/name@email.de?secret=JBSWY3DPEHPK3PXP",
		"otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=7&digits=8",
		"otpauth://totp/Steam:gamer?secret=JBSWY3DPEHPK3PXP&issuer=Steam&encoder=steam",
	}
	for _, c := range cases {
		e, err := parseOTPAuth(c)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if err := normalizeEntry(&e); err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		again, err := parseOTPAuth(buildOTPAuth(e))
		if err != nil {
			t.Fatal(err)
		}
		normalizeEntry(&again) // came from a valid entry
		if again != e {
			t.Errorf("round trip of %s:\n%+v\n%+v", c, e, again)
		}
	}
	e, _ := parseOTPAuth(cases[1])
	if e.Issuer != "" || e.Account != "name@email.de" {
		t.Fatalf("label without issuer: %+v", e)
	}
	e, _ = parseOTPAuth(cases[0])
	if e.Issuer != "ACME Co" || e.Account != "john.doe@email.com" {
		t.Fatalf("%+v", e)
	}
	if !strings.Contains(buildOTPAuth(e), "/ACME%20Co:john.doe@email.com?") {
		t.Fatal(buildOTPAuth(e))
	}
	for _, bad := range []string{"https://x", "otpauth://totp/x", "otpauth://foo/x?secret=AAAA"} {
		if _, err := parseOTPAuth(bad); err == nil {
			t.Errorf("%s passed", bad)
		}
	}
}

func TestGuessWebsite(t *testing.T) {
	for in, want := range map[string]string{"GitHub": "github.com", "Hetzner Cloud": "hetznercloud.com", "proton.me": "proton.me", "": "", "Amazon Web Services": "aws.amazon.com"} {
		if got := guessWebsite(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if normalizeHost("https://WWW.Example.org/login?x=1") != "www.example.org" || normalizeHost("not a host") != "" {
		t.Fatal("normalizeHost")
	}
}

func cheapKDF(t *testing.T) {
	old := defaultKDF
	defaultKDF = kdfParams{Name: kdfName, Time: 1, Memory: 8 * 1024, Threads: 1}
	t.Cleanup(func() { defaultKDF = old })
}

func TestStoreLifecycle(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "vault.otpv")
	s := newStore(path)
	if err := s.create("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := s.create("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if err := s.create("correct horse battery"); err == nil {
		t.Fatal("second create replaced the vault")
	}
	e, err := s.add(Entry{Issuer: "GitHub", Account: "me", Secret: "jbsw y3dp ehpk 3pxp"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Website != "github.com" || e.Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("%+v", e)
	}
	if _, err := s.add(Entry{Issuer: "Other", Secret: "JBSWY3DPEHPK3PXP"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	added, skipped, err := s.addMany([]Entry{{Issuer: "A", Secret: "MFRGGZDF"}, {Issuer: "B", Secret: "MFRGGZDF"}, {Issuer: "C", Secret: "JBSWY3DPEHPK3PXP"}, {Secret: "MZXW6"}})
	if err != nil || added != 1 || skipped != 3 {
		t.Fatalf("addMany %d %d %v", added, skipped, err)
	}
	s.lock()
	if _, err := s.entries(); err == nil {
		t.Fatal("entries while locked")
	}
	if err := s.unlock("wrong password!"); err == nil || !strings.Contains(err.Error(), "Wrong password") {
		t.Fatalf("wrong password: %v", err)
	}
	if err := s.unlock("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	list, _ := s.entries()
	if len(list) != 2 {
		t.Fatalf("%d entries", len(list))
	}
	upd := list[1]
	upd.Secret = ""
	upd.Favorite = true
	upd.Note = "n"
	got, err := s.update(upd)
	if err != nil || got.Secret == "" || !got.Favorite {
		t.Fatalf("update: %+v %v", got, err)
	}
	if list, _ := s.entries(); list[0].ID != upd.ID {
		t.Fatal("favorite not first")
	}
	if err := s.changePassword("nope nope nope", "another long one"); err == nil {
		t.Fatal("wrong old password accepted")
	}
	if err := s.changePassword("correct horse battery", "another long one"); err != nil {
		t.Fatal(err)
	}
	s.lock()
	if err := s.unlock("correct horse battery"); err == nil {
		t.Fatal("old password still opens")
	}
	if err := s.unlock("another long one"); err != nil {
		t.Fatal(err)
	}
	if err := s.remove(upd.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.entries(); len(list) != 1 {
		t.Fatal("remove")
	}
	if ok, _ := vaultExists(path + ".bak"); !ok {
		t.Fatal("no .bak file")
	}
}

func TestTamperedHeaderFails(t *testing.T) {
	cheapKDF(t)
	k, err := newSealKey("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := seal(k, vaultData{Entries: []Entry{{ID: "1", Issuer: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := open(raw, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(raw), `"time": 1`, `"time": 2`, 1)
	if _, _, err := open([]byte(bad), "correct horse battery"); err == nil {
		t.Fatal("changed header still opens")
	}
	if strings.Contains(string(raw), `"x"`) {
		t.Fatal("issuer readable in the file")
	}
}
