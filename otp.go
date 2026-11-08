// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Kinds of one time passwords. Steam uses TOTP with its own alphabet.
const (
	kindTOTP  = "totp"
	kindHOTP  = "hotp"
	kindSteam = "steam"
)

// Defaults of RFC 6238 that nearly every service uses.
const (
	defaultAlgorithm = "SHA1"
	defaultDigits    = 6
	defaultPeriod    = 30
	steamDigits      = 5
	steamAlphabet    = "23456789BCDFGHJKMNPQRTVWXY"
)

// Entry is one account in the vault.
type Entry struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Secret    string `json:"secret"` // base32, upper case, no padding
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Counter   uint64 `json:"counter"`
	Website   string `json:"website,omitempty"` // host name for the icon
	Icon      string `json:"icon,omitempty"`    // data URL
	Note      string `json:"note,omitempty"`
	Favorite  bool   `json:"favorite,omitempty"`
	Created   int64  `json:"created"` // Unix seconds
	Updated   int64  `json:"updated"`
}

// normalizeSecret turns what users paste into plain base32: spaces, dashes
// and padding go, letters become upper case. It fails when nothing usable is
// left.
func normalizeSecret(s string) (string, error) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '-' || r == '\t' || r == '\n' || r == '\r' || r == '=':
			continue
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7'):
			b.WriteRune(r)
		default:
			return "", userError(nil, fmt.Sprintf("The secret contains %q, which is not allowed", r),
				"A secret uses only the letters A to Z and the digits 2 to 7.")
		}
	}
	out := b.String()
	if out == "" {
		return "", userError(nil, "The secret is empty", "Paste the secret or the otpauth:// link of the account.")
	}
	if _, err := decodeSecret(out); err != nil {
		return "", userError(err, "The secret is not valid base32", "Check that it was copied completely.")
	}
	return out, nil
}

func decodeSecret(s string) ([]byte, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errors.New("empty key")
	}
	return key, nil
}

// normalizeEntry fills in defaults and checks every field, so that a code can
// always be computed from an entry that passed.
func normalizeEntry(e *Entry) error {
	e.Kind = strings.ToLower(strings.TrimSpace(e.Kind))
	if e.Kind == "" {
		e.Kind = kindTOTP
	}
	if e.Kind != kindTOTP && e.Kind != kindHOTP && e.Kind != kindSteam {
		return userError(nil, "Unknown type "+e.Kind, "Use TOTP, HOTP or Steam.")
	}
	sec, err := normalizeSecret(e.Secret)
	if err != nil {
		return err
	}
	e.Secret = sec
	e.Algorithm = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(e.Algorithm), "-", ""))
	if e.Algorithm == "" {
		e.Algorithm = defaultAlgorithm
	}
	if e.Algorithm != "SHA1" && e.Algorithm != "SHA256" && e.Algorithm != "SHA512" {
		return userError(nil, "Unknown algorithm "+e.Algorithm, "Use SHA1, SHA256 or SHA512.")
	}
	if e.Kind == kindSteam {
		e.Digits, e.Algorithm = steamDigits, defaultAlgorithm
	}
	if e.Digits == 0 {
		e.Digits = defaultDigits
	}
	if e.Digits < 5 || e.Digits > 10 {
		return userError(nil, fmt.Sprintf("%d digits are not possible", e.Digits), "Use 6, 7 or 8 digits.")
	}
	if e.Period == 0 {
		e.Period = defaultPeriod
	}
	if e.Period < 5 || e.Period > 600 {
		return userError(nil, fmt.Sprintf("A period of %d seconds is not possible", e.Period), "Use a period between 5 and 600 seconds, usually 30.")
	}
	e.Issuer = strings.TrimSpace(e.Issuer)
	e.Account = strings.TrimSpace(e.Account)
	e.Website = normalizeHost(e.Website)
	if e.Issuer == "" && e.Account == "" {
		return userError(nil, "The entry has neither a service nor a user name", "Enter at least the name of the service.")
	}
	return nil
}

func hashFor(algorithm string) func() hash.Hash {
	switch algorithm {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return sha1.New
	}
}

// hotpValue is RFC 4226: HMAC of the counter, dynamic truncation.
func hotpValue(key []byte, counter uint64, algorithm string) uint32 {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(hashFor(algorithm), key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
}

func formatCode(v uint32, digits int, kind string) string {
	if kind == kindSteam {
		out := make([]byte, steamDigits)
		for i := range out {
			out[i] = steamAlphabet[v%uint32(len(steamAlphabet))]
			v /= uint32(len(steamAlphabet))
		}
		return string(out)
	}
	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, uint64(v)%mod)
}

// codeAt computes the code of e for the counter or the time step of t.
func codeAt(e Entry, t time.Time) (string, error) {
	key, err := decodeSecret(e.Secret)
	if err != nil {
		return "", err
	}
	counter := e.Counter
	if e.Kind != kindHOTP {
		counter = uint64(t.Unix()) / uint64(e.Period)
	}
	return formatCode(hotpValue(key, counter, e.Algorithm), e.Digits, e.Kind), nil
}

// CodeView is what the page shows for one entry at one moment.
type CodeView struct {
	ID        string `json:"id"`
	Current   string `json:"current"`
	Next      string `json:"next"`
	Remaining int    `json:"remaining"` // seconds until Current changes
	Period    int    `json:"period"`
}

func codeView(e Entry, now time.Time) CodeView {
	v := CodeView{ID: e.ID, Period: e.Period}
	cur, err := codeAt(e, now)
	if err != nil {
		v.Current = "------"
		return v
	}
	v.Current = cur
	if e.Kind == kindHOTP {
		next := e
		next.Counter++
		v.Next, _ = codeAt(next, now) // ignore: same key as above, cannot fail
		return v
	}
	p := int64(e.Period)
	v.Remaining = int(p - now.Unix()%p)
	v.Next, _ = codeAt(e, now.Add(time.Duration(p)*time.Second)) // ignore: same key
	return v
}
