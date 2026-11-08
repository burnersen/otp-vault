// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// Google Authenticator exports accounts as QR codes with links like
// otpauth-migration://offline?data=<base64 protobuf>. The protobuf is small,
// so it is read here by hand instead of pulling in a protobuf library:
//
//	MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
//	OtpParameters {
//	  bytes secret = 1; string name = 2; string issuer = 3;
//	  Algorithm algorithm = 4;  // 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
//	  DigitCount digits = 5;    // 1 six, 2 eight
//	  OtpType type = 6;         // 1 HOTP, 2 TOTP
//	  int64 counter = 7;
//	}

var errProto = errors.New("damaged protobuf")

type protoReader struct {
	b []byte
}

func (r *protoReader) varint() (uint64, error) {
	var v uint64
	for shift := uint(0); shift < 64; shift += 7 {
		if len(r.b) == 0 {
			return 0, errProto
		}
		c := r.b[0]
		r.b = r.b[1:]
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, nil
		}
	}
	return 0, errProto
}

// next returns field number, wire type and, for length delimited fields,
// the bytes; for varints the value.
func (r *protoReader) next() (field int, wire int, data []byte, val uint64, err error) {
	key, err := r.varint()
	if err != nil {
		return 0, 0, nil, 0, err
	}
	field, wire = int(key>>3), int(key&7)
	switch wire {
	case 0:
		val, err = r.varint()
	case 1:
		if len(r.b) < 8 {
			return 0, 0, nil, 0, errProto
		}
		r.b = r.b[8:]
	case 2:
		var n uint64
		n, err = r.varint()
		if err == nil && n > uint64(len(r.b)) {
			err = errProto
		}
		if err == nil {
			data, r.b = r.b[:n], r.b[n:]
		}
	case 5:
		if len(r.b) < 4 {
			return 0, 0, nil, 0, errProto
		}
		r.b = r.b[4:]
	default:
		err = errProto
	}
	return field, wire, data, val, err
}

func parseMigration(raw string) ([]Entry, error) {
	bad := func(err error) ([]Entry, error) {
		return nil, userError(err, "The Google Authenticator export could not be read", "Scan or paste the whole QR code again.")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "otpauth-migration" {
		return bad(err)
	}
	data := strings.ReplaceAll(u.Query().Get("data"), " ", "+")
	payload, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		payload, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(data, "="))
	}
	if err != nil {
		return bad(err)
	}
	var out []Entry
	r := protoReader{b: payload}
	for len(r.b) > 0 {
		field, wire, msg, _, err := r.next()
		if err != nil {
			return bad(err)
		}
		if field != 1 || wire != 2 {
			continue
		}
		e, err := parseMigrationEntry(msg)
		if err != nil {
			return bad(err)
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, userError(nil, "The Google Authenticator export contains no accounts", "Choose the accounts in the app again before exporting.")
	}
	return out, nil
}

func parseMigrationEntry(msg []byte) (Entry, error) {
	e := Entry{Kind: kindTOTP, Algorithm: "SHA1", Digits: 6}
	r := protoReader{b: msg}
	for len(r.b) > 0 {
		field, _, data, val, err := r.next()
		if err != nil {
			return Entry{}, err
		}
		switch field {
		case 1:
			e.Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
		case 2:
			e.Account = string(data)
		case 3:
			e.Issuer = string(data)
		case 4:
			switch val {
			case 2:
				e.Algorithm = "SHA256"
			case 3:
				e.Algorithm = "SHA512"
			case 4:
				e.Algorithm = "MD5" // refused later by normalizeEntry
			}
		case 5:
			if val == 2 {
				e.Digits = 8
			}
		case 6:
			if val == 1 {
				e.Kind = kindHOTP
			}
		case 7:
			e.Counter = val
		}
	}
	// The name is often "Issuer:account" as in an otpauth label.
	if i := strings.Index(e.Account, ":"); i > 0 {
		if e.Issuer == "" {
			e.Issuer = strings.TrimSpace(e.Account[:i])
		}
		if strings.EqualFold(strings.TrimSpace(e.Account[:i]), e.Issuer) {
			e.Account = strings.TrimSpace(e.Account[i+1:])
		}
	}
	return e, nil
}

// buildMigration writes entries in Google Authenticator's export format,
// used by the tests and for the "Google Authenticator" export.
func buildMigration(list []Entry) string {
	var payload []byte
	for _, e := range list {
		key, err := decodeSecret(e.Secret)
		if err != nil {
			continue
		}
		var m []byte
		m = appendBytes(m, 1, key)
		m = appendBytes(m, 2, []byte(e.Account))
		m = appendBytes(m, 3, []byte(e.Issuer))
		alg := uint64(1)
		switch e.Algorithm {
		case "SHA256":
			alg = 2
		case "SHA512":
			alg = 3
		}
		m = appendVarintField(m, 4, alg)
		digits := uint64(1)
		if e.Digits == 8 {
			digits = 2
		}
		m = appendVarintField(m, 5, digits)
		typ := uint64(2)
		if e.Kind == kindHOTP {
			typ = 1
			m = appendVarintField(m, 7, e.Counter)
		}
		m = appendVarintField(m, 6, typ)
		payload = appendBytes(payload, 1, m)
	}
	payload = appendVarintField(payload, 2, 1) // version
	payload = appendVarintField(payload, 3, 1) // batch size
	payload = appendVarintField(payload, 4, 0) // batch index
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendVarintField(b []byte, field int, v uint64) []byte {
	return appendVarint(appendVarint(b, uint64(field)<<3), v)
}

func appendBytes(b []byte, field int, data []byte) []byte {
	b = appendVarint(b, uint64(field)<<3|2)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}
