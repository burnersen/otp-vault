// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

func mustImport(t *testing.T, data, password string) (string, []Entry) {
	t.Helper()
	format, list, err := parseImport([]byte(data), password)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	for i := range list {
		if err := normalizeEntry(&list[i]); err != nil {
			t.Fatalf("entry %d %+v: %v", i, list[i], err)
		}
	}
	return format, list
}

func TestImportPlainSecretAndLinks(t *testing.T) {
	text := "otpauth://totp/name@email.de?secret=JBSWY3DPEHPK3PXP\r\n# comment\n\notpauth://totp/GitHub:me?secret=MFRGGZDF&issuer=GitHub\n"
	f, list := mustImport(t, text, "")
	if f != fmtText || len(list) != 2 || list[1].Issuer != "GitHub" || list[0].Account != "name@email.de" {
		t.Fatalf("%s %+v", f, list)
	}
	if _, _, err := parseImport([]byte("otpauth://totp/x?secret=AAAA\nhello"), ""); err == nil {
		t.Fatal("bad line accepted")
	}
}

func TestBareSecretNeedsName(t *testing.T) {
	f, list, err := parseImport([]byte("JBSWY3DPEHPK3PXP"), "")
	if err != nil || f != fmtSecret || len(list) != 1 || list[0].Issuer != "" {
		t.Fatalf("%s %+v %v", f, list, err)
	}
}

func TestGoogleMigrationRoundTrip(t *testing.T) {
	in := []Entry{
		{Kind: kindTOTP, Issuer: "GitHub", Account: "me", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30},
		{Kind: kindHOTP, Issuer: "Bank", Account: "you", Secret: "MFRGGZDFMZTWQ2LK", Algorithm: "SHA256", Digits: 8, Period: 30, Counter: 5},
	}
	link := buildMigration(in)
	f, list := mustImport(t, link, "")
	if f != fmtMigration || len(list) != 2 {
		t.Fatalf("%s %+v", f, list)
	}
	for i := range in {
		got := list[i]
		if got.Secret != in[i].Secret || got.Issuer != in[i].Issuer || got.Account != in[i].Account ||
			got.Kind != in[i].Kind || got.Digits != in[i].Digits || got.Algorithm != in[i].Algorithm || got.Counter != in[i].Counter {
			t.Errorf("%d: %+v != %+v", i, got, in[i])
		}
	}
	// a real export from the app ("Issuer:name" in the name field)
	real := "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC"
	_, list = mustImport(t, real, "")
	if len(list) != 1 || list[0].Issuer != "Example" || list[0].Account != "alice@google.com" {
		t.Fatalf("%+v", list)
	}
}

func gcmSeal(t *testing.T, key, nonce, plain []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		t.Fatal(err)
	}
	return g.Seal(nil, nonce, plain, nil)
}

func rnd(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) // never fails
	return b
}

const aegisPlainDB = `{"version":2,"entries":[{"type":"totp","uuid":"x","name":"me@mail.de","issuer":"Proton","note":"n","favorite":true,"icon":"iVBORw0K","icon_mime":"image/png","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA256","digits":8,"period":60}},{"type":"steam","uuid":"y","name":"gamer","issuer":"Steam","info":{"secret":"MFRGGZDF","algo":"SHA1","digits":5,"period":30}}],"groups":[]}`

func TestImportAegisPlain(t *testing.T) {
	doc := `{"version":1,"header":{"slots":null,"params":null},"db":` + aegisPlainDB + `}`
	f, list := mustImport(t, doc, "")
	if f != fmtAegis || len(list) != 2 {
		t.Fatalf("%s %d", f, len(list))
	}
	e := list[0]
	if e.Issuer != "Proton" || e.Algorithm != "SHA256" || e.Digits != 8 || e.Period != 60 || !e.Favorite || e.Icon != "data:image/png;base64,iVBORw0K" {
		t.Fatalf("%+v", e)
	}
	if list[1].Kind != kindSteam {
		t.Fatalf("%+v", list[1])
	}
}

func TestImportAegisEncrypted(t *testing.T) {
	password := "aegis pass"
	master := rnd(32)
	dbNonce := rnd(12)
	sealed := gcmSeal(t, master, dbNonce, []byte(aegisPlainDB))
	ct, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	salt := rnd(32)
	derived, err := scrypt.Key([]byte(password), salt, 1024, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	keyNonce := rnd(12)
	sk := gcmSeal(t, derived, keyNonce, master)
	header := map[string]any{
		"slots": []any{
			map[string]any{"type": 2, "uuid": "bio"},
			map[string]any{"type": 1, "uuid": "pw", "key": hex.EncodeToString(sk[:32]),
				"key_params": map[string]string{"nonce": hex.EncodeToString(keyNonce), "tag": hex.EncodeToString(sk[32:])},
				"n":          1024, "r": 8, "p": 1, "salt": hex.EncodeToString(salt)},
		},
		"params": map[string]string{"nonce": hex.EncodeToString(dbNonce), "tag": hex.EncodeToString(tag)},
	}
	raw, _ := json.Marshal(map[string]any{"version": 1, "header": header, "db": base64.StdEncoding.EncodeToString(ct)})
	if _, _, err := parseImport(raw, ""); !errors.Is(err, errNeedPassword) {
		t.Fatalf("no password: %v", err)
	}
	if _, _, err := parseImport(raw, "wrong"); err == nil || !strings.Contains(err.Error(), "Wrong password") {
		t.Fatalf("wrong password: %v", err)
	}
	_, list := mustImport(t, string(raw), password)
	if len(list) != 2 || list[0].Issuer != "Proton" {
		t.Fatalf("%+v", list)
	}
}

func TestImport2FAS(t *testing.T) {
	services := `[{"name":"GitHub","secret":"JBSWY3DPEHPK3PXP","otp":{"account":"me","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP"}},{"name":"Bank","secret":"MFRGGZDF","otp":{"label":"you","issuer":"MyBank","tokenType":"HOTP","counter":3}}]`
	f, list := mustImport(t, `{"services":`+services+`,"schemaVersion":4}`, "")
	if f != fmt2FAS || len(list) != 2 || list[0].Issuer != "GitHub" || list[1].Issuer != "MyBank" || list[1].Account != "you" || list[1].Kind != kindHOTP {
		t.Fatalf("%+v", list)
	}
	salt, iv := rnd(256), rnd(12)
	key, _ := pbkdf2.Key(sha256.New, "2fas pass", salt, 10000, 32)
	ct := gcmSeal(t, key, iv, []byte(services))
	enc := base64.StdEncoding.EncodeToString(ct) + ":" + base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(iv)
	doc := `{"services":[],"servicesEncrypted":"` + enc + `","schemaVersion":4}`
	if _, _, err := parseImport([]byte(doc), ""); !errors.Is(err, errNeedPassword) {
		t.Fatal(err)
	}
	_, list = mustImport(t, doc, "2fas pass")
	if len(list) != 2 {
		t.Fatal(len(list))
	}
}

func TestImportAndOTPAndBitwarden(t *testing.T) {
	f, list := mustImport(t, `[{"secret":"JBSWY3DPEHPK3PXP","issuer":"","label":"GitLab:me","digits":6,"type":"TOTP","algorithm":"SHA1","period":30}]`, "")
	if f != fmtAndOTP || list[0].Issuer != "GitLab" || list[0].Account != "me" {
		t.Fatalf("%+v", list)
	}
	bw := `{"encrypted":false,"items":[{"name":"Mastodon","login":{"username":"bernd","totp":"JBSW Y3DP EHPK 3PXP","uris":[{"uri":"https://mastodon.social/login"}]}},{"name":"no totp","login":{"username":"x"}},{"name":"Steam","login":{"username":"g","totp":"steam://MFRGGZDF"}}]}`
	f, list = mustImport(t, bw, "")
	if f != fmtBitwarden || len(list) != 2 || list[0].Website != "mastodon.social" || list[1].Kind != kindSteam {
		t.Fatalf("%+v", list)
	}
	if _, _, err := parseImport([]byte(`{"encrypted":true,"items":[]}`), ""); err == nil {
		t.Fatal("encrypted bitwarden accepted")
	}
}

func TestImportCSV(t *testing.T) {
	bw := "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
		",,login,Discord,,,0,https://discord.com,me,pw,otpauth://totp/Discord:me?secret=JBSWY3DPEHPK3PXP&issuer=Discord\n" +
		",,login,NoTotp,,,0,,me,pw,\n" +
		",,login,Plain,,,0,https://plain.example,you,pw,MFRGGZDF\n"
	f, list := mustImport(t, bw, "")
	if f != fmtCSV || len(list) != 2 || list[1].Issuer != "Plain" || list[1].Website != "plain.example" || list[1].Kind != kindTOTP {
		t.Fatalf("%+v", list)
	}
	kp := "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\"Root\",\"Netcup\",\"me\",\"x\",\"https://netcup.de\",\"\",\"otpauth://totp/Netcup:me?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Netcup\"\n"
	_, list = mustImport(t, kp, "")
	if len(list) != 1 || list[0].Issuer != "Netcup" {
		t.Fatalf("%+v", list)
	}
}

func TestExportsImportAgain(t *testing.T) {
	cheapKDF(t)
	in := []Entry{
		{Kind: kindTOTP, Issuer: "GitHub", Account: "me", Secret: "JBSWY3DPEHPK3PXP", Website: "github.com", Note: "a, \"b\""},
		{Kind: kindHOTP, Issuer: "Bank", Account: "you", Secret: "MFRGGZDFMZTWQ2LK", Algorithm: "SHA512", Digits: 8, Counter: 9},
		{Kind: kindSteam, Issuer: "Steam", Account: "g", Secret: "MZXW6YTBOI", Icon: "data:image/png;base64,iVBO"},
	}
	for i := range in {
		if err := normalizeEntry(&in[i]); err != nil {
			t.Fatal(err)
		}
	}
	same := func(name string, got []Entry) {
		t.Helper()
		if len(got) != len(in) {
			t.Fatalf("%s: %d entries", name, len(got))
		}
		for i := range in {
			g := got[i]
			if g.Secret != in[i].Secret || g.Kind != in[i].Kind || g.Issuer != in[i].Issuer || g.Account != in[i].Account ||
				g.Digits != in[i].Digits || g.Algorithm != in[i].Algorithm || g.Counter != in[i].Counter || g.Period != in[i].Period {
				t.Errorf("%s %d:\n got %+v\nwant %+v", name, i, g, in[i])
			}
		}
	}
	_, list := mustImport(t, string(exportURIList(in)), "")
	same("uris", list)
	raw, err := exportCSVFile(in)
	if err != nil {
		t.Fatal(err)
	}
	_, list = mustImport(t, string(raw), "")
	same("csv", list)
	if list[0].Note != in[0].Note || list[0].Website != "github.com" {
		t.Fatalf("csv note/website: %+v", list[0])
	}
	raw, err = exportAegis(in)
	if err != nil {
		t.Fatal(err)
	}
	_, list = mustImport(t, string(raw), "")
	same("aegis", list)
	if list[2].Icon != in[2].Icon {
		t.Fatal("aegis icon lost")
	}
	k, _ := newSealKey("backup password")
	raw, err = exportSealed(in, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseImport(raw, ""); !errors.Is(err, errNeedPassword) {
		t.Fatal(err)
	}
	_, list = mustImport(t, string(raw), "backup password")
	same("backup", list)
	_, list = mustImport(t, buildMigration(in[:2]), "")
	if len(list) != 2 || list[1].Counter != 9 {
		t.Fatalf("%+v", list)
	}
}

func TestPDF(t *testing.T) {
	var list []Entry
	for i := 0; i < 7; i++ {
		e := Entry{Issuer: "Dienst Größe (Ä)", Account: "user@example.org", Secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
		normalizeEntry(&e) // valid by construction
		list = append(list, e)
	}
	raw, err := buildPDF(list, sheetText{Page: "Seite %d von %d"}, time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.HasPrefix(s, "%PDF-1.4") || !strings.HasSuffix(s, "%%EOF\n") || strings.Count(s, "/Type /Page ") != 2 {
		t.Fatal("pdf structure")
	}
	if !strings.Contains(s, `Gr\366\337e \(\304\)`) || !strings.Contains(s, "Seite 2 von 2") {
		t.Fatal("pdf text encoding")
	}
	// the xref offsets must point at the objects
	xref := strings.Index(s, "\nxref\n") + 1
	lines := strings.Split(s[xref:], "\n")
	for i, l := range lines[3:9] {
		off, err := strconv.Atoi(strings.Fields(l)[0])
		if err != nil || !bytes.HasPrefix(raw[off:], []byte(strconv.Itoa(i+1)+" 0 obj")) {
			t.Fatalf("xref %d: %q", i+1, l)
		}
	}
	if _, err := qrSVG(buildOTPAuth(list[0])); err != nil {
		t.Fatal(err)
	}
}
