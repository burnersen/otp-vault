// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/burnersen/otp-vault/internal/qr"
)

// A small PDF writer for the printed recovery sheets: A4, the standard
// fonts every PDF reader has (Helvetica, Courier, WinAnsi encoding, so
// German umlauts work), QR codes as filled rectangles. No library needed,
// and the result is plain vector graphics that print sharp at any size.

const (
	a4W, a4H     = 595.28, 841.89
	pageMargin   = 36.0
	cardCols     = 2
	cardRows     = 3
	cardGap      = 12.0
	headerHeight = 54.0
	footerHeight = 34.0
	qrSize       = 128.0
)

// sheetText holds the words on the sheet, in the language of the page.
type sheetText struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Account  string `json:"account"`
	Secret   string `json:"secret"`
	Warning  string `json:"warning"`
	Page     string `json:"page"` // "Page %d of %d"
}

var sheetTextEN = sheetText{
	Title:    "otp-vault recovery sheet",
	Subtitle: "Scan a code with any authenticator app to restore the account.",
	Account:  "User",
	Secret:   "Secret",
	Warning:  "Keep this sheet in a safe place: anyone who has it can create your login codes.",
	Page:     "Page %d of %d",
}

func (t sheetText) orDefault() sheetText {
	d := sheetTextEN
	if t.Title != "" {
		d.Title = t.Title
	}
	if t.Subtitle != "" {
		d.Subtitle = t.Subtitle
	}
	if t.Account != "" {
		d.Account = t.Account
	}
	if t.Secret != "" {
		d.Secret = t.Secret
	}
	if t.Warning != "" {
		d.Warning = t.Warning
	}
	if strings.Count(t.Page, "%d") == 2 {
		d.Page = t.Page
	}
	return d
}

// winAnsi turns text into bytes of Windows-1252, escaped for a PDF string.
// Characters outside it become "?".
func winAnsi(s string) string {
	extra := map[rune]byte{'€': 0x80, '‚': 0x82, '„': 0x84, '…': 0x85, '‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '™': 0x99}
	var b strings.Builder
	for _, r := range s {
		var c byte
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			c = byte(r)
		case r >= 0x20 && r < 0x7f:
			c = byte(r)
		case r >= 0xa0 && r <= 0xff:
			c = byte(r)
		default:
			var ok bool
			if c, ok = extra[r]; !ok {
				c = '?'
			}
		}
		if c >= 0x80 {
			fmt.Fprintf(&b, "\\%03o", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// fit cuts text so it stays inside width at the font size (an average
// character width is good enough for names and mail addresses).
func fit(s string, width, size, avg float64) string {
	max := int(width / (size * avg))
	r := []rune(s)
	if len(r) <= max || max < 4 {
		return s
	}
	return string(r[:max-1]) + "…"
}

type pdfPage struct{ content bytes.Buffer }

func (p *pdfPage) text(font string, size, x, y float64, gray float64, s string) {
	fmt.Fprintf(&p.content, "BT /%s %.1f Tf %.3f g %.2f %.2f Td (%s) Tj ET\n", font, size, gray, x, y, winAnsi(s))
}

// textCentered uses the same average width as fit; close enough for a title.
func (p *pdfPage) textCentered(font string, size, cx, y, gray float64, s string, avg float64) {
	w := float64(len([]rune(s))) * size * avg
	p.text(font, size, cx-w/2, y, gray, s)
}

func (p *pdfPage) rect(x, y, w, h, gray float64) {
	fmt.Fprintf(&p.content, "%.3f G 0.8 w %.2f %.2f %.2f %.2f re S\n", gray, x, y, w, h)
}

// qrCode draws text as a QR code with its top left corner at x, top.
func (p *pdfPage) qrCode(text string, x, top, size float64) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	cell := size / float64(code.Size)
	p.content.WriteString("0 g\n")
	for row := 0; row < code.Size; row++ {
		for col := 0; col < code.Size; {
			if !code.Black(col, row) {
				col++
				continue
			}
			start := col
			for col < code.Size && code.Black(col, row) {
				col++
			}
			// A hair of overlap avoids white lines between cells in viewers.
			fmt.Fprintf(&p.content, "%.3f %.3f %.3f %.3f re\n",
				x+float64(start)*cell, top-float64(row+1)*cell-0.05, float64(col-start)*cell, cell+0.1)
		}
	}
	p.content.WriteString("f\n")
	return nil
}

func groupSecret(s string) []string {
	var parts []string
	for i := 0; i < len(s); i += 4 {
		end := min(i+4, len(s))
		parts = append(parts, s[i:end])
	}
	var lines []string
	const perLine = 8 // groups of four
	for i := 0; i < len(parts); i += perLine {
		lines = append(lines, strings.Join(parts[i:min(i+perLine, len(parts))], " "))
	}
	return lines
}

func entryDetails(e Entry) string {
	switch e.Kind {
	case kindHOTP:
		return fmt.Sprintf("HOTP · %s · %d · counter %d", e.Algorithm, e.Digits, e.Counter)
	case kindSteam:
		return "Steam · 30 s"
	}
	return fmt.Sprintf("TOTP · %s · %d · %d s", e.Algorithm, e.Digits, e.Period)
}

// buildPDF lays out the entries six per A4 page.
func buildPDF(list []Entry, t sheetText, now time.Time) ([]byte, error) {
	t = t.orDefault()
	perPage := cardCols * cardRows
	pageCount := (len(list) + perPage - 1) / perPage
	if pageCount == 0 {
		pageCount = 1
	}
	cardW := (a4W - 2*pageMargin - cardGap*(cardCols-1)) / cardCols
	cardH := (a4H - 2*pageMargin - headerHeight - footerHeight - cardGap*(cardRows-1)) / cardRows
	var pages []*pdfPage
	for pi := 0; pi < pageCount; pi++ {
		p := &pdfPage{}
		top := a4H - pageMargin
		p.text("F2", 16, pageMargin, top-16, 0.1, t.Title)
		p.text("F1", 9, pageMargin, top-31, 0.35, t.Subtitle)
		date := now.Format("2006-01-02 15:04")
		p.text("F1", 9, a4W-pageMargin-float64(len(date))*9*0.52, top-16, 0.35, date)
		for i := 0; i < perPage; i++ {
			idx := pi*perPage + i
			if idx >= len(list) {
				break
			}
			e := list[idx]
			col, row := i%cardCols, i/cardCols
			x := pageMargin + float64(col)*(cardW+cardGap)
			y := top - headerHeight - float64(row)*(cardH+cardGap) // top of the card
			p.rect(x, y-cardH, cardW, cardH, 0.75)
			cx := x + cardW/2
			if err := p.qrCode(buildOTPAuth(e), cx-qrSize/2, y-12, qrSize); err != nil {
				return nil, err
			}
			ty := y - 12 - qrSize - 18
			issuer := e.Issuer
			if issuer == "" {
				issuer = e.Account
			}
			p.textCentered("F2", 12, cx, ty, 0.1, fit(issuer, cardW-16, 12, 0.56), 0.56)
			ty -= 14
			if e.Account != "" && e.Account != issuer {
				p.textCentered("F1", 9.5, cx, ty, 0.2, fit(t.Account+": "+e.Account, cardW-16, 9.5, 0.52), 0.52)
			}
			ty -= 14
			for _, line := range groupSecret(e.Secret) {
				p.textCentered("F3", 8.5, cx, ty, 0.1, line, 0.6)
				ty -= 10.5
			}
			p.textCentered("F1", 7.5, cx, ty-2, 0.4, entryDetails(e), 0.5)
		}
		p.text("F1", 8, pageMargin, pageMargin+6, 0.35, t.Warning)
		pg := fmt.Sprintf(t.Page, pi+1, pageCount)
		p.text("F1", 8, a4W-pageMargin-float64(len(pg))*8*0.52, pageMargin+6, 0.35, pg)
		pages = append(pages, p)
	}
	return writePDF(pages, t.Title, now), nil
}

func writePDF(pages []*pdfPage, title string, now time.Time) []byte {
	var out bytes.Buffer
	var offsets []int
	obj := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	// 1 catalog, 2 pages, 3 to 5 fonts, 6 info, then page and content pairs.
	const first = 7
	kids := make([]string, len(pages))
	for i := range pages {
		kids[i] = fmt.Sprintf("%d 0 R", first+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
	obj(fmt.Sprintf("<< /Title (%s) /Producer (otp-vault) /CreationDate (D:%s) >>", winAnsi(title), now.UTC().Format("20060102150405Z")))
	for i, p := range pages {
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
			a4W, a4H, first+2*i+1))
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", p.content.Len(), p.content.String()))
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return out.Bytes()
}

// qrSVG returns text as a QR code in an SVG data URL for the page.
func qrSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := code.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; {
			if !code.Black(x, y) {
				x++
				continue
			}
			start := x
			for x < code.Size && code.Black(x, y) {
				x++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", start+quiet, y+quiet, x-start, x-start)
		}
	}
	b.WriteString(`"/></svg>`)
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.String())), nil
}
