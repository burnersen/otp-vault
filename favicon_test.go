// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")

func TestIconLinks(t *testing.T) {
	page := `<head><link rel="icon" href="/small.ico"><LINK REL='apple-touch-icon' href='/apple.png'>
	<link rel="mask-icon" href="/mask.svg"><link rel="icon" sizes="32x32 64x64" href=big.png></head>`
	got := iconLinks(page)
	if len(got) != 3 || got[0].href != "/apple.png" || got[1].href != "big.png" || got[2].href != "/small.ico" {
		t.Fatalf("%+v", got)
	}
}

func TestFetchIcon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`<link rel="icon" href="/img/icon.png">`))
	})
	mux.HandleFunc("/img/icon.png", func(w http.ResponseWriter, r *http.Request) { w.Write(pngBytes) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	f := &iconFetcher{client: srv.Client(), scheme: "https", agent: "test"}
	// normalizeHost drops the port, so test hosts go through a transport
	// that sends every request to the test server.
	f.client.Transport = rewriteTransport{to: u, base: srv.Client().Transport}
	got, err := f.fetch(context.Background(), "example.org")
	if err != nil || !strings.HasPrefix(got, "data:image/png;base64,") {
		t.Fatalf("%q %v", got, err)
	}
	if iconMime([]byte("<html>hello</html>")) != "" || iconMime([]byte{0, 0, 1, 0, 1}) != "image/x-icon" ||
		iconMime([]byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)) != "image/svg+xml" ||
		iconMime([]byte(`<svg><script>alert(1)</script></svg>`)) != "" {
		t.Fatal("iconMime")
	}
}

type rewriteTransport struct {
	to   *url.URL
	base http.RoundTripper
}

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = r.to.Host
	return r.base.RoundTrip(req)
}
