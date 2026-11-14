// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Icons are fetched only when the user asks, and only from the service's
// own website (never from an icon service that would learn the list of
// accounts). Only the host name leaves the PC, never a secret or a user name.

const (
	maxPageBytes = 1 << 20
	maxIconBytes = 512 << 10
	iconTimeout  = 12 * time.Second
)

type iconFetcher struct {
	client *http.Client
	scheme string // "https"; tests use their TLS server
	agent  string
}

func newIconFetcher() *iconFetcher {
	return &iconFetcher{
		client: &http.Client{Timeout: iconTimeout, CheckRedirect: httpsRedirectsOnly},
		scheme: "https",
		agent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) otp-vault/" + version,
	}
}

// httpsRedirectsOnly stops a website from sending the request on to an
// unencrypted address, where anyone on the way could swap the icon.
func httpsRedirectsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("redirect to an unencrypted address refused: " + req.URL.Host)
	}
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	return nil
}

var (
	linkTag  = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	attrExpr = regexp.MustCompile(`(?is)([a-z-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
)

type iconCandidate struct {
	href  string
	score int
}

// iconLinks reads the <link rel="icon"> tags of a page. Bigger icons and
// apple-touch-icons (usually 180 px) come first: they look best on a card.
func iconLinks(page string) []iconCandidate {
	var out []iconCandidate
	for _, tag := range linkTag.FindAllString(page, -1) {
		attrs := map[string]string{}
		for _, m := range attrExpr.FindAllStringSubmatch(tag, -1) {
			attrs[strings.ToLower(m[1])] = m[3] + m[4] + m[5]
		}
		rel := strings.ToLower(attrs["rel"])
		if !strings.Contains(rel, "icon") || attrs["href"] == "" || strings.Contains(rel, "mask") {
			continue
		}
		score := 16
		if strings.Contains(rel, "apple-touch") {
			score = 180
		}
		for _, sz := range strings.Fields(strings.ToLower(attrs["sizes"])) {
			if w, _, ok := strings.Cut(sz, "x"); ok {
				if n, err := strconv.Atoi(w); err == nil && n > score && n <= 512 {
					score = n
				}
			}
			if sz == "any" {
				score = 200
			}
		}
		if strings.HasSuffix(strings.ToLower(attrs["href"]), ".svg") || attrs["type"] == "image/svg+xml" {
			score = 190
		}
		out = append(out, iconCandidate{href: attrs["href"], score: score})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })
	return out
}

// fetch returns the icon of host as a data URL.
func (f *iconFetcher) fetch(ctx context.Context, host string) (string, error) {
	host = normalizeHost(host)
	if host == "" {
		return "", userError(nil, "No website for the icon", "Enter the website of the service, for example github.com.")
	}
	hosts := []string{host}
	if parts := strings.Split(host, "."); len(parts) > 2 {
		hosts = append(hosts, strings.Join(parts[1:], ".")) // accounts.example.com > example.com
	} else if !strings.HasPrefix(host, "www.") {
		hosts = append(hosts, "www."+host)
	}
	var lastErr error
	for _, h := range hosts {
		base := &url.URL{Scheme: f.scheme, Host: h, Path: "/"}
		var tries []string
		if page, final, err := f.get(ctx, base.String(), maxPageBytes); err == nil {
			for _, c := range iconLinks(string(page)) {
				if u, err := final.Parse(strings.TrimSpace(c.href)); err == nil && (u.Scheme == "https" || u.Scheme == f.scheme) {
					tries = append(tries, u.String())
				}
			}
			tries = append(tries, final.ResolveReference(&url.URL{Path: "/favicon.ico"}).String())
		} else {
			lastErr = err
		}
		tries = append(tries, base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String())
		seen := map[string]bool{}
		for _, u := range tries {
			if seen[u] {
				continue
			}
			seen[u] = true
			data, _, err := f.get(ctx, u, maxIconBytes)
			if err != nil {
				lastErr = err
				continue
			}
			if mime := iconMime(data); mime != "" {
				return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data), nil
			}
		}
	}
	return "", userError(lastErr, "No icon found for "+host, "Check the website, or leave the entry without an icon.")
}

func (f *iconFetcher) get(ctx context.Context, u string, limit int64) ([]byte, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", f.agent)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close() // read only
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, errors.New(u + ": too large")
	}
	return data, resp.Request.URL, nil
}

// iconMime looks at the bytes, not at what the server claims.
func iconMime(b []byte) string {
	switch {
	case len(b) < 4:
		return ""
	case b[0] == 0 && b[1] == 0 && (b[2] == 1 || b[2] == 2) && b[3] == 0:
		return "image/x-icon"
	}
	ct := http.DetectContentType(b)
	if strings.HasPrefix(ct, "image/") && iconMimeOK(ct) {
		return ct
	}
	head := strings.ToLower(string(b[:min(len(b), 512)]))
	if strings.Contains(head, "<svg") && !strings.Contains(strings.ToLower(string(b)), "<script") {
		return "image/svg+xml"
	}
	return ""
}
