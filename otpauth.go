// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"net/url"
	"strconv"
	"strings"
)

// parseOTPAuth reads an otpauth:// link (Key Uri Format of Google
// Authenticator). The issuer may be in the label ("GitHub:me"), in the
// parameter or in both; the parameter wins. The result is not normalized yet:
// the caller decides what to do with missing parts.
func parseOTPAuth(raw string) (Entry, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth") {
		return Entry{}, userError(err, "This is not an otpauth:// link", "A link looks like otpauth://totp/Service:name?secret=...")
	}
	e := Entry{Kind: strings.ToLower(u.Host)}
	if e.Kind != kindTOTP && e.Kind != kindHOTP && e.Kind != kindSteam {
		return Entry{}, userError(nil, "The link has the unknown type "+u.Host, "Only totp and hotp links are supported.")
	}
	label := strings.TrimPrefix(u.EscapedPath(), "/")
	if l, err := url.PathUnescape(label); err == nil {
		label = l
	}
	if i := strings.Index(label, ":"); i >= 0 {
		e.Issuer, e.Account = strings.TrimSpace(label[:i]), strings.TrimSpace(label[i+1:])
	} else {
		e.Account = strings.TrimSpace(label)
	}
	q := u.Query()
	if v := strings.TrimSpace(q.Get("issuer")); v != "" {
		e.Issuer = v
	}
	e.Secret = q.Get("secret")
	e.Algorithm = q.Get("algorithm")
	if v := q.Get("digits"); v != "" {
		e.Digits, _ = strconv.Atoi(v) // ignore: a bad number stays 0 and becomes the default
	}
	if v := q.Get("period"); v != "" {
		e.Period, _ = strconv.Atoi(v) // ignore: as above
	}
	if v := q.Get("counter"); v != "" {
		e.Counter, _ = strconv.ParseUint(v, 10, 64) // ignore: as above
	}
	if strings.EqualFold(q.Get("encoder"), "steam") || (e.Kind == kindTOTP && strings.EqualFold(e.Issuer, "steam") && e.Digits == steamDigits) {
		e.Kind = kindSteam
	}
	if e.Secret == "" {
		return Entry{}, userError(nil, "The link has no secret", "Copy the whole link, including the part after secret=.")
	}
	return e, nil
}

// buildOTPAuth writes the link other apps understand. Steam entries become
// totp links with encoder=steam, which Aegis, 2FAS and KeePassXC read.
func buildOTPAuth(e Entry) string {
	kind := e.Kind
	q := url.Values{}
	q.Set("secret", e.Secret)
	if e.Issuer != "" {
		q.Set("issuer", e.Issuer)
	}
	q.Set("algorithm", e.Algorithm)
	q.Set("digits", strconv.Itoa(e.Digits))
	switch kind {
	case kindHOTP:
		q.Set("counter", strconv.FormatUint(e.Counter, 10))
	case kindSteam:
		kind = kindTOTP
		q.Set("encoder", "steam")
		q.Set("period", strconv.Itoa(e.Period))
	default:
		q.Set("period", strconv.Itoa(e.Period))
	}
	label := e.Account
	if e.Issuer != "" {
		label = e.Issuer + ":" + e.Account
	}
	// url.PathEscape keeps ":" and "@", which every app expects in the label.
	return "otpauth://" + kind + "/" + url.PathEscape(label) + "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
}

// normalizeHost turns "https://www.GitHub.com/login" into "www.github.com".
func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	if !strings.Contains(h, ".") || strings.ContainsAny(h, " _") {
		return ""
	}
	return h
}

// knownSites maps issuers whose name is not their domain.
var knownSites = map[string]string{
	"google": "google.com", "gmail": "google.com", "microsoft": "microsoft.com",
	"amazon": "amazon.com", "amazon web services": "aws.amazon.com", "aws": "aws.amazon.com",
	"apple": "apple.com", "facebook": "facebook.com", "meta": "facebook.com", "instagram": "instagram.com",
	"twitter": "x.com", "x": "x.com", "github": "github.com", "gitlab": "gitlab.com",
	"discord": "discord.com", "steam": "steampowered.com", "epic games": "epicgames.com",
	"paypal": "paypal.com", "dropbox": "dropbox.com", "proton": "proton.me", "protonmail": "proton.me",
	"bitwarden": "bitwarden.com", "cloudflare": "cloudflare.com", "nextcloud": "nextcloud.com",
	"netcup": "netcup.de", "contabo": "contabo.com", "hetzner": "hetzner.com", "ionos": "ionos.de",
	"gmx": "gmx.net", "web.de": "web.de", "ebay": "ebay.de", "mastodon": "joinmastodon.org",
	"reddit": "reddit.com", "linkedin": "linkedin.com", "twitch": "twitch.tv", "ubisoft": "ubisoft.com",
	"battle.net": "battle.net", "blizzard": "battle.net", "nintendo": "nintendo.com", "playstation": "playstation.com",
	"sony": "playstation.com", "xbox": "xbox.com", "wordpress": "wordpress.com", "binance": "binance.com",
	"coinbase": "coinbase.com", "kraken": "kraken.com", "tesla": "tesla.com", "slack": "slack.com",
	"zoom": "zoom.us", "atlassian": "atlassian.com", "npm": "npmjs.com", "pypi": "pypi.org",
	"docker": "docker.com", "docker hub": "hub.docker.com", "digitalocean": "digitalocean.com",
}

// guessWebsite suggests the host for an icon from the issuer. The user can
// always correct it; a wrong guess only means no icon.
func guessWebsite(issuer string) string {
	key := strings.ToLower(strings.TrimSpace(issuer))
	if key == "" {
		return ""
	}
	if host, ok := knownSites[key]; ok {
		return host
	}
	if h := normalizeHost(key); h != "" {
		return h
	}
	var b strings.Builder
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() < 2 {
		return ""
	}
	return b.String() + ".com"
}
