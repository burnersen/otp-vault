// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only
//
// Checks of the page, without a browser: node frontend/app_check.js
"use strict";
const fs = require("fs");
const path = require("path");
const { loadPage, check, done, dist, repo } = require("./check_harness");

const html = fs.readFileSync(path.join(dist, "index.html"), "utf8");
const js = fs.readFileSync(path.join(dist, "app.js"), "utf8");
const goFiles = fs.readdirSync(repo).filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"));
const go = goFiles.map((f) => fs.readFileSync(path.join(repo, f), "utf8")).join("\n");
const OTPV = loadPage();
const en = OTPV.TEXTS.en;
const de = OTPV.TEXTS.de;

// Both languages complete, nothing empty, no long dashes.
{
  const missingDe = Object.keys(en).filter((k) => !(k in de));
  const missingEn = Object.keys(de).filter((k) => !(k in en));
  check("German has every English text", missingDe.length === 0, missingDe);
  check("English has every German text", missingEn.length === 0, missingEn);
  const empty = [...Object.entries(en), ...Object.entries(de)].filter(([, v]) => !String(v).trim()).map(([k]) => k);
  check("no empty texts", empty.length === 0, empty);
  const dashes = [...Object.entries(en), ...Object.entries(de)].filter(([, v]) => /[–—]/.test(v)).map(([k]) => k);
  check("no long dashes in texts", dashes.length === 0, dashes);
  const sameVars = Object.keys(en).filter((k) => k in de &&
    JSON.stringify((en[k].match(/\{\w+\}|%d/g) || []).sort()) !== JSON.stringify((de[k].match(/\{\w+\}|%d/g) || []).sort()));
  check("both languages use the same placeholders", sameVars.length === 0, sameVars);
}

// Wiring: every key and id the page uses exists.
{
  const keys = [...html.matchAll(/data-i18n(?:-ph|-label)?="([^"]+)"/g), ...js.matchAll(/\bt\("([^"]+)"/g)].map((m) => m[1]);
  const unknown = [...new Set(keys)].filter((k) => !(k in en));
  check("every text key used exists", keys.length > 50 && unknown.length === 0, unknown);
  const ids = [...js.matchAll(/el\("([^"]+)"\)/g)].map((m) => m[1]);
  const missing = [...new Set(ids)].filter((id) => !html.includes(`id="${id}"`));
  check("index.html has every id the script asks for", ids.length > 50 && missing.length === 0, missing);
  const order = ["vendor/jsQR.js", "i18n.js", "app.js"].map((f) => html.indexOf(`src="${f}"`));
  check("index.html loads jsQR, i18n.js, app.js in this order", order.every((x, i) => x > 0 && (i === 0 || x > order[i - 1])), order);
  check("no inline script in index.html", !/<script>[\s\S]*?<\/script>/.test(html));
  check("no inline style or handlers in index.html (CSP)", !/\sstyle="|\son[a-z]+="/.test(html));
  check("nothing is set as HTML (names could inject code)", !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(js));
  check("the page has a Content-Security-Policy", /Content-Security-Policy/.test(html));
}

// Every method the page calls exists on App in Go.
{
  const called = [...new Set([...js.matchAll(/call\("([A-Za-z]+)"/g)].map((m) => m[1]))];
  const missing = called.filter((m) => !new RegExp(`func \\(a \\*App\\) ${m}\\(`).test(go));
  check("the page calls Go methods", called.length > 15, called);
  check("every called Go method exists", missing.length === 0, missing);
  const events = [...js.matchAll(/EventsOn\("([a-z-]+)"/g)].map((m) => m[1]);
  const unsent = events.filter((e) => !go.includes(`a.emit("${e}"`));
  check("every event the page listens to is sent by Go", unsent.length === 0, unsent);
}

// Every JSON field the page reads from settings exists in Go.
{
  const fields = [...new Set([...js.matchAll(/(?<!["\w])settings\.([a-zA-Z]+)/g)].map((m) => m[1]))];
  const missing = fields.filter((f) => !go.includes(`json:"${f}"`));
  check("every settings field the page uses exists in Go", missing.length === 0, missing);
}

// Errors from Go: the German table covers the messages, patterns work.
{
  const e = OTPV.errText("Wrong password\nCheck the password and the keyboard layout (Caps Lock, Y and Z).", "de");
  check("German error message", e.msg === "Falsches Passwort", e);
  check("German error hint", e.hint.startsWith("Prüf das Passwort"), e);
  const p = OTPV.errText("This account is in the vault already: GitHub (me)\nEdit the existing entry instead.", "de");
  check("German pattern with a value", p.msg === "Dieses Konto ist schon im Tresor: GitHub (me)", p);
  const en1 = OTPV.errText("Wrong password\nhint", "en");
  check("English stays English", en1.msg === "Wrong password" && en1.hint === "hint", en1);
  const one = OTPV.errText("Only a message", "de");
  check("message without hint", one.msg === "Only a message" && one.hint === "", one);
  // Every userError message in Go that is a fixed text has a German version.
  const msgs = [...go.matchAll(/userError\([^,]+, "([^"]+)", "([^"]*)"\)/g)].flatMap((m) => [m[1], m[2]]).filter(Boolean);
  const table = OTPV.translateLine;
  const untranslated = [...new Set(msgs)].filter((m) => table(m, "de") === m);
  check("fixed Go messages found", msgs.length > 40, msgs.length);
  check("every fixed Go message has a German text", untranslated.length === 0, untranslated);
}

// Pure helpers.
{
  check("groupCode 6", JSON.stringify(OTPV.groupCode("123456")) === '["123","456"]');
  check("groupCode 8", JSON.stringify(OTPV.groupCode("12345678")) === '["1234","5678"]');
  check("groupCode 7", JSON.stringify(OTPV.groupCode("1234567")) === '["123","4567"]');
  check("groupCode steam", JSON.stringify(OTPV.groupCode("K7X9P")) === '["K7X9P"]');
  check("ring full at the start", Math.abs(OTPV.ringOffset(30, 30)) < 1e-9);
  check("ring empty at the end", Math.abs(OTPV.ringOffset(0, 30) - 2 * Math.PI * 17) < 1e-9);
  check("strength empty", OTPV.strength("") === -1);
  check("strength short", OTPV.strength("abc") === 0);
  check("strength okay", OTPV.strength("abcdefgh") === 1);
  check("strength good", OTPV.strength("Abcdefgh1234") === 2);
  check("strength great", OTPV.strength("correct horse battery staple") === 3);
  const e = { issuer: "GitHub", account: "me@x.de", note: "", website: "github.com" };
  check("search issuer", OTPV.matches(e, "git") && OTPV.matches(e, "X.DE") && !OTPV.matches(e, "proton"));
  check("search empty matches", OTPV.matches(e, ""));
  check("avatar hue stable", OTPV.hue("github") === OTPV.hue("github") && OTPV.hue("a") !== OTPV.hue("b"));
}

done();
