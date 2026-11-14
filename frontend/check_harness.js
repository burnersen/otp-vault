// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only
//
// check_harness.js runs the page's own scripts without a browser.
//
// It loads the shipped dist/i18n.js and dist/app.js, not copies: a copy would
// drift and then prove nothing. Only the pure part (window.OTPV) is checked
// here; the drawing is checked by looking at the real window.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const dist = path.join(__dirname, "dist");
const repo = path.join(__dirname, "..");

// extra: more globals for the page (timers, a stand-in for Go).
function loadPage(extra) {
  const document = { addEventListener() {}, querySelectorAll() { return []; } };
  const context = vm.createContext(Object.assign({ document, console }, extra || {}));
  context.window = context;
  for (const file of ["i18n.js", "app.js"]) {
    vm.runInContext(fs.readFileSync(path.join(dist, file), "utf8"), context, { filename: file });
  }
  return context.OTPV;
}

let failures = 0;
function check(name, ok, detail) {
  if (ok) {
    console.log("ok    " + name);
  } else {
    console.log("FAIL  " + name + (detail === undefined ? "" : "\n      " + JSON.stringify(detail)));
    failures++;
  }
}

function done() {
  if (failures > 0) {
    console.log(failures + " check(s) failed");
    process.exit(1);
  }
}

module.exports = { loadPage, check, done, dist, repo };
