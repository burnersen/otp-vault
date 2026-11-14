// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only
//
// The logic of the window. Plain JavaScript: no framework, no npm, no build
// step. Go does the work and keeps the secrets (app.go); this file asks Go
// and shows what Go reports. Every value from the vault or an import is set
// with textContent, never as HTML: a name cannot inject anything.
//
// The pure parts are on window.OTPV and are checked without a browser by
// ../app_check.js.
"use strict";

(function (root) {
  const TEXTS = root.OTPV_TEXTS;
  const ERR_DE = root.OTPV_ERRORS_DE;
  const RING = 2 * Math.PI * 17; // circumference of the countdown ring

  const state = {
    lang: "en",
    settings: null,
    hasVault: false,
    unlocked: false,
    entries: [],     // EntryView from Go
    codes: {},       // id -> CodeView
    query: "",
    editing: null,   // entry being edited, null when adding
    menuFor: null,   // entry id of the open card menu
    iconFor: null,   // entry id waiting for an icon file
    importText: "",
    importFormat: "",
    preview: null,   // ImportPreview
    googleQRs: [],
    googleAt: 0,
    tickTimer: 0,
    lastTouch: 0,
    version: "",
    vaultPath: "",
  };

  // ---- pure helpers ---------------------------------------------------------

  function t(key, vars) {
    let text = (TEXTS[state.lang] || TEXTS.en)[key];
    if (text === undefined) text = TEXTS.en[key];
    if (text === undefined) return key;
    if (vars) text = text.replace(/\{(\w+)\}/g, (m, n) => (vars[n] === undefined ? m : String(vars[n])));
    return text;
  }

  function translateLine(line, lang) {
    if (lang !== "de" || !line) return line;
    if (Object.prototype.hasOwnProperty.call(ERR_DE.exact, line)) return ERR_DE.exact[line];
    for (const [re, repl] of ERR_DE.patterns) {
      if (re.test(line)) return line.replace(re, repl);
    }
    return line;
  }

  // errText splits an error from Go ("message\nhint") and translates it.
  function errText(err, lang) {
    const raw = String(err && err.message ? err.message : err === undefined || err === null ? "" : err);
    const i = raw.indexOf("\n");
    const msg = i < 0 ? raw : raw.slice(0, i);
    const hint = i < 0 ? "" : raw.slice(i + 1);
    return { msg: translateLine(msg, lang || state.lang), hint: translateLine(hint, lang || state.lang) };
  }

  // groupCode splits a code for reading: 123 456, 1234 5678, 123 4567.
  function groupCode(code) {
    if (!/^\d{6,10}$/.test(code)) return [code];
    const half = Math.floor(code.length / 2);
    return [code.slice(0, half), code.slice(half)];
  }

  function ringOffset(remaining, period) {
    if (!period) return 0;
    const left = Math.max(0, Math.min(period, remaining));
    return RING * (1 - left / period);
  }

  // strength rates a new master password: 0 weak, 1 okay, 2 good, 3 very good.
  function strength(pw) {
    if (!pw) return -1;
    const len = [...pw].length;
    let classes = 0;
    if (/[a-z]/.test(pw)) classes++;
    if (/[A-Z]/.test(pw)) classes++;
    if (/\d/.test(pw)) classes++;
    if (/[^A-Za-z0-9]/.test(pw)) classes++;
    const words = pw.trim().split(/\s+/).length;
    if (len < 8) return 0;
    if (len >= 20 || (words >= 4 && len >= 16)) return 3;
    if (len >= 14 || (len >= 12 && classes >= 3)) return 2;
    return 1;
  }

  function matches(e, q) {
    if (!q) return true;
    q = q.toLowerCase();
    return [e.issuer, e.account, e.note, e.website].some((s) => (s || "").toLowerCase().includes(q));
  }

  function hue(s) {
    let h = 0;
    for (const c of s || "?") h = (h * 31 + c.codePointAt(0)) % 360;
    return h;
  }

  function displayName(e) {
    return e.issuer || e.account || "?";
  }

  // ---- DOM helpers ----------------------------------------------------------

  function el(id) {
    return document.getElementById(id);
  }

  function make(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function svgIcon(path, extra) {
    const ns = "http://www.w3.org/2000/svg";
    const s = document.createElementNS(ns, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", path);
    s.appendChild(p);
    if (extra) extra(s, ns);
    return s;
  }

  function backend() {
    return (root.go && root.go.main && root.go.main.App) || null;
  }

  async function call(name, ...args) {
    const b = backend();
    if (!b) throw new Error("The page is not connected to otp-vault.");
    return b[name](...args);
  }

  function applyTexts() {
    document.documentElement.lang = state.lang;
    document.querySelectorAll("[data-i18n]").forEach((n) => { n.textContent = t(n.dataset.i18n); });
    document.querySelectorAll("[data-i18n-ph]").forEach((n) => { n.placeholder = t(n.dataset.i18nPh); });
    document.querySelectorAll("[data-i18n-label]").forEach((n) => {
      n.title = t(n.dataset.i18nLabel);
      n.setAttribute("aria-label", t(n.dataset.i18nLabel));
    });
    document.querySelectorAll("[data-lang]").forEach((b) => b.classList.toggle("active", b.dataset.lang === state.lang));
    el("lock-eye").textContent = el("lock-pw").type === "password" ? t("lock.show") : t("lock.hide");
    fillSelects();
    if (!el("lock-view").hidden) showLock();
    if (state.unlocked) render();
  }

  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  }

  let toastTimer = 0;
  function toast(text, bad) {
    const n = el("toast");
    n.textContent = text;
    n.classList.toggle("bad", !!bad);
    n.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { n.hidden = true; }, bad ? 6000 : 2600);
  }

  // ---- dialogs ----------------------------------------------------------------

  const DIALOGS = ["dlg-entry", "dlg-details", "dlg-import", "dlg-export", "dlg-google", "dlg-settings", "dlg-confirm", "dlg-error"];

  function openDialog(id) {
    closeMenu();
    DIALOGS.forEach((d) => { el(d).hidden = d !== id; });
    el("overlay").hidden = false;
    const first = el(id).querySelector("input:not([type=hidden]):not([type=radio]):not([type=checkbox]), textarea, select, button.primary");
    if (first) setTimeout(() => first.focus(), 30);
  }

  // wipeDialogs removes what a closed dialog must not keep: secret, link and
  // QR codes of the details and the Google export, typed passwords. With
  // all (at lock) the texts of add and import go too.
  function wipeDialogs(all) {
    el("details-secret").textContent = "";
    el("details-uri").textContent = "";
    el("details-qr").removeAttribute("src");
    el("google-qr").removeAttribute("src");
    state.googleQRs = [];
    for (const id of ["entry-secret", "export-pw", "export-pw2", "import-pw", "pw-old", "pw-new", "pw-new2"]) el(id).value = "";
    if (all) {
      el("import-text").value = "";
      el("import-list").textContent = "";
      state.importText = "";
      state.editing = null;
    }
  }

  function closeDialog() {
    el("overlay").hidden = true;
    DIALOGS.forEach((d) => { el(d).hidden = true; });
    wipeDialogs(false);
    if (state.preview) {
      state.preview = null;
      call("CancelImport").catch(() => {});
    }
  }

  function showError(err) {
    const e = errText(err);
    el("error-msg").textContent = e.msg;
    el("error-hint").textContent = e.hint;
    openDialog("dlg-error");
  }

  function setInlineError(id, err) {
    if (!err) { el(id).textContent = ""; return; }
    const e = errText(err);
    el(id).textContent = e.hint ? e.msg + "\n" + e.hint : e.msg;
  }

  let confirmResolve = null;
  function confirmDialog(title, text) {
    el("confirm-title").textContent = title;
    el("confirm-text").textContent = text;
    openDialog("dlg-confirm");
    return new Promise((resolve) => { confirmResolve = resolve; });
  }

  // ---- lock screen ------------------------------------------------------------

  function showLock() {
    el("main-view").hidden = true;
    el("lock-view").hidden = false;
    const create = !state.hasVault;
    el("lock-title").textContent = t(create ? "lock.createTitle" : "lock.unlockTitle");
    el("lock-lead").textContent = t(create ? "lock.createLead" : "lock.unlockLead");
    el("lock-submit").textContent = t(create ? "lock.create" : "lock.unlock");
    el("lock-pw2-row").hidden = !create;
    el("lock-meter").hidden = !create;
    el("lock-pw").autocomplete = create ? "new-password" : "current-password";
    el("lock-path").textContent = state.vaultPath;
    updateMeter();
  }

  function updateMeter() {
    if (state.hasVault) { el("lock-hint").textContent = ""; return; }
    const s = strength(el("lock-pw").value);
    const colors = ["#b3261e", "#d99a00", "#3a8f5c", "#1e8e5a"];
    const keys = ["lock.strengthWeak", "lock.strengthOk", "lock.strengthGood", "lock.strengthGreat"];
    el("lock-meter-bar").style.width = s < 0 ? "0" : ((s + 1) * 25) + "%";
    el("lock-meter-bar").style.background = s < 0 ? "transparent" : colors[s];
    el("lock-hint").textContent = s < 0 ? "" : t(keys[s]);
  }

  async function submitLock(ev) {
    ev.preventDefault();
    const pw = el("lock-pw").value;
    el("lock-error").textContent = "";
    if (!state.hasVault) {
      if ([...pw].length < 8) { el("lock-error").textContent = t("lock.short"); return; }
      if (pw !== el("lock-pw2").value) { el("lock-error").textContent = t("lock.mismatch"); return; }
    }
    const btn = el("lock-submit");
    btn.disabled = true;
    btn.textContent = t("lock.working");
    try {
      await call(state.hasVault ? "Unlock" : "Create", pw);
      el("lock-pw").value = "";
      el("lock-pw2").value = "";
      state.hasVault = true;
      await enterVault();
    } catch (err) {
      setInlineError("lock-error", err);
      el("lock-pw").select();
    } finally {
      btn.disabled = false;
      if (!el("lock-view").hidden) showLock();
    }
  }

  // ---- main view ----------------------------------------------------------------

  async function enterVault() {
    state.unlocked = true;
    el("lock-view").hidden = true;
    el("main-view").hidden = false;
    await loadEntries();
    el("search").focus();
  }

  function onLocked() {
    state.unlocked = false;
    state.entries = [];
    state.codes = {};
    clearTimeout(state.tickTimer);
    el("cards").textContent = "";
    closeDialog();
    wipeDialogs(true);
    closeMenu();
    showLock();
    setTimeout(() => el("lock-pw").focus(), 30);
  }

  async function loadEntries() {
    state.entries = await call("List");
    render();
    await tick();
  }

  function render() {
    const list = state.entries.filter((e) => matches(e, state.query));
    el("count-label").textContent = state.entries.length === 1 ? t("list.count1") : t("list.countN", { n: state.entries.length });
    el("empty").hidden = state.entries.length > 0;
    el("no-match").hidden = state.entries.length === 0 || list.length > 0;
    el("no-match").textContent = t("list.noMatch", { q: state.query });
    document.body.classList.toggle("hide-codes", !!(state.settings && state.settings.hideCodes));
    const cards = el("cards");
    cards.textContent = "";
    for (const e of list) cards.appendChild(card(e));
    updateCodes();
  }

  function avatar(e) {
    const a = make("div", "avatar");
    if (e.icon) {
      const img = document.createElement("img");
      img.alt = "";
      img.src = e.icon;
      img.onerror = () => { a.textContent = displayName(e).slice(0, 1).toUpperCase(); };
      a.appendChild(img);
    } else {
      a.textContent = displayName(e).slice(0, 1).toUpperCase();
      a.style.background = "hsl(" + hue(displayName(e).toLowerCase()) + " 55% 42%)";
    }
    return a;
  }

  function card(e) {
    const c = make("article", "card");
    c.dataset.id = e.id;
    const head = make("div", "card-head");
    head.appendChild(avatar(e));
    const names = make("div", "names");
    names.appendChild(make("div", "issuer", displayName(e)));
    if (e.issuer && e.account) names.appendChild(make("div", "account", e.account));
    head.appendChild(names);
    const fav = make("button", "icon-btn" + (e.favorite ? " fav-on" : ""));
    fav.type = "button";
    fav.title = t("card.favorite");
    fav.appendChild(svgIcon("m12 3 2.7 5.6 6.1.8-4.4 4.3 1 6.1L12 17l-5.4 2.8 1-6.1-4.4-4.3 6.1-.8z"));
    fav.onclick = () => toggleFavorite(e.id);
    head.appendChild(fav);
    const more = make("button", "icon-btn");
    more.type = "button";
    more.title = t("card.menu");
    more.appendChild(svgIcon("M12 6h.01M12 12h.01M12 18h.01"));
    more.onclick = (ev) => { ev.stopPropagation(); openMenu(e.id, more); };
    head.appendChild(more);
    c.appendChild(head);

    const body = make("div", "card-body");
    const code = make("button", "code");
    code.type = "button";
    code.title = t("card.copy");
    code.onclick = () => copy(e.id, false, code);
    body.appendChild(code);
    if (e.kind === "hotp") {
      const b = make("button", "hotp-btn", t("card.nextHotp"));
      b.type = "button";
      b.onclick = () => nextHOTP(e.id);
      body.appendChild(b);
    } else {
      const ring = make("div", "ring");
      ring.appendChild(svgIcon("", (s, ns) => {
        s.textContent = "";
        for (const cls of ["track", "arc"]) {
          const circ = document.createElementNS(ns, "circle");
          circ.setAttribute("cx", "21"); circ.setAttribute("cy", "21"); circ.setAttribute("r", "17");
          circ.setAttribute("class", cls);
          if (cls === "arc") circ.setAttribute("stroke-dasharray", String(RING));
          s.appendChild(circ);
        }
        s.setAttribute("viewBox", "0 0 42 42");
      }));
      ring.appendChild(make("span", "secs"));
      body.appendChild(ring);
    }
    c.appendChild(body);

    const foot = make("div", "card-foot");
    const nextWrap = make("span", "next-wrap");
    if (state.settings && state.settings.showNext) {
      nextWrap.appendChild(document.createTextNode(t("card.next") + " "));
      const nb = make("button", "next-code");
      nb.type = "button";
      nb.title = t("card.copy");
      nb.onclick = () => copy(e.id, true, nb);
      nextWrap.appendChild(nb);
    }
    foot.appendChild(nextWrap);
    const badges = make("span", "");
    if (e.kind === "hotp") badges.appendChild(make("span", "badge", t("card.counter", { n: e.counter })));
    else if (e.kind === "steam") badges.appendChild(make("span", "badge", "Steam"));
    else if (e.digits !== 6 || e.period !== 30 || e.algorithm !== "SHA1") {
      badges.appendChild(make("span", "badge", e.algorithm + " · " + e.digits + " · " + e.period + "s"));
    }
    foot.appendChild(badges);
    c.appendChild(foot);
    return c;
  }

  function fillCode(btn, code) {
    btn.textContent = "";
    const parts = groupCode(code || "");
    parts.forEach((p, i) => {
      if (i > 0) btn.appendChild(make("span", "gap"));
      btn.appendChild(document.createTextNode(p));
    });
  }

  function updateCodes() {
    document.querySelectorAll(".card").forEach((c) => {
      const v = state.codes[c.dataset.id];
      if (!v) return;
      const code = c.querySelector(".code");
      if (code.dataset.code !== v.current) {
        fillCode(code, v.current);
        code.dataset.code = v.current;
      }
      const next = c.querySelector(".next-code");
      if (next && next.textContent !== v.next) next.textContent = v.next;
      const ring = c.querySelector(".ring");
      if (ring) {
        const arc = ring.querySelector(".arc");
        const old = Number(ring.dataset.rem || 0);
        if (v.remaining > old) {
          arc.style.transition = "none"; // a new period: jump back, do not run backwards
          arc.getBoundingClientRect();
        }
        arc.style.strokeDashoffset = String(ringOffset(v.remaining - 1, v.period));
        if (v.remaining > old) requestAnimationFrame(() => { arc.style.transition = ""; });
        ring.dataset.rem = v.remaining;
        ring.querySelector(".secs").textContent = v.remaining;
        const urgent = v.remaining <= 5;
        ring.classList.toggle("urgent", urgent);
        code.classList.toggle("urgent", urgent);
      }
    });
  }

  // tick fetches the codes and always plans the next round itself. It may be
  // called at any time (after adding an entry, when the window is shown):
  // the timer is replaced, never left stopped.
  async function tick() {
    clearTimeout(state.tickTimer);
    if (!state.unlocked) return;
    try {
      const codes = await call("Codes");
      state.codes = {};
      for (const c of codes) state.codes[c.id] = c;
      updateCodes();
    } catch (err) {
      // Locked meanwhile and the "locked" event was missed: show the lock
      // screen. Anything else was a hiccup, the next round tries again.
      try {
        const st = await call("State");
        if (!st.unlocked && state.unlocked) { onLocked(); return; }
      } catch (err2) { /* next round */ }
    }
    if (state.unlocked) startTicker();
  }

  function startTicker() {
    clearTimeout(state.tickTimer);
    state.tickTimer = setTimeout(tick, 1000 - (Date.now() % 1000) + 30);
  }

  async function copy(id, next, btn) {
    try {
      const code = await call("Copy", id, next);
      btn.classList.remove("flash");
      btn.getBoundingClientRect();
      btn.classList.add("flash");
      const secs = state.settings ? state.settings.clipboardSeconds : 0;
      toast(secs > 0 ? t("toast.copiedClear", { s: secs }) : t("toast.copied", { code }));
    } catch (err) {
      showError(err);
    }
  }

  async function toggleFavorite(id) {
    try {
      replaceEntry(await call("ToggleFavorite", id));
      state.entries = await call("List");
      render();
    } catch (err) { showError(err); }
  }

  async function nextHOTP(id) {
    try {
      await call("NextHOTP", id);
      state.entries = await call("List");
      render();
      await tick();
    } catch (err) { showError(err); }
  }

  function replaceEntry(v) {
    const i = state.entries.findIndex((e) => e.id === v.id);
    if (i >= 0) state.entries[i] = v;
  }

  // ---- card menu ----------------------------------------------------------------

  function openMenu(id, anchor) {
    const m = el("card-menu");
    state.menuFor = id;
    m.hidden = false;
    const r = anchor.getBoundingClientRect();
    const w = m.offsetWidth, h = m.offsetHeight;
    m.style.left = Math.max(8, Math.min(r.right - w, root.innerWidth - w - 8)) + "px";
    m.style.top = (r.bottom + h + 8 > root.innerHeight ? Math.max(8, r.top - h - 4) : r.bottom + 4) + "px";
  }

  function closeMenu() {
    el("card-menu").hidden = true;
    state.menuFor = null;
  }

  async function menuAction(act) {
    const id = state.menuFor;
    closeMenu();
    const e = state.entries.find((x) => x.id === id);
    if (!e) return;
    try {
      switch (act) {
        case "edit": openEntry(e); break;
        case "details": await openDetails(e); break;
        case "icon":
          replaceEntry(await call("FetchIcon", id));
          render();
          break;
        case "iconFile":
          state.iconFor = id;
          el("icon-file").value = "";
          el("icon-file").click();
          break;
        case "iconRemove":
          replaceEntry(await call("SetIcon", id, ""));
          render();
          break;
        case "delete":
          if (await confirmDialog(t("confirm.delete", { name: displayName(e) }), t("confirm.deleteText"))) {
            await call("DeleteEntry", id);
            state.entries = state.entries.filter((x) => x.id !== id);
            render();
            toast(t("toast.deleted"));
          }
          break;
      }
    } catch (err) { showError(err); }
  }

  function readAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r.readAsDataURL(file);
    });
  }

  async function iconFileChosen() {
    const f = el("icon-file").files[0];
    if (!f || !state.iconFor) return;
    try {
      let url = await readAsDataURL(f);
      if (/^data:application\/octet-stream/.test(url) && /\.ico$/i.test(f.name)) url = url.replace(/^data:[^;]*/, "data:image/x-icon");
      replaceEntry(await call("SetIcon", state.iconFor, url));
      render();
    } catch (err) { showError(err); }
  }

  // ---- add and edit -------------------------------------------------------------

  function openEntry(e) {
    state.editing = e || null;
    el("entry-title").textContent = t(e ? "entry.editTitle" : "entry.addTitle");
    el("entry-save").textContent = t(e ? "entry.save" : "entry.add");
    el("entry-secret").value = "";
    el("entry-secret-hint").textContent = t(e ? "entry.secretKeep" : "entry.secretHint");
    el("entry-issuer").value = e ? e.issuer : "";
    el("entry-account").value = e ? e.account : "";
    el("entry-website").value = e ? e.website : "";
    el("entry-note").value = e ? e.note : "";
    el("entry-kind").value = e ? e.kind : "totp";
    el("entry-alg").value = e ? e.algorithm : "SHA1";
    el("entry-digits").value = String(e ? e.digits : 6);
    el("entry-period").value = String(e ? e.period : 30);
    el("entry-counter").value = String(e ? e.counter : 0);
    el("entry-adv").open = !!(e && (e.kind !== "totp" || e.digits !== 6 || e.period !== 30 || e.algorithm !== "SHA1"));
    el("entry-parsed").hidden = true;
    el("entry-error").textContent = "";
    kindChanged();
    openDialog("dlg-entry");
    el(e ? "entry-issuer" : "entry-secret").focus();
  }

  function kindChanged() {
    const k = el("entry-kind").value;
    el("entry-counter-row").hidden = k !== "hotp";
    el("entry-period-row").hidden = k === "hotp";
    el("entry-digits").disabled = k === "steam";
    el("entry-alg").disabled = k === "steam";
  }

  let parseTimer = 0;
  function secretChanged() {
    clearTimeout(parseTimer);
    parseTimer = setTimeout(parseSecret, 250);
  }

  async function parseSecret() {
    const text = el("entry-secret").value.trim();
    const note = el("entry-parsed");
    note.hidden = true;
    note.textContent = "";
    if (!text || state.editing) return;
    try {
      const p = await call("ParseInput", text);
      if (p.count > 1) {
        note.appendChild(document.createTextNode(t("entry.many", { n: p.count }) + " "));
        const b = make("button", "link", t("entry.toImport"));
        b.type = "button";
        b.onclick = () => openImport(text);
        note.appendChild(b);
        note.hidden = false;
        return;
      }
      const e = p.entry;
      const fill = (id, v) => { if (v && !el(id).value) el(id).value = v; };
      fill("entry-issuer", e.issuer);
      fill("entry-account", e.account);
      fill("entry-website", p.website);
      fill("entry-note", e.note);
      if (/^otpauth/i.test(text) || e.kind === "steam") {
        el("entry-kind").value = e.kind;
        el("entry-alg").value = e.algorithm;
        el("entry-digits").value = String(e.digits);
        el("entry-period").value = String(e.period);
        el("entry-counter").value = String(e.counter);
        kindChanged();
      }
      note.textContent = t("entry.parsed", { format: p.format });
      note.hidden = false;
      el("entry-error").textContent = "";
    } catch (err) {
      setInlineError("entry-error", err);
    }
  }

  async function saveEntry(ev) {
    ev.preventDefault();
    const input = {
      id: state.editing ? state.editing.id : "",
      kind: el("entry-kind").value,
      issuer: el("entry-issuer").value.trim(),
      account: el("entry-account").value.trim(),
      secret: el("entry-secret").value.trim(),
      algorithm: el("entry-alg").value,
      digits: Number(el("entry-digits").value) || 6,
      period: Number(el("entry-period").value) || 30,
      counter: Number(el("entry-counter").value) || 0,
      website: el("entry-website").value.trim(),
      note: el("entry-note").value.trim(),
      icon: state.editing ? state.editing.icon : "",
      favorite: state.editing ? state.editing.favorite : false,
    };
    if (!input.issuer && !input.account && !/^otpauth/i.test(input.secret)) {
      el("entry-error").textContent = t("entry.needName");
      return;
    }
    const btn = el("entry-save");
    if (btn.disabled) return; // a second Enter while the first is being saved
    btn.disabled = true;
    const editing = !!state.editing;
    try {
      const v = await call(editing ? "UpdateEntry" : "AddEntry", input);
      closeDialog();
      toast(editing ? t("toast.saved") : t("toast.added", { name: displayName(v) }));
      state.entries = await call("List");
      render();
      await tick();
    } catch (err) {
      if (el("dlg-entry").hidden) showError(err); // saved, but the list did not refresh
      else setInlineError("entry-error", err);
    } finally {
      btn.disabled = false;
    }
  }

  // ---- QR codes from images -----------------------------------------------------

  async function decodeImage(file) {
    if (typeof root.jsQR !== "function") return null;
    const bmp = await createImageBitmap(file);
    // Big screenshots are scaled down: faster, and jsQR reads them just as well.
    const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale)), h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(bmp, 0, 0, w, h);
    const data = ctx.getImageData(0, 0, w, h);
    const r = root.jsQR(data.data, w, h, { inversionAttempts: "attemptBoth" });
    return r ? r.data : null;
  }

  function isImage(file) {
    return /^image\//.test(file.type) || /\.(png|jpe?g|gif|bmp|webp)$/i.test(file.name);
  }

  function readAsText(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r.readAsText(file);
    });
  }

  // ---- import -------------------------------------------------------------------

  function openImport(text) {
    state.preview = null;
    el("import-text").value = text || "";
    el("import-error").textContent = "";
    showImportStep("input");
    openDialog("dlg-import");
    if (text) readImport();
  }

  function showImportStep(step) {
    el("import-step-input").hidden = step !== "input";
    el("import-step-password").hidden = step !== "password";
    el("import-step-preview").hidden = step !== "preview";
  }

  async function importFiles(files) {
    el("import-error").textContent = "";
    const lines = [];
    const problems = [];
    let textFile = null;
    for (const f of files) {
      try {
        if (isImage(f)) {
          const data = await decodeImage(f);
          if (data) lines.push(data);
          else problems.push(t("import.noQr", { file: f.name }));
        } else if (!textFile) {
          textFile = { name: f.name, text: await readAsText(f) };
        }
      } catch (err) {
        problems.push(t("import.badFile", { file: f.name }));
      }
    }
    if (problems.length) el("import-error").textContent = problems.join("\n");
    if (textFile && lines.length === 0) {
      state.importText = textFile.text;
      el("import-text").value = textFile.text.length < 20000 ? textFile.text : "";
      el("import-text").placeholder = textFile.name;
      await runImport(textFile.text, "");
      return;
    }
    if (lines.length) {
      const box = el("import-text");
      box.value = (box.value.trim() ? box.value.trim() + "\n" : "") + lines.join("\n");
      await readImport();
    }
  }

  async function readImport() {
    const text = el("import-text").value.trim() || state.importText;
    await runImport(text, "");
  }

  async function runImport(text, password) {
    state.importText = text;
    el("import-error").textContent = "";
    try {
      const p = await call("ImportText", text, password);
      state.importFormat = p.format;
      if (p.needsPassword) {
        el("import-pw-title").textContent = t("import.passwordTitle", { format: p.format });
        el("import-pw").value = "";
        el("import-pw-error").textContent = "";
        showImportStep("password");
        setTimeout(() => el("import-pw").focus(), 30);
        return;
      }
      el("import-pw").value = "";
      state.preview = p;
      showPreview();
    } catch (err) {
      if (password) setInlineError("import-pw-error", err);
      else setInlineError("import-error", err);
    }
  }

  function showPreview() {
    const p = state.preview;
    el("import-found").textContent = t("import.found", { n: p.items.length, format: p.format });
    const list = el("import-list");
    list.textContent = "";
    for (const it of p.items) {
      const li = make("li");
      li.dataset.index = it.index;
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = !it.duplicate && !it.problem;
      cb.disabled = !!it.problem;
      cb.onchange = () => { li.classList.toggle("off", !cb.checked); updateCommit(); };
      li.appendChild(cb);
      li.appendChild(avatar({ issuer: it.issuer, account: it.account, icon: it.icon }));
      const names = make("div", "names");
      if (it.missing) {
        const iss = document.createElement("input");
        iss.type = "text"; iss.className = "imp-issuer"; iss.placeholder = t("import.namePh");
        const acc = document.createElement("input");
        acc.type = "text"; acc.className = "imp-account"; acc.placeholder = t("import.accountPh");
        iss.oninput = acc.oninput = updateCommit;
        names.appendChild(iss);
        names.appendChild(acc);
      } else {
        names.appendChild(make("div", "issuer", it.issuer || it.account));
        if (it.issuer && it.account) names.appendChild(make("div", "account", it.account));
        else if (it.details) names.appendChild(make("div", "account", it.details));
      }
      li.appendChild(names);
      if (it.problem) li.appendChild(make("span", "tag problem", t("import.problem") + ": " + errText(it.problem).msg));
      else if (it.duplicate) li.appendChild(make("span", "tag dup", t("import.dup")));
      else if (it.missing) li.appendChild(make("span", "tag missing", t("import.missing")));
      li.classList.toggle("off", !cb.checked);
      list.appendChild(li);
    }
    el("import-commit-error").textContent = "";
    showImportStep("preview");
    updateCommit();
  }

  function importChoices() {
    return [...el("import-list").children].map((li) => {
      const iss = li.querySelector(".imp-issuer"), acc = li.querySelector(".imp-account");
      return {
        index: Number(li.dataset.index),
        include: li.querySelector("input[type=checkbox]").checked,
        issuer: iss ? iss.value.trim() : "",
        account: acc ? acc.value.trim() : "",
      };
    });
  }

  function updateCommit() {
    const n = importChoices().filter((c) => c.include).length;
    el("import-commit").textContent = t("import.take", { n });
    el("import-commit").disabled = n === 0;
  }

  async function commitImport() {
    const choices = importChoices();
    const items = state.preview ? state.preview.items : [];
    for (const c of choices) {
      const it = items.find((x) => x.index === c.index);
      if (c.include && it && it.missing && !c.issuer && !c.account) {
        el("import-commit-error").textContent = t("entry.needName");
        return;
      }
    }
    const btn = el("import-commit");
    if (btn.disabled) return;
    btn.disabled = true;
    try {
      const r = await call("CommitImport", choices);
      state.preview = null;
      closeDialog();
      toast(t("toast.imported", { n: r.added, s: r.skipped }));
      state.entries = await call("List");
      render();
      await tick();
    } catch (err) {
      if (el("dlg-import").hidden) showError(err);
      else setInlineError("import-commit-error", err);
    } finally {
      btn.disabled = false;
    }
  }

  // ---- details --------------------------------------------------------------------

  async function openDetails(e) {
    const d = await call("Details", e.id);
    el("details-name").textContent = e.issuer && e.account ? e.issuer + " · " + e.account : displayName(e);
    el("details-qr").src = d.qr;
    el("details-secret").textContent = d.secret.replace(/(.{4})/g, "$1 ").trim();
    el("details-uri").textContent = d.uri;
    el("details-copy-secret").onclick = () => copySecret(e.id, false);
    el("details-copy-uri").onclick = () => copySecret(e.id, true);
    openDialog("dlg-details");
  }

  // Go copies the secret, the same private way as a code (no clipboard
  // history, cleared after the time from the settings).
  async function copySecret(id, link) {
    try {
      await call("CopySecret", id, link);
      const secs = state.settings ? state.settings.clipboardSeconds : 0;
      toast(secs > 0 ? t("toast.copiedClear", { s: secs }) : t("details.copied"));
    } catch (err) { showError(err); }
  }

  // ---- export -----------------------------------------------------------------------

  function openExport() {
    const list = el("export-list");
    list.textContent = "";
    for (const e of state.entries) {
      const li = make("li");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = true;
      cb.value = e.id;
      cb.onchange = updateExportCount;
      li.appendChild(cb);
      li.appendChild(make("span", "", displayName(e) + (e.issuer && e.account ? " · " + e.account : "")));
      list.appendChild(li);
    }
    el("export-pw").value = "";
    el("export-pw2").value = "";
    el("export-error").textContent = "";
    exportKindChanged();
    updateExportCount();
    openDialog("dlg-export");
  }

  function exportKind() {
    const r = document.querySelector("input[name=export-kind]:checked");
    return r ? r.value : "backup";
  }

  function exportKindChanged() {
    const k = exportKind();
    el("export-pw-row").hidden = k !== "backup-pw";
    el("export-warn").hidden = !["aegis", "uris", "csv"].includes(k);
    el("export-go").textContent = k === "google" ? t("export.show") : t("export.save");
  }

  function exportIDs() {
    const boxes = [...el("export-list").querySelectorAll("input[type=checkbox]")];
    const on = boxes.filter((b) => b.checked).map((b) => b.value);
    return { ids: on.length === boxes.length ? [] : on, count: on.length, total: boxes.length };
  }

  function updateExportCount() {
    const s = exportIDs();
    el("export-count").textContent = "(" + s.count + "/" + s.total + ")";
    el("export-go").disabled = s.count === 0;
  }

  async function runExport(ev) {
    ev.preventDefault();
    const k = exportKind();
    const sel = exportIDs();
    el("export-error").textContent = "";
    if (k === "backup-pw") {
      if ([...el("export-pw").value].length < 8) { el("export-error").textContent = t("lock.short"); return; }
      if (el("export-pw").value !== el("export-pw2").value) { el("export-error").textContent = t("lock.mismatch"); return; }
    }
    try {
      if (k === "google") {
        state.googleQRs = await call("GoogleExport", sel.ids);
        state.googleAt = 0;
        showGoogle();
        openDialog("dlg-google");
        return;
      }
      const sheet = {
        title: t("sheet.title"), subtitle: t("sheet.subtitle"), account: t("sheet.account"),
        secret: t("sheet.secret"), warning: t("sheet.warning"), page: t("sheet.page"),
      };
      const path = await call("Export", { kind: k, ids: sel.ids, password: el("export-pw").value, sheet, title: t("export.saveDialog") });
      el("export-pw").value = "";
      el("export-pw2").value = "";
      if (path) {
        closeDialog();
        toast(t("toast.exported", { path }));
      }
    } catch (err) {
      setInlineError("export-error", err);
    }
  }

  function showGoogle() {
    const n = state.googleQRs.length, i = state.googleAt;
    el("google-qr").src = state.googleQRs[i] || "";
    el("google-lead").textContent = t("export.googleLead", { i: i + 1, n });
    el("google-prev").hidden = n < 2;
    el("google-next").hidden = n < 2;
    el("google-prev").disabled = i === 0;
    el("google-next").disabled = i >= n - 1;
  }

  // ---- settings ---------------------------------------------------------------------

  function fillSelects() {
    const lock = el("set-autolock"), clip = el("set-clipboard");
    const lv = lock.value, cv = clip.value;
    lock.textContent = "";
    for (const m of [1, 2, 5, 10, 15, 30, 60, 0]) {
      const o = make("option", "", m === 0 ? t("settings.never") : m === 1 ? t("settings.minute") : t("settings.minutes", { n: m }));
      o.value = String(m);
      lock.appendChild(o);
    }
    clip.textContent = "";
    for (const s of [10, 20, 30, 45, 60, 120, 0]) {
      const o = make("option", "", s === 0 ? t("settings.never") : t("settings.seconds", { n: s }));
      o.value = String(s);
      clip.appendChild(o);
    }
    if (lv) lock.value = lv;
    if (cv) clip.value = cv;
  }

  function openSettings() {
    const s = state.settings;
    el("set-theme").value = s.theme;
    el("set-autolock").value = String(s.autoLockMinutes);
    el("set-clipboard").value = String(s.clipboardSeconds);
    el("set-winlock").checked = s.lockOnWindowsLock;
    el("set-hidelock").checked = s.lockOnHide;
    el("set-hidecodes").checked = s.hideCodes;
    el("set-tray").checked = s.closeToTray;
    el("set-hidecopy").checked = s.hideAfterCopy;
    el("set-next").checked = s.showNext;
    el("set-version").textContent = t("settings.version", { v: state.version });
    el("set-path").textContent = state.vaultPath;
    el("pw-old").value = el("pw-new").value = el("pw-new2").value = "";
    el("pw-error").textContent = "";
    call("State").then((st) => { el("set-autostart").checked = st.autostart; }).catch(() => {});
    openDialog("dlg-settings");
  }

  async function saveSettings(patch) {
    const next = Object.assign({}, state.settings, patch);
    try {
      state.settings = await call("SaveSettings", next);
    } catch (err) {
      state.settings = next; // keep it for this session; the error says why it was not saved
      showError(err);
    }
    applyTheme(state.settings.theme);
    if (patch.language) {
      state.lang = state.settings.language;
      applyTexts();
    } else if (state.unlocked) {
      render();
    }
  }

  async function changePassword(ev) {
    ev.preventDefault();
    const nw = el("pw-new").value;
    el("pw-error").textContent = "";
    if ([...nw].length < 8) { el("pw-error").textContent = t("lock.short"); return; }
    if (nw !== el("pw-new2").value) { el("pw-error").textContent = t("lock.mismatch"); return; }
    try {
      await call("ChangePassword", el("pw-old").value, nw);
      el("pw-old").value = el("pw-new").value = el("pw-new2").value = "";
      toast(t("toast.pwChanged"));
    } catch (err) { setInlineError("pw-error", err); }
  }

  // ---- wiring -----------------------------------------------------------------------

  function touch() {
    const now = Date.now();
    if (state.unlocked && now - state.lastTouch > 15000) {
      state.lastTouch = now;
      call("Touch").catch(() => {});
    }
  }

  function wire() {
    el("lock-form").addEventListener("submit", submitLock);
    el("lock-pw").addEventListener("input", updateMeter);
    el("lock-eye").onclick = () => {
      const show = el("lock-pw").type === "password";
      el("lock-pw").type = el("lock-pw2").type = show ? "text" : "password";
      el("lock-eye").textContent = show ? t("lock.hide") : t("lock.show");
    };
    for (const id of ["lock-pw", "lock-pw2"]) {
      el(id).addEventListener("keyup", (ev) => {
        if (ev.getModifierState && ev.getModifierState("CapsLock")) el("lock-hint").textContent = t("lock.caps");
        else updateMeter();
      });
    }
    document.querySelectorAll("[data-lang]").forEach((b) => {
      b.onclick = () => saveSettings({ language: b.dataset.lang });
    });

    el("search").addEventListener("input", () => { state.query = el("search").value.trim(); render(); });
    el("search").addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        const first = document.querySelector(".card .code");
        if (first) first.click();
      }
    });
    el("btn-add").onclick = () => openEntry(null);
    el("empty-add").onclick = () => openEntry(null);
    el("btn-import").onclick = () => openImport("");
    el("empty-import").onclick = () => openImport("");
    el("btn-export").onclick = openExport;
    el("btn-settings").onclick = openSettings;
    el("btn-icons").onclick = () => call("FetchMissingIcons").then(() => toast(t("toast.iconsStarted"))).catch(showError);
    el("btn-lock").onclick = () => call("Lock").catch(showError);

    el("card-menu").querySelectorAll("button[data-act]").forEach((b) => { b.onclick = () => menuAction(b.dataset.act); });
    el("icon-file").addEventListener("change", iconFileChosen);
    document.addEventListener("click", (ev) => {
      if (!el("card-menu").hidden && !el("card-menu").contains(ev.target)) closeMenu();
    });

    el("dlg-entry").addEventListener("submit", saveEntry);
    el("entry-cancel").onclick = closeDialog;
    el("entry-secret").addEventListener("input", secretChanged);
    el("entry-kind").addEventListener("change", kindChanged);
    el("entry-qr").onclick = () => { el("import-file").dataset.target = "entry"; el("import-file").accept = "image/*"; el("import-file").value = ""; el("import-file").click(); };

    el("details-close").onclick = closeDialog;

    el("import-cancel").onclick = closeDialog;
    el("import-read").onclick = readImport;
    el("import-choose").onclick = () => { el("import-file").dataset.target = "import"; el("import-file").accept = ""; el("import-file").value = ""; el("import-file").click(); };
    el("import-file").addEventListener("change", async () => {
      const files = [...el("import-file").files];
      if (el("import-file").dataset.target === "entry") {
        const f = files[0];
        if (!f) return;
        const data = await decodeImage(f).catch(() => null);
        if (data) { el("entry-secret").value = data; parseSecret(); }
        else el("entry-error").textContent = t("import.noQr", { file: f.name });
        return;
      }
      importFiles(files);
    });
    el("import-step-password").addEventListener("submit", (ev) => { ev.preventDefault(); runImport(state.importText, el("import-pw").value); });
    el("import-pw-back").onclick = () => showImportStep("input");
    el("import-back").onclick = () => { state.preview = null; call("CancelImport").catch(() => {}); showImportStep("input"); };
    el("import-commit").onclick = commitImport;
    el("import-all").onclick = () => { el("import-list").querySelectorAll("li").forEach((li) => { const c = li.querySelector("input[type=checkbox]"); if (!c.disabled) { c.checked = true; li.classList.remove("off"); } }); updateCommit(); };
    el("import-none").onclick = () => { el("import-list").querySelectorAll("li").forEach((li) => { li.querySelector("input[type=checkbox]").checked = false; li.classList.add("off"); }); updateCommit(); };
    const drop = el("import-drop");
    drop.addEventListener("dragover", (ev) => { ev.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (ev) => { ev.preventDefault(); drop.classList.remove("over"); importFiles([...ev.dataTransfer.files]); });

    el("dlg-export").addEventListener("submit", runExport);
    el("export-cancel").onclick = closeDialog;
    document.querySelectorAll("input[name=export-kind]").forEach((r) => r.addEventListener("change", exportKindChanged));
    el("export-all").onclick = () => { el("export-list").querySelectorAll("input").forEach((c) => { c.checked = true; }); updateExportCount(); };
    el("export-none").onclick = () => { el("export-list").querySelectorAll("input").forEach((c) => { c.checked = false; }); updateExportCount(); };
    el("google-prev").onclick = () => { state.googleAt--; showGoogle(); };
    el("google-next").onclick = () => { state.googleAt++; showGoogle(); };
    el("google-close").onclick = closeDialog;

    el("settings-close").onclick = closeDialog;
    el("set-theme").onchange = () => saveSettings({ theme: el("set-theme").value });
    el("set-autolock").onchange = () => saveSettings({ autoLockMinutes: Number(el("set-autolock").value) });
    el("set-clipboard").onchange = () => saveSettings({ clipboardSeconds: Number(el("set-clipboard").value) });
    const boxes = { "set-winlock": "lockOnWindowsLock", "set-hidelock": "lockOnHide", "set-hidecodes": "hideCodes", "set-tray": "closeToTray", "set-hidecopy": "hideAfterCopy", "set-next": "showNext" };
    for (const [id, key] of Object.entries(boxes)) el(id).onchange = () => saveSettings({ [key]: el(id).checked });
    el("set-autostart").onchange = () => call("SetAutostart", el("set-autostart").checked).catch((err) => { el("set-autostart").checked = !el("set-autostart").checked; showError(err); });
    el("pw-form").addEventListener("submit", changePassword);
    el("set-quit").onclick = () => call("Quit").catch(showError);

    el("confirm-yes").onclick = () => { closeDialog(); if (confirmResolve) confirmResolve(true); confirmResolve = null; };
    el("confirm-no").onclick = () => { closeDialog(); if (confirmResolve) confirmResolve(false); confirmResolve = null; };
    el("error-ok").onclick = closeDialog;
    el("overlay").addEventListener("mousedown", (ev) => { if (ev.target === el("overlay")) closeDialog(); });

    document.addEventListener("keydown", (ev) => {
      touch();
      if (ev.key === "Escape") {
        if (!el("card-menu").hidden) closeMenu();
        else if (!el("overlay").hidden) closeDialog();
        else if (state.query) { el("search").value = ""; state.query = ""; render(); }
        return;
      }
      if (!state.unlocked || !el("overlay").hidden) return;
      if (ev.ctrlKey && ev.key.toLowerCase() === "f") { ev.preventDefault(); el("search").focus(); }
      if (ev.ctrlKey && ev.key.toLowerCase() === "n") { ev.preventDefault(); openEntry(null); }
      if (ev.ctrlKey && ev.key.toLowerCase() === "l") { ev.preventDefault(); call("Lock").catch(showError); }
    });
    document.addEventListener("mousemove", touch, { passive: true });
    document.addEventListener("mousedown", touch, { passive: true });

    // Paste a screenshot of a QR code anywhere: it goes to the import.
    document.addEventListener("paste", (ev) => {
      if (!state.unlocked) return;
      const files = [...(ev.clipboardData ? ev.clipboardData.files : [])].filter(isImage);
      if (!files.length) return;
      ev.preventDefault();
      if (el("dlg-import").hidden) openImport("");
      importFiles(files);
    });
    // Files dropped on the window go to the import as well.
    document.addEventListener("dragover", (ev) => { if (state.unlocked) ev.preventDefault(); });
    document.addEventListener("drop", (ev) => {
      if (!state.unlocked || ev.defaultPrevented) return;
      ev.preventDefault();
      const files = [...ev.dataTransfer.files];
      if (!files.length) return;
      if (el("dlg-import").hidden) openImport("");
      importFiles(files);
    });

    if (root.runtime && root.runtime.EventsOn) {
      root.runtime.EventsOn("locked", () => { if (state.unlocked) { onLocked(); } });
      root.runtime.EventsOn("icon", (v) => { replaceEntry(v); render(); });
      root.runtime.EventsOn("icons-done", (found, missed) => toast(t("toast.iconsDone", { found, missed })));
      root.runtime.EventsOn("shown", () => { if (state.unlocked) tick(); else el("lock-pw").focus(); });
    }
  }

  async function start() {
    wire();
    try {
      const st = await call("State");
      state.settings = st.settings;
      state.lang = st.settings.language;
      state.hasVault = st.hasVault;
      state.version = st.version;
      state.vaultPath = st.vaultPath;
      applyTheme(st.settings.theme);
      applyTexts();
      if (st.unlocked) await enterVault();
      else showLock();
      if (st.warning) toast(st.warning, true);
      call("Ready").catch(() => {});
    } catch (err) {
      applyTexts();
      showLock();
      el("lock-error").textContent = errText(err).msg;
    }
  }

  root.OTPV = { t, errText, translateLine, groupCode, ringOffset, strength, matches, hue, TEXTS, state, tick };
  if (document && document.addEventListener) document.addEventListener("DOMContentLoaded", start);
})(window);
