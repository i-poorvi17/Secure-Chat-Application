/* Secure Chat — script.js
   Classes, async/await, Web Crypto (PBKDF2 + ECDH + AES-GCM), EventTarget-based
   mock server, weighted scam detector, safe DOM building (no innerHTML). */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const te = new TextEncoder(), td = new TextDecoder();
const b64 = {
  to: buf => btoa(String.fromCharCode(...new Uint8Array(buf))),
  from: s => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
};
const fmt = t => new Date(t).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
const h = (tag, props = {}, ...kids) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  el.append(...kids.flat().filter(Boolean));
  return el;
};

/* ---------- Crypto (real Web Crypto API) ---------- */
class CryptoService {
  static async hash(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
    const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" }, base, 256);
    return { salt: b64.to(salt), hash: b64.to(bits) };
  }
  static keyPair() { return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]); }
  static sharedKey(priv, pub) {
    return crypto.subtle.deriveKey({ name: "ECDH", public: pub }, priv, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  static async encrypt(key, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(text));
    return { iv: b64.to(iv), ct: b64.to(ct) };
  }
  static async decrypt(key, { iv, ct }) {
    return td.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.from(iv) }, key, b64.from(ct)));
  }
}

/* ---------- Weighted scam detector ---------- */
class ScamDetector {
  static THRESHOLD = 2;
  static rules = [
    [/\botp\b|one[- ]time (pass|code)/i, 3, "Asks for an OTP / verification code"],
    [/https?:\/\/\S+|bit\.ly|tinyurl|click (this|the) link/i, 2, "Contains a suspicious link"],
    [/\b(won|lottery|prize|congratulations)\b/i, 2, "Unsolicited prize language"],
    [/bank account|card number|cvv|net ?banking/i, 3, "Requests banking details"],
    [/urgent|act now|immediately|expires? (today|soon)/i, 1, "Pressures you to act fast"],
    [/gift card|crypto|send .*payment/i, 2, "Asks for gift-card / crypto payment"],
  ];
  static scan(text) {
    const hits = this.rules.filter(([re]) => re.test(text));
    const score = hits.reduce((s, [, w]) => s + w, 0);
    return { score, flagged: score >= this.THRESHOLD, reasons: hits.map(x => x[2]) };
  }
}

/* ---------- Mock backend + database ---------- */
class MockServer extends EventTarget {
  messages = [];            // ciphertext-only message table
  async relay(packet) {
    await sleep(120 + Math.random() * 250);   // simulated network latency
    this.messages.push(packet);
    this.dispatchEvent(new CustomEvent("relay", { detail: packet }));
    return packet;
  }
}
const UserDB = {
  get all() { try { return JSON.parse(localStorage.getItem("sca_users") || "{}"); } catch { return {}; } },
  set all(v) { try { localStorage.setItem("sca_users", JSON.stringify(v)); } catch { /* storage blocked */ } },
};

/* ---------- App ---------- */
class App {
  contacts = [
    { id: "rahul", name: "Rahul Verma", ini: "R", tone: "blue", status: "online" },
    { id: "lucky", name: "Lucky Draw Official", ini: "!", tone: "red", status: "unknown sender" },
  ];
  replies = ["Got it, thanks!", "Sounds good — I'll check the repo.", "Nice, that covers the demo.", "Let's sync before the review."];
  server = new MockServer();
  flags = new Map();       // message id -> scan result
  scamLog = [];
  user = null;
  active = "rahul";
  mode = "login";

  async init() {
    await this.ensureDemoUser();
    this.bind();
    this.server.addEventListener("relay", e => this.renderServerLog(e.detail));
  }

  async ensureDemoUser() {
    const users = UserDB.all;
    if (!users.poorvi) { users.poorvi = { name: "Poorvi", ...(await CryptoService.hash("demo")) }; UserDB.all = users; }
  }

  bind() {
    $("#authForm").addEventListener("submit", e => this.handleAuth(e));
    $("#switchBtn").addEventListener("click", () => this.setMode(this.mode === "login" ? "register" : "login"));
    $("#logout").addEventListener("click", () => this.logout());
    $("#composer").addEventListener("submit", e => { e.preventDefault(); this.send(); });
    $("#input").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); this.send(); } });
    $("#contacts").addEventListener("change", e => { this.active = e.target.value; this.renderAll(); });   // event delegation
  }

  setMode(mode) {
    this.mode = mode;
    const reg = mode === "register";
    $("#authForm").dataset.mode = mode;
    $("#authTitle").textContent = reg ? "Create your account" : "Welcome back";
    $("#authSub").textContent = reg ? "Sign up to send encrypted messages." : "Log in to your end-to-end encrypted inbox.";
    $("#authSubmit").textContent = reg ? "Create account" : "Sign in";
    $("#switchText").textContent = reg ? "Already registered?" : "New here?";
    $("#switchBtn").textContent = reg ? "Sign in" : "Create an account";
    $("#authError").textContent = "";
  }

  async handleAuth(e) {
    e.preventDefault();
    const f = new FormData(e.target);
    const username = f.get("username").trim().toLowerCase(), password = f.get("password");
    const users = UserDB.all, err = $("#authError");
    try {
      if (this.mode === "register") {
        if (users[username]) return void (err.textContent = "That username is taken.");
        const name = f.get("name").trim() || username;
        users[username] = { name, ...(await CryptoService.hash(password)) };
        UserDB.all = users;
        this.user = { username, name };
      } else {
        const rec = users[username];
        if (!rec) return void (err.textContent = "No account found.");
        const { hash } = await CryptoService.hash(password, b64.from(rec.salt));
        if (hash !== rec.hash) return void (err.textContent = "Incorrect password.");
        this.user = { username, name: rec.name };
      }
      await this.startSession();
    } catch (ex) {
      err.textContent = "Web Crypto unavailable — serve this folder over localhost/https (python -m http.server).";
      console.error(ex);
    }
  }

  async startSession() {
    // Fresh ECDH identity per session; one derived AES-GCM key per conversation.
    const me = await CryptoService.keyPair();
    for (const c of this.contacts) {
      const theirs = await CryptoService.keyPair();
      c.key = await CryptoService.sharedKey(me.privateKey, theirs.publicKey);
    }
    this.server.messages = []; this.flags.clear(); this.scamLog = [];
    for (const [convo, from, text] of [
      ["rahul", "rahul", "Hey! Did you push the auth module yet?"],
      ["rahul", "me", "Yep — PBKDF2 hashing and sessions work. Testing E2EE next."],
      ["rahul", "rahul", "Nice, let's demo the scam detector tomorrow."],
      ["lucky", "lucky", "Congratulations! You WON ₹50,000. Click this link bit.ly/claim and share your OTP and bank account number."],
    ]) await this.post(convo, from, text);

    $("#auth").hidden = true; $("#chat").hidden = false;
    $("#meName").textContent = this.user.name;
    $("#meAvatar").textContent = this.user.name[0].toUpperCase();
    this.renderAll();
  }

  logout() {
    this.user = null; $("#chat").hidden = true; $("#auth").hidden = false;
    $("#authForm").reset(); this.setMode("login");
  }

  /* encrypt on the sender, relay ciphertext, scan on the recipient */
  async post(convo, from, text) {
    const c = this.contacts.find(x => x.id === convo);
    const packet = { id: crypto.randomUUID(), convo, from, t: Date.now(), ...(await CryptoService.encrypt(c.key, text)) };
    await this.server.relay(packet);
    const scan = ScamDetector.scan(text);
    if (scan.flagged) {
      this.flags.set(packet.id, scan);
      this.scamLog.unshift({ ...scan, from, convo, text, t: packet.t });
    }
    return packet;
  }

  async send() {
    const box = $("#input"), text = box.value.trim();
    if (!text) return;
    box.value = "";
    await this.post(this.active, "me", text);
    this.renderAll();
    if (this.active === "rahul") {
      await sleep(900 + Math.random() * 600);
      await this.post("rahul", "rahul", this.replies[Math.floor(Math.random() * this.replies.length)]);
      this.renderAll();
    }
  }

  /* ---------- rendering (DOM built with textContent — XSS-safe) ---------- */
  renderAll() { this.renderContacts(); this.renderHeader(); this.renderMessages(); this.renderScamLog(); }

  renderContacts() {
    const flagged = new Set(this.scamLog.filter(l => l.from !== "me").map(l => l.convo));
    $("#contacts").replaceChildren(...this.contacts.map(c =>
      h("label", { class: "contact" },
        h("input", { type: "radio", name: "contact", value: c.id, checked: c.id === this.active }),
        h("span", { class: `avatar ${c.tone}` }, c.ini),
        h("span", { class: "cinfo" }, h("b", {}, c.name), h("small", {}, c.status)),
        flagged.has(c.id) && h("span", { class: "badge" }, "SCAM"))));
  }

  renderHeader() {
    const c = this.contacts.find(x => x.id === this.active);
    $("#hAvatar").className = `avatar ${c.tone}`;
    $("#hAvatar").textContent = c.ini;
    $("#hName").textContent = c.name;
    $("#hStatus").textContent = c.status;
  }

  async renderMessages() {
    const c = this.contacts.find(x => x.id === this.active);
    const rows = this.server.messages.filter(m => m.convo === c.id);
    const texts = await Promise.all(rows.map(m => CryptoService.decrypt(c.key, m)));   // client-side decrypt
    if (c.id !== this.active) return;                                                  // ignore stale renders
    const wrap = $("#messages");
    wrap.replaceChildren(...rows.map((m, i) => {
      const scan = this.flags.get(m.id);
      return h("article", { class: `msg ${m.from === "me" ? "me" : "them"}` },
        h("div", { class: `bubble${scan ? " flagged" : ""}` }, texts[i]),
        scan && h("div", { class: "flag" }, "⚠️", h("span", {}, h("b", {}, "Potential scam: "), scan.reasons.join(" · "))),
        h("div", { class: "meta" }, `🔒 ${fmt(m.t)}`),
        h("details", { class: "cipher" }, h("summary", {}, "view ciphertext"), h("code", {}, `${m.iv}.${m.ct}`)));
    }));
    wrap.scrollTop = wrap.scrollHeight;
  }

  renderServerLog(p) {
    const log = $("#serverLog");
    log.prepend(h("div", { class: "entry" }, h("b", {}, "from: "), `${p.from}\n`, h("b", {}, "to: "), `${p.convo}\n`,
      h("b", {}, "iv: "), `${p.iv}\n`, h("b", {}, "payload: "), p.ct));
  }

  renderScamLog() {
    const log = $("#scamLog");
    log.replaceChildren(...(this.scamLog.length ? this.scamLog.map(l =>
      h("div", { class: "entry danger" }, h("b", {}, "score: "), `${l.score}\n`, h("b", {}, "reasons: "), `${l.reasons.join(", ")}\n`,
        h("b", {}, "message: "), l.text)) : [h("p", { class: "muted" }, "No flags yet.")]));
  }
}

document.addEventListener("DOMContentLoaded", () => new App().init());
