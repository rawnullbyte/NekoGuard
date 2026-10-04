/* NekoGuard clearance renewal.
 *
 * The PoW clearance cookie expires after the configured session TTL. Once it
 * does, a background AJAX call comes back as the PoW interstitial — a 200
 * text/html document where the caller expected JSON — and the call fails.
 *
 * This script keeps the clearance alive and shields in-flight work:
 *   - renews in the background before expiry, on a worker so it never blocks
 *     the UI (typing in an editor must not stutter),
 *   - keeps checking while the tab is hidden, so long background tasks survive
 *   - notices system sleep and renews before releasing anything, and
 *   - queues requests only while the session is genuinely invalid, releasing
 *     them once renewal completes.
 *
 * It is injected at the end of <body>, so it wraps fetch/XHR before any page
 * script gets a chance to. Everything is inside one IIFE: no globals.
 */
(function () {
  "use strict";

  // The server renders the live values in ahead of this IIFE — the real TTL
  // from configuration, not a hardcoded copy. The literals below are only a
  // fallback for the case where that preamble is missing.
  var defaults = {
    bits: 14,
    ttl: 1800,
    renew: "/__ng/challenge",
    verify: "/__ng/verify",
    cookie: "nekoguard_session",
  };

  var cfg = {};
  for (var key in defaults) cfg[key] = defaults[key];
  var supplied = window.__NG_CONFIG__;
  if (supplied) {
    for (var k in supplied) {
      if (Object.prototype.hasOwnProperty.call(supplied, k) && supplied[k] != null) {
        cfg[k] = supplied[k];
      }
    }
  }
  try {
    delete window.__NG_CONFIG__;
  } catch (_) {}

  // How long before expiry to renew. The spec's fixed 5-minute buffer.
  var BUFFER_MS = 5 * 60 * 1000;

  // How often to re-evaluate token age. Deliberately not gated on
  // visibilitychange: a hidden tab running a long task must keep renewing.
  var HEARTBEAT_MS = 30 * 1000;

  // A request waiting for renewal is released after this long regardless, so
  // a solver that never finishes cannot hang the page forever.
  var MAX_QUEUE_WAIT_MS = 30 * 1000;

  // A tick that arrives this much later than expected means the device slept.
  var SLEEP_SLACK_MS = 2 * HEARTBEAT_MS + 5 * 1000;

  var loadedAt = Date.now();
  var solver = null;      // in-flight renewal, or null
  var queue = [];         // requests waiting on a valid session
  var lastTick = Date.now();
  var loggedFailure = false;

  /* ── Expiry ─────────────────────────────────────────────────────────────
   * The cookie is HttpOnly, so it cannot be read from here. We instead anchor
   * on the TTL the server reported: expiry = load time + ttl. That makes our
   * notion of "expired" conservative — we stop trusting the cookie at the
   * earliest moment it could have lapsed, never later, so we never release a
   * request on a cookie the server has already rejected.
   */
  function expiresAt() {
    return loadedAt + cfg.ttl * 1000;
  }

  function isExpired() {
    return Date.now() >= expiresAt();
  }

  /* Renew this far before expiry: (TTL - 5 minutes). When the TTL is shorter
   * than the buffer the deadline is already in the past, which simply means
   * "renew immediately" — no special case needed. */
  function renewDeadline() {
    return expiresAt() - Math.max(BUFFER_MS, 0);
  }

  function needsRenewal() {
    return Date.now() >= renewDeadline();
  }

  /* ── Solving ────────────────────────────────────────────────────────────
   * Same construction as `pow.rs`: SHA-256 over challenge || nonce, hex, with
   * `bits` leading zero bits. The nonce counts up from zero as a decimal
   * string, exactly as the interstitial sends it.
   */
  function meetsTarget(hash, bits) {
    var full = Math.floor(bits / 4);
    var rem = bits % 4;
    if (hash.slice(0, full) !== "0".repeat(full)) return false;
    if (rem === 0) return true;
    return parseInt(hash[full], 16) < (1 << (4 - rem));
  }

  function toHex(buf) {
    var out = "";
    var bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  var WORKER_SOURCE = [
    "self.onmessage = function (e) {",
    "  var d = e.data, nonce = 0;",
    "  var enc = new TextEncoder();",
    "  function meets(hash, bits) {",
    "    var full = Math.floor(bits / 4), rem = bits % 4;",
    "    if (hash.slice(0, full) !== '0'.repeat(full)) return false;",
    "    if (rem === 0) return true;",
    "    return parseInt(hash[full], 16) < (1 << (4 - rem));",
    "  }",
    "  function hex(buf) {",
    "    var o = '', b = new Uint8Array(buf);",
    "    for (var i = 0; i < b.length; i++) o += b[i].toString(16).padStart(2, '0');",
    "    return o;",
    "  }",
    "  (async function () {",
    "    var data = enc.encode(d.challenge);",
    "    while (true) {",
    "      if (nonce % 2000 === 0) self.postMessage({ progress: nonce });",
    "      var buf = new Uint8Array(data.length + String(nonce).length);",
    "      buf.set(data, 0);",
    "      buf.set(enc.encode(String(nonce)), data.length);",
    "      var h = hex(await crypto.subtle.digest('SHA-256', buf));",
    "      if (meets(h, d.bits)) { self.postMessage({ nonce: String(nonce) }); return; }",
    "      nonce++;",
    "    }",
    "  })();",
    "};",
  ].join("\n");

  function solveOnMainThread(challenge, bits) {
    var data = new TextEncoder().encode(challenge);
    var nonce = 0;

    return new Promise(function (resolve, reject) {
      (async function step() {
        try {
          // Yield periodically so the UI keeps painting.
          for (var i = 0; i < 2000; i++) {
            var digits = new TextEncoder().encode(String(nonce));
            var buf = new Uint8Array(data.length + digits.length);
            buf.set(data, 0);
            buf.set(digits, data.length);
            var hash = toHex(await crypto.subtle.digest("SHA-256", buf));
            if (meetsTarget(hash, bits)) return resolve(String(nonce));
            nonce++;
          }
          setTimeout(step, 0);
        } catch (err) {
          reject(err);
        }
      })();
    });
  }

  function solve(challenge, bits) {
    // Blob workers are blocked in some environments (notably a page script
    // that has locked down blob: URLs). Falling back to the main thread keeps
    // renewal working there — slower, but silent failure would be worse.
    try {
      var url = URL.createObjectURL(
        new Blob([WORKER_SOURCE], { type: "application/javascript" })
      );
      var worker = new Worker(url);

      return new Promise(function (resolve, reject) {
        var settled = false;
        worker.onmessage = function (e) {
          if (e.data && e.data.nonce !== undefined) {
            settled = true;
            worker.terminate();
            URL.revokeObjectURL(url);
            resolve(e.data.nonce);
          }
        };
        worker.onerror = function () {
          if (settled) return;
          settled = true;
          worker.terminate();
          URL.revokeObjectURL(url);
          solveOnMainThread(challenge, bits).then(resolve, reject);
        };
        worker.postMessage({ challenge: challenge, bits: bits });
      });
    } catch (err) {
      return solveOnMainThread(challenge, bits);
    }
  }

  /* ── Renewal ────────────────────────────────────────────────────────────
   * Single-flight: concurrent callers share one solve rather than each
   * starting their own.
   */
  function renew() {
    if (solver) return solver;

    solver = (async function () {
      try {
        // `nativeFetch` is the captured original, so renewal always bypasses
        // the queue — a renewal that queued behind itself would deadlock.
        if (!nativeFetch) throw new Error("fetch unavailable");

        var res = await nativeFetch(cfg.renew, {
          method: "GET",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          cache: "no-store",
        });
        if (!res.ok) throw new Error("challenge request failed: " + res.status);

        var payload = await res.json();
        if (!payload || !payload.challenge) throw new Error("no challenge in response");

        var ttl = typeof payload.ttl === "number" ? payload.ttl : cfg.ttl;
        var bits = typeof payload.bits === "number" ? payload.bits : cfg.bits;

        var nonce = await solve(payload.challenge, bits);

        var verify = await nativeFetch(cfg.verify, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ challenge: payload.challenge, nonce: nonce }),
        });
        if (!verify.ok) throw new Error("verification failed: " + verify.status);

        // The server sets the new cookie; re-anchor our window on it.
        loadedAt = Date.now();
        cfg.ttl = ttl;
        loggedFailure = false;
        release();
        return true;
      } catch (err) {
        // Keep the queue moving on failure: releasing requests lets the page's
        // own error handling run, which beats holding them forever.
        if (!loggedFailure) {
          loggedFailure = true;
          try {
            console.warn("[nekoguard] clearance renewal failed", err);
          } catch (_) {}
        }
        release(true);
        return false;
      } finally {
        solver = null;
      }
    })();

    return solver;
  }

  /* ── Queue ──────────────────────────────────────────────────────────────
   * Requests are held ONLY while the session is genuinely invalid. Inside the
   * buffer window the existing cookie is still accepted by the server, so
   * requests pass straight through while a renewal runs in the background.
   */
  function enqueue(entry) {
    queue.push(entry);
    setTimeout(function () {
      releaseOne(entry, true);
    }, MAX_QUEUE_WAIT_MS);
  }

  function releaseOne(entry, aborted) {
    var at = queue.indexOf(entry);
    if (at === -1) return;
    queue.splice(at, 1);
    if (aborted) {
      // Too long to keep waiting: let the request go and fail on its own
      // terms rather than hanging silently.
      entry.done(new Error("nekoguard: clearance not renewed in time"));
    } else {
      entry.done(null);
    }
  }

  function release(aborted) {
    var pending = queue.slice();
    for (var i = 0; i < pending.length; i++) releaseOne(pending[i], aborted);
  }

  /* Decide whether a request may proceed now, holding it if the session has
   * lapsed and renewing in the background either way.
   */
  function gate(entry) {
    // Past the buffer: renew now, but the cookie is still valid so the
    // request never waits.
    if (!isExpired()) {
      if (needsRenewal()) renew();
      entry.done(null);
      return;
    }

    // Genuinely expired: hold the request until a renewal lands.
    enqueue(entry);
    renew();
  }

  /* ── Interceptors ───────────────────────────────────────────────────────
   * Installed under the native names so renewal itself always bypasses the
   * queue — a queued renewal would deadlock.
   */
  var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  var NativeXHR = window.XMLHttpRequest;

  if (nativeFetch) {
    window.fetch = function (input, init) {
      return new Promise(function (resolve, reject) {
        gate({
          done: function (err) {
            if (err) reject(err);
            else resolve(nativeFetch(input, init));
          },
        });
      });
    };
  }

  if (NativeXHR) {
    function GuardedXHR() {
      var xhr = new NativeXHR();
      var self = this;
      var queued = null;

      // Re-expose the API surface the page expects.
      ["open", "setRequestHeader", "abort", "getAllResponseHeaders",
       "getResponseHeader", "overrideMimeType"].forEach(function (name) {
        self[name] = function () {
          return xhr[name].apply(xhr, arguments);
        };
      });

      self.send = function (body) {
        gate({
          done: function (err) {
            if (err) {
              // Surface the failure through the normal XHR events.
              xhr.dispatchEvent(new Event("error"));
              if (typeof self.onerror === "function") self.onerror(err);
              return;
            }
            xhr.send(body);
          },
        });
      };

      ["abort", "error", "load", "loadend", "loadstart", "progress",
       "readystatechange", "timeout"].forEach(function (name) {
        xhr.addEventListener(name, function (e) {
          if (typeof self["on" + name] === "function") self["on" + name](e);
        });
      });

      Object.defineProperty(self, "readyState", { get: function () { return xhr.readyState; } });
      Object.defineProperty(self, "status", { get: function () { return xhr.status; } });
      Object.defineProperty(self, "statusText", { get: function () { return xhr.statusText; } });
      Object.defineProperty(self, "response", { get: function () { return xhr.response; } });
      Object.defineProperty(self, "responseText", { get: function () { return xhr.responseText; } });
      Object.defineProperty(self, "responseType", {
        get: function () { return xhr.responseType; },
        set: function (v) { xhr.responseType = v; },
      });
      Object.defineProperty(self, "timeout", {
        get: function () { return xhr.timeout; },
        set: function (v) { xhr.timeout = v; },
      });
      Object.defineProperty(self, "upload", { get: function () { return xhr.upload; } });
      Object.defineProperty(self, "withCredentials", {
        get: function () { return xhr.withCredentials; },
        set: function (v) { xhr.withCredentials = v; },
      });
    }
    GuardedXHR.prototype = NativeXHR.prototype;
    window.XMLHttpRequest = GuardedXHR;
  }

  /* ── Heartbeat ──────────────────────────────────────────────────────────
   * Runs unconditionally: no visibility checks, so backgrounding the tab (or
   * minimizing the window) never suspends renewal.
   */
  setInterval(function () {
    var now = Date.now();
    var elapsed = now - lastTick;
    lastTick = now;

    // A tick that arrives far later than expected means the device slept or
    // the page was frozen. Anything queued stays queued: releasing it now
    // would send it out on the cookie that lapsed during sleep — the exact
    // failure this script exists to prevent. Renew instead; the renewal
    // releases the queue when it lands.
    if (elapsed > SLEEP_SLACK_MS) {
      if (isExpired() || needsRenewal()) renew();
      return;
    }

    if (isExpired()) {
      renew();
    } else if (needsRenewal()) {
      renew();
    }
  }, HEARTBEAT_MS);

  // Nothing to renew until a session exists; the interstitial page never
  // loads this script. Kick once in case the page was restored from the
  // back/forward cache long after the cookie lapsed.
  if (needsRenewal()) renew();
})();
