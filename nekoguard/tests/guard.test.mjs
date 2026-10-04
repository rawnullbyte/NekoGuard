// Tests for the injected clearance-renewal script.
//
// `guard.js` is a browser script with no build step, so these tests give it a
// minimal browser: a `window`, a hand-driven clock, and stubbed fetch/XHR.
// That makes the queue, the expiry arithmetic and the sleep detection
// deterministic — the parts of this feature most likely to be wrong and least
// observable from the Rust side.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));

// Which build of the script to exercise.
//
// The default is the authored source, so a failure points at readable code.
// GUARD_JS can point at the build output instead, which is how the minifier is
// checked: the same suite runs against the minified artifact, so a minification
// bug that breaks renewal fails the build rather than surfacing in production.
const SOURCE_PATH =
  process.env.GUARD_JS || join(HERE, "..", "src", "assets", "guard.js");
const SOURCE = readFileSync(SOURCE_PATH, "utf8");

if (process.env.GUARD_JS) {
  console.error(`[guard tests] using ${SOURCE_PATH} (${SOURCE.length} bytes)`);
}

// Cheap difficulty: the tests run a genuine search, just a short one.
const BITS = 8;

const START = 1_000_000;

/** A tiny browser with an explicitly driven clock and timer queue. */
function makeBrowser({
  ttl = 1800,
  solveWorks = true,
  renewalHangs = false,
  heartbeat = 30_000,
} = {}) {
  const state = {
    now: START,
    timers: [],
    nextId: 1,
    fetches: [],       // page requests that reached the network
    renewals: 0,       // /__ng/challenge calls
    verified: 0,       // /__ng/verify calls
    nativeSends: 0,    // XHRs that actually went out
    warned: [],
    target: START,     // clock time the harness is settling towards
    events: 0,         // monotonic count of observable activity
  };

  const RealDate = Date;
  const FakeDate = function (...args) {
    if (args.length === 0) return new RealDate(state.now);
    return new RealDate(...args);
  };
  FakeDate.now = () => state.now;

  const sandbox = {
    crypto: globalThis.crypto,
    TextEncoder,
    Blob: globalThis.Blob,
    Promise,
    JSON,
    Math,
    parseInt,
    Object,
    Array,
    String,
    Number,
    Error,
    Event: globalThis.Event,
    console: {
      warn: (...a) => {
        state.warned.push(a.join(" "));
        state.events++;
      },
      log() {},
    },
    Date: FakeDate,
    URL: { createObjectURL: () => "blob:stub", revokeObjectURL() {} },
    setInterval(fn, ms) {
      const id = state.nextId++;
      state.timers.push({ id, fn, ms, repeat: true, at: state.now + ms });
      return id;
    },
    clearInterval(id) {
      const at = state.timers.findIndex((t) => t.id === id);
      if (at !== -1) state.timers.splice(at, 1);
    },
    setTimeout(fn, ms) {
      const id = state.nextId++;
      state.timers.push({ id, fn, ms, repeat: false, at: state.now + ms });
      return id;
    },
    clearTimeout(id) {
      const at = state.timers.findIndex((t) => t.id === id);
      if (at !== -1) state.timers.splice(at, 1);
    },
  };

  // ---- stubbed XHR -------------------------------------------------------
  function StubXHR() {
    genuine.add(this);
    this._listeners = {};
    this.readyState = 4;
    this.status = 200;
    this.statusText = "OK";
    this.response = "";
    this.responseText = "";
    this.responseType = "";
    this.timeout = 0;
    this.upload = {};
  }
  StubXHR.prototype.open = function () {};
  StubXHR.prototype.setRequestHeader = function () {};
  StubXHR.prototype.abort = function () {};
  StubXHR.prototype.getAllResponseHeaders = function () {
    return "";
  };
  StubXHR.prototype.getResponseHeader = function () {
    return null;
  };
  StubXHR.prototype.overrideMimeType = function () {};
  StubXHR.prototype.addEventListener = function (name, fn) {
    (this._listeners[name] = this._listeners[name] || []).push(fn);
  };
  // Browsers throw when a native accessor runs with a `this` that is not a
  // *genuine* XMLHttpRequest. The check is a brand check on internal state,
  // NOT `instanceof` — an interceptor that sets
  // `Wrapper.prototype = XMLHttpRequest.prototype` makes wrapper objects pass
  // `instanceof` while the browser still throws on them. Modelling this with a
  // brand set is what makes the regression below meaningful: an
  // `instanceof`-based stub silently accepts the very wrapper that broke
  // Ghost's admin.
  const genuine = new WeakSet();
  const brandCheck = (self, member) => {
    if (!genuine.has(self)) {
      throw new TypeError(
        `'get ${member}' called on an object that does not implement interface XMLHttpRequest.`
      );
    }
  };

  StubXHR.prototype.addEventListener = function (name, fn) {
    (this._listeners[name] = this._listeners[name] || []).push(fn);
  };
  Object.defineProperty(StubXHR.prototype, "onreadystatechange", {
    configurable: true,
    get() {
      brandCheck(this, "onreadystatechange");
      return this._onreadystatechange || null;
    },
    set(v) {
      brandCheck(this, "onreadystatechange");
      this._onreadystatechange = v;
    },
  });
  StubXHR.prototype.dispatchEvent = function (e) {
    (this._listeners[e.type] || []).forEach((fn) => fn(e));
  };
  StubXHR.prototype.send = function () {
    state.nativeSends++;
    state.events++;
  };

  const nativeFetch = (url, init = {}) => {
    if (url === "/__ng/challenge") {
      state.renewals++;
      state.events++;
      if (renewalHangs) return new Promise(() => {});
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ challenge: "chal" + state.renewals, bits: BITS, ttl }),
      });
    }
    if (url === "/__ng/verify") {
      state.verified++;
      state.events++;
      if (!solveWorks) return Promise.resolve({ ok: false, status: 403 });
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ ok: true }) });
    }
    state.fetches.push({ url, init, at: state.now });
    state.events++;
    return Promise.resolve({ ok: true, status: 200, url, json: async () => ({ ok: true }) });
  };

  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.fetch = nativeFetch;
  sandbox.XMLHttpRequest = StubXHR;
  sandbox.__NG_CONFIG__ = { bits: BITS, ttl };

  const context = vm.createContext(sandbox);
  vm.runInContext(SOURCE, context, { filename: "guard.js" });

  /**
   * Yield to the host event loop until nothing observable is changing.
   *
   * A solve is a real async loop over `crypto.subtle.digest`, so promise
   * chains need genuine macrotask turns — a few `await Promise.resolve()`
   * calls are not enough, and without draining properly a later timer (the
   * queue timeout) races the renewal it is meant to wait for.
   */
  async function quiesce() {
    let idle = 0;
    for (let i = 0; i < 2000; i++) {
      const before = state.events;
      await new Promise((resolve) => setImmediate(resolve));
      if (state.events === before) {
        if (++idle >= 3) return;
      } else {
        idle = 0;
      }
    }
  }

  /**
   * Fire every timer due at or before the target — each at its own due time,
   * with promise chains drained in between, so events are ordered as they
   * would be in a real browser.
   */
  async function settle() {
    for (let guard = 0; guard < 500; guard++) {
      const due = state.timers
        .filter((timer) => timer.at <= state.target)
        .sort((a, b) => a.at - b.at)[0];
      if (!due) break;

      state.now = Math.max(state.now, due.at);
      if (due.repeat) due.at += due.ms;
      else state.timers.splice(state.timers.indexOf(due), 1);
      due.fn();
      await quiesce();
    }
    state.now = Math.max(state.now, state.target);
    await quiesce();
  }

  /** Move the clock forward, firing timers as they come due. */
  async function advance(ms) {
    state.target = Math.max(state.target, state.now) + ms;
    await settle();
  }

  /**
   * Jump the clock without firing anything: what system sleep looks like to a
   * page. A heartbeat that merely reads the clock will notice the gap.
   */
  async function sleep(ms) {
    state.now += ms;
    state.target = Math.max(state.target, state.now);
    await quiesce();
  }

  return {
    state,
    advance,
    sleep,
    settle,
    window: sandbox,
    nativeFetch,
    fetchCount: () => state.fetches.length,
    renewals: () => state.renewals,
    verified: () => state.verified,
    nativeSends: () => state.nativeSends,
  };
}

test("wraps fetch and XHR without leaking a global", async () => {
  const b = makeBrowser();

  assert.notEqual(b.window.fetch, b.nativeFetch, "fetch must be wrapped");
  assert.equal(typeof b.window.XMLHttpRequest, "function");
  assert.deepEqual(b.state.warned, []);
});

test("a fresh session lets requests straight through", async () => {
  const b = makeBrowser();
  await b.window.fetch("/ghost/api/admin/posts");
  await b.settle();
  assert.equal(b.fetchCount(), 1, "request should not have been queued");
});

test("inside the buffer window requests pass while renewal runs", async () => {
  const ttl = 1800;
  const b = makeBrowser({ ttl });

  // Open the 5-minute buffer: (ttl - 300)s after load.
  await b.advance((ttl - 300) * 1000 + 1_000);

  await b.window.fetch("/ghost/api/admin/posts");

  // The cookie is still valid, so the request must go out regardless of
  // whether the background renewal has finished.
  assert.equal(b.fetchCount(), 1, "a still-valid cookie must not block the request");
  assert.ok(b.renewals() >= 1, "renewal should run in the background");
});

test("an expired session queues the request, then releases it", async () => {
  const ttl = 1800;
  const b = makeBrowser({ ttl });

  // Lapse the session without letting the heartbeat renew first, so this
  // request genuinely arrives on a dead cookie.
  await b.sleep(ttl * 1000 + 60_000);
  const beforeRenewals = b.renewals();

  const pending = b.window.fetch("/ghost/api/admin/posts");

  // Checked before anything drains: the request must be held, not sent, and
  // it must have kicked off a renewal rather than waiting on the heartbeat.
  assert.equal(b.fetchCount(), 0, "request must be held while expired");
  assert.ok(b.renewals() > beforeRenewals, "a request on a dead cookie should kick a renewal");

  await b.advance(31_000);
  await pending;

  assert.equal(b.fetchCount(), 1, "request should be released after renewal");
});

test("renewal is single-flight", async () => {
  // ttl <= buffer, so renewal is due from the first tick.
  const b = makeBrowser({ ttl: 60 });

  const all = Promise.all([b.window.fetch("/a"), b.window.fetch("/b"), b.window.fetch("/c")]);
  await b.settle();
  await all;

  assert.equal(b.renewals(), 1, `expected a single solve, saw ${b.renewals()}`);
});

test("a TTL shorter than the buffer renews immediately", async () => {
  const b = makeBrowser({ ttl: 60 });
  await b.settle();
  assert.ok(b.renewals() >= 1, "a short TTL must not be silently ignored");
});

test("waking from system sleep renews before releasing anything", async () => {
  const ttl = 1800;
  const b = makeBrowser({ ttl });

  // Sleep far past expiry with no ticks firing.
  await b.sleep(ttl * 1000 + 10 * 60_000);

  // A request arrives immediately on wake, on the dead cookie.
  const pending = b.window.fetch("/ghost/api/admin/posts").catch(() => "released");
  assert.equal(b.fetchCount(), 0, "must not release on a lapsed cookie");

  // The first heartbeat notices the gap and renews, releasing the queue.
  await b.advance(31_000);
  await pending;

  assert.ok(b.renewals() >= 1, "wake-up must trigger renewal");
  assert.equal(b.fetchCount(), 1, "the held request should be released after renewal");
});

test("a wedged renewal releases the queue instead of hanging it", async () => {
  // TTL above the buffer, so nothing renews at load and the sleep below
  // genuinely lapses the session.
  const b = makeBrowser({ ttl: 1800, renewalHangs: true });
  await b.sleep(1800 * 1000 + 60_000);

  const pending = b.window.fetch("/ghost/api/admin/posts");
  // Handled up front: the rejection lands while the clock is being advanced.
  const outcome = pending.then(
    () => "resolved",
    (err) => err
  );
  assert.equal(b.fetchCount(), 0, "request should start out queued");

  // Past the maximum wait the request is let go, so the page's own error
  // handling runs rather than the promise hanging forever.
  await b.advance(31_000);
  const err = await outcome;
  assert.ok(err instanceof Error, `expected a failure, got ${err}`);
  assert.match(err.message, /clearance/i);
});

test("XHR objects stay genuine, with native accessors intact", async () => {
  // Regression: the interceptor used to replace window.XMLHttpRequest with a
  // wrapper, then read `self.onreadystatechange` to forward events. That read
  // reached the native getter with a `this` that was not a real XHR, the
  // browser threw, and Ghost's admin reported "Server was unreachable".
  const b = makeBrowser();

  const xhr = new b.window.XMLHttpRequest();
  assert.ok(
    xhr instanceof b.window.XMLHttpRequest,
    "constructed object must be an instance of the exposed constructor"
  );

  // Every native member must be reachable without throwing.
  assert.doesNotThrow(() => void xhr.onreadystatechange, "reading onreadystatechange");
  assert.doesNotThrow(() => {
    xhr.onreadystatechange = function () {};
  }, "assigning onreadystatechange");
  assert.doesNotThrow(() => void xhr.readyState, "reading readyState");
  assert.doesNotThrow(() => void xhr.responseType, "reading responseType");
  assert.doesNotThrow(() => void xhr.withCredentials, "reading withCredentials");
  assert.doesNotThrow(() => xhr.open("GET", "/x"), "open()");

  // And a request on a fresh session still goes straight out.
  xhr.send();
  await b.settle();
  assert.equal(b.nativeSends(), 1, "the request should reach the native send");
});

test("XHR requests are queued and released like fetch", async () => {
  const b = makeBrowser({ ttl: 1800 });
  await b.sleep(1800 * 1000 + 60_000);

  const xhr = new b.window.XMLHttpRequest();
  xhr.open("POST", "/ghost/api/admin/posts");
  xhr.send("payload");
  assert.equal(b.nativeSends(), 0, "XHR must be held while expired");

  await b.advance(31_000);
  assert.equal(b.nativeSends(), 1, "XHR should be released after renewal");
});

test("renewal traffic never goes through the queue", async () => {
  // A renewal that queued behind itself would deadlock, so it must use the
  // captured original.
  const b = makeBrowser({ ttl: 60 });
  await b.settle();
  await b.advance(31_000);
  await b.settle();

  assert.ok(b.renewals() >= 1);
  assert.equal(b.fetchCount(), 0, "renewal must not look like a page request");
});

test("the TTL is read from injected config, not a hardcoded default", async () => {
  // With a 3600s TTL, renewal must not fire at the 1800s a default config
  // would have used.
  const ttl = 3600;
  const b = makeBrowser({ ttl });

  await b.advance(1800 * 1000);
  assert.equal(b.renewals(), 0, "renewed too early for a 3600s TTL");

  // The buffer opens at (3600 - 300)s.
  await b.advance(1500 * 1000);
  assert.ok(b.renewals() >= 1, "renewal should follow the configured TTL");
});

test("a failing solve does not leave requests queued forever", async () => {
  const b = makeBrowser({ ttl: 1800, solveWorks: false });
  await b.sleep(1800 * 1000 + 60_000);

  const pending = b.window.fetch("/ghost/api/admin/posts");
  const outcome = pending.then(
    () => "resolved",
    (err) => err
  );
  await b.advance(31_000);

  // Either the failed renewal releases it, or the queue timeout does; both
  // beat hanging.
  const err = await outcome;
  assert.ok(err instanceof Error, `expected a failure, got ${err}`);
});

test("requests are not held on a valid session even under repeated ticks", async () => {
  const b = makeBrowser({ ttl: 1800 });
  for (let i = 0; i < 5; i++) {
    await b.advance(10_000);
    await b.window.fetch("/ghost/api/admin/posts");
  }
  await b.settle();
  assert.equal(b.fetchCount(), 5, "no request should have been delayed");
});
