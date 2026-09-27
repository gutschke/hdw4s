/* A desktop's name, as THIS BROWSER calls it.

   Inlined, not fetched: hdw4s-gate-index writes it into every pool slot's session
   page at build time, and hdw4s-demux reads it once at start and writes it into
   the pages it renders itself (the directory, the ended page, the refusal). One
   file, two readers, so the rule below has one home.

   WHY THE BROWSER AND NOT THE SERVER. A pool desktop used to be named after its
   SLOT -- "19 . Desktop" -- and the slot is reused. Three novices of three read
   the number as an identity: one got "19" again straight after the ended page
   said the old desktop's contents were destroyed, and stopped believing it.
   The owner's ruling, 2026-09-27: a small per-browser id, the lowest one this
   browser is not using and has not used in the last fifteen minutes, so a
   number never outlives its meaning by less than that and never grows without
   bound; plus an optional name of the visitor's own. Both live here, in this
   origin's localStorage, and the server never sees either.

   THE STORE, and it is deliberately tiny and quadratic: one key, a map from
   session id to {n: id, t: last used (ms), name: optional}. "Last used" is when
   a page last SHOWED that desktop: its own tab touches it every minute while it
   is open, and the directory touches every row it lists. Nobody has hundreds of
   desktops, so every lookup is a scan.

   WHAT "HELD" MEANS, because the page cannot see the server: an id is taken if
   another entry used it within the window, or if the directory -- the one page
   that knows this browser's live desktops -- lists that entry. A live desktop
   whose tab was closed long ago can therefore lose its id to a new one; the
   directory is where that would be SEEN, so the directory is where it is
   repaired (the more recently used of the two keeps the number).

   FAILS TO THE PLAIN WORD. Every storage access is in a try; a private window,
   blocked storage or a full quota leaves the server's own label ("Desktop"),
   which is what a page with no script shows too. Names are inserted with
   textContent, never markup: a name is text a person typed. */
(function (root) {
  'use strict';
  var KEY = 'hdw4s_desktop_names';
  var WINDOW_MS = 15 * 60 * 1000;           // the owner's fifteen minutes
  var FORGET_MS = 30 * 24 * 3600 * 1000;    // an entry nobody showed for a month
  var TOUCH_MS = 60 * 1000;
  var PLAIN = 'Desktop';
  var SID = /^[0-9a-f]{8,64}$/;

  function valid(e) {
    return e && typeof e === 'object' && typeof e.n === 'number' &&
      isFinite(e.n) && e.n >= 1 && e.n === Math.floor(e.n) &&
      typeof e.t === 'number' && isFinite(e.t);
  }

  // Everything below here up to the DOM half is pure: a store in, a store out.
  // That is what the tests drive.
  function clean(store, now) {
    var out = {};
    for (var sid in store) {
      if (!Object.prototype.hasOwnProperty.call(store, sid)) continue;
      var e = store[sid];
      if (!SID.test(sid) || !valid(e) || now - e.t >= FORGET_MS) continue;
      out[sid] = {n: e.n, t: e.t};
      if (typeof e.name === 'string' && e.name) out[sid].name = e.name.slice(0, 60);
    }
    return out;
  }

  function taken(store, sid, now, live) {
    var ids = {};
    for (var x in store) {
      if (x === sid) continue;
      var e = store[x];
      if (now - e.t < WINDOW_MS || (live && live.indexOf(x) >= 0)) ids[e.n] = true;
    }
    return ids;
  }

  function lowestFree(ids) {
    var n = 1;
    while (ids[n]) n++;
    return n;
  }

  // The id for SID, allocating one if it has none, and marking it used NOW.
  function assign(store, sid, now, live) {
    if (!store[sid]) store[sid] = {n: lowestFree(taken(store, sid, now, live)), t: now};
    store[sid].t = now;
    return store[sid].n;
  }

  // The directory's pass: LIVE is every desktop this browser has, in page order.
  // An entry not listed is not running; it keeps its place until its fifteen
  // minutes are up, so the number is not handed straight to the next desktop.
  // Two listed desktops on one number (possible only through a long-closed tab,
  // above) are split here, and the one used more recently keeps it.
  function reconcile(store, live, now) {
    for (var x in store) {
      if (live.indexOf(x) < 0 && now - store[x].t >= WINDOW_MS) delete store[x];
    }
    var order = live.filter(function (s) { return store[s]; });
    order.sort(function (a, b) { return store[b].t - store[a].t; });
    var seen = {};
    order.forEach(function (s) {
      if (seen[store[s].n]) {
        var name = store[s].name;
        delete store[s];
        assign(store, s, now, live);
        if (name) store[s].name = name;
      }
      seen[store[s].n] = true;
    });
    live.forEach(function (s) { assign(store, s, now, live); });
    return store;
  }

  function label(store, sid) {
    var e = store[sid];
    if (!e) return PLAIN;
    return e.name || (PLAIN + ' ' + e.n);
  }

  function rename(store, sid, text) {
    if (!store[sid]) return store;
    var t = String(text == null ? '' : text).replace(/\s+/g, ' ').trim().slice(0, 60);
    if (t && t !== PLAIN + ' ' + store[sid].n) store[sid].name = t;
    else delete store[sid].name;
    return store;
  }

  // ---- storage, every touch of it guarded ----------------------------------
  function load(ls, now) {
    try {
      var v = JSON.parse(ls.getItem(KEY) || '{}');
      if (!v || typeof v !== 'object' || Array.isArray(v)) v = {};
      return clean(v, now);
    } catch (e) { return null; }
  }
  function save(ls, store) {
    try { ls.setItem(KEY, JSON.stringify(store)); return true; } catch (e) { return false; }
  }
  function storage() {
    try { return root.localStorage || null; } catch (e) { return null; }
  }

  // One read-modify-write, so two tabs interleave at worst by one step. A
  // throw anywhere answers null, and the caller leaves the plain word.
  function update(fn) {
    var ls = storage();
    if (!ls) return null;
    var now = Date.now();
    var store = load(ls, now);
    if (!store) return null;
    var r = fn(store, now);
    return save(ls, store) ? r : null;
  }

  // ---- the session page ----------------------------------------------------
  // BAKED is the name the page was built with. Only the pool's generic word is
  // replaced; anything else is an administrator's name and is left alone.
  function sessionPage(baked) {
    if (baked !== PLAIN) return;
    var m = /^\/s\/([0-9a-f]+)\//.exec(root.location.pathname);
    if (!m || !SID.test(m[1])) return;
    var sid = m[1];
    var mine = function () {
      return update(function (store, now) { assign(store, sid, now); return label(store, sid); });
    };
    var name = mine();
    if (!name) return;
    var h = root.document.getElementById('hdw4s-name');
    if (h) h.textContent = name;
    root.document.title = name;
    // The streaming client sets the title from its manifest once it loads, and
    // the manifest can only carry the generic word. Put ours back when THAT is
    // what it wrote, and only then: any other title is somebody else's to set.
    try {
      var head = root.document.head || root.document.documentElement;
      new root.MutationObserver(function () {
        if (root.document.title === baked) root.document.title = name;
      }).observe(head, {childList: true, subtree: true, characterData: true});
    } catch (e) {}
    // Keeps this desktop's number "in use" for as long as a tab shows it.
    root.setInterval(function () {
      var n = mine();
      if (n && n !== name) {
        name = n;
        root.document.title = name;
        if (h) h.textContent = name;
      }
    }, TOUCH_MS);
  }

  // ---- the router's pages ----------------------------------------------------
  // Every element carrying data-hdw4s-sid is one of this browser's live desktops,
  // and a page that calls this lists ALL of them.
  function directory() {
    var doc = root.document;
    var els = Array.prototype.slice.call(doc.querySelectorAll('[data-hdw4s-sid]'));
    var live = els.map(function (el) { return el.getAttribute('data-hdw4s-sid'); })
                  .filter(function (s) { return SID.test(s); });
    var store = update(function (store, now) { reconcile(store, live, now); return store; });
    if (!store) return;
    els.forEach(function (el) {
      var sid = el.getAttribute('data-hdw4s-sid');
      if (!store[sid]) return;
      el.textContent = label(store, sid);
      el.title = 'Rename';
      el.classList.add('renamable');
      el.tabIndex = 0;
      el.addEventListener('click', function () { edit(el, sid); });
      el.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' && ev.target === el) { ev.preventDefault(); edit(el, sid); }
      });
    });
  }

  // RENAMING IS OFFERED, NEVER ASKED FOR. The name itself is the control: a
  // click turns it into a field, Enter or leaving it keeps the text, Escape
  // abandons it, and an empty field goes back to the number. No dialog, no
  // prompt, no button that competes with Resume.
  function edit(el, sid) {
    if (el.querySelector('input')) return;
    var before = el.textContent;
    var input = root.document.createElement('input');
    input.type = 'text';
    input.maxLength = 60;
    input.value = before;
    input.setAttribute('aria-label', 'Name for this desktop');
    el.textContent = '';
    el.appendChild(input);
    input.focus();
    input.select();
    var done = false;
    function finish(keep, refocus) {
      if (done) return;
      done = true;
      var shown = before;
      if (keep) {
        var s = update(function (store) { rename(store, sid, input.value); return store; });
        if (s && s[sid]) shown = label(s, sid);
      }
      el.textContent = shown;
      if (refocus) el.focus();
    }
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') { ev.preventDefault(); finish(true, true); }
      else if (ev.key === 'Escape') { ev.preventDefault(); finish(false, true); }
    });
    input.addEventListener('blur', function () { finish(true); });
    input.addEventListener('click', function (ev) { ev.stopPropagation(); });
  }

  var api = {KEY: KEY, WINDOW_MS: WINDOW_MS, PLAIN: PLAIN,
             clean: clean, assign: assign, reconcile: reconcile,
             label: label, rename: rename,
             sessionPage: sessionPage, directory: directory};
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.hdw4sNames = api;
})(typeof window !== 'undefined' ? window : this);
