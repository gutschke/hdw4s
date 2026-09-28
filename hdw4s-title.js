/* THE TAB'S TITLE ON A SESSION PAGE: always ours, and marked while idle.

   Inlined, not fetched, into the head of every session page -- named and
   pooled alike -- by hdw4s-gate-index, straight after the title element it
   rewrites.

   WHY IT IS GUARDED RATHER THAN SET. The streaming client names the tab
   itself: when it loads it writes the word "Selkies" into document.title and
   then fetches the web manifest and writes its name over that. The owner,
   2026-09-27: people who use this never otherwise see that word, do not know
   there is a distinction between it and this product, and the tab strip
   showing it confuses them. Two ways it reached the tab strip:
     - the upstream page's own title element says it, and a page held behind
       the gate never loads the client, so nothing ever replaced it. That is
       the tab a background reload leaves behind -- the owner's "idle" tab;
     - the client's own write, which stands whenever the manifest fetch that
       follows it fails (a desktop that has gone away answers it with an
       error, not a name).
   Watching for the write and undoing it leaves the word visible for a frame,
   so the property itself is overridden on this document and a write from
   anybody else lands as OUR title. The observer below is the second line, for
   a writer that goes around the property (the title element's text).

   WHERE THE NAME COMES FROM, in order: this browser's own name for a pool
   desktop (hdw4s-names.js calls name()); else the web manifest's "name", read
   HERE rather than taken from the client's write, so it is known while the
   page is still behind the gate and so no write from the client is ever
   believed; else the name the page was built with. The manifest is where an
   administrator names a named desktop (the proxy sample "hdw4s proxy" prints
   serves one), and before this file existed the client's write was
   what put that name in the tab -- swallowing the write without reading the
   manifest would have turned every named desktop into "Desktop".

   THE IDLE MARKER. Seeing the tab change told the owner something true: that
   tab was not connected. He wanted that kept, without losing the name:
   "knowing that a tab is idle is useful, but the title should stay." So the
   title is the desktop's name, plus a marker whenever this page is NOT
   showing a live desktop: before the client is loaded (a fresh tab on its
   card, and a background tab reloaded by the client's own recovery, which
   waits unseen for somebody to look) and whenever the card is up again after
   a loss. Both are read from the page as it stands -- the client's module
   script in the body, and the card's `hidden` -- so nothing here depends on
   the gate's internals, and a gate that changes how it decides still gets
   the right marker for what it shows.

   FAILS TO THE STATIC TITLE. hdw4s-gate-index writes our name into the title
   element at build time, so a browser with no script, or one where the
   override is refused, still shows our name rather than the upstream word. */
(function (root) {
  'use strict';
  var IDLE = ' (idle)';

  // Pure: what the tab should read.
  function compose(name, idle) {
    return idle ? name + IDLE : name;
  }

  // Pure: is this page showing a live desktop? MODULES is the list of module
  // script srcs in the body, GATE_HIDDEN whether the card is down (null when
  // there is no card on the page at all).
  function connected(src, modules, gateHidden) {
    return modules.indexOf(src) >= 0 && gateHidden !== false;
  }

  // Pure: the name a manifest's text offers, or null.
  function manifestName(text) {
    try {
      var m = JSON.parse(text);
      var n = m && typeof m.name === 'string' ? m.name.replace(/\s+/g, ' ').trim() : '';
      return n ? n.slice(0, 80) : null;
    } catch (e) { return null; }
  }

  function install(base, src) {
    var doc = root.document;
    var name = String(base || 'Desktop');
    var chosen = false;          // true once this browser has named the desktop
    var idle = true;
    var desc = null;
    try { desc = Object.getOwnPropertyDescriptor(root.Document.prototype, 'title'); }
    catch (e) {}
    if (!desc || !desc.get || !desc.set) desc = null;
    function read() { return desc ? desc.get.call(doc) : doc.title; }
    function write(t) { if (desc) desc.set.call(doc, t); else doc.title = t; }
    function want() { return compose(name, idle); }
    function apply() { if (read() !== want()) write(want()); }

    if (desc) {
      try {
        Object.defineProperty(doc, 'title', {
          configurable: true,
          get: function () { return read(); },
          // Anybody else's write lands as ours, whatever it said.
          set: function () { apply(); }
        });
      } catch (e) { desc = null; }
    }

    function look() {
      var mods = [];
      var body = doc.body;
      if (body) {
        var ss = body.getElementsByTagName('script');
        for (var i = 0; i < ss.length; i++) {
          if (ss[i].type === 'module') mods.push(ss[i].getAttribute('src'));
        }
      }
      var gate = doc.getElementById('hdw4s-gate');
      idle = !connected(src, mods, gate ? gate.hidden : null);
      apply();
    }

    function learn() {
      var link = doc.querySelector('link[rel~="manifest"]');
      if (!link || typeof root.fetch !== 'function') return;
      try {
        root.fetch(link.href, {credentials: 'same-origin', cache: 'no-store'})
          .then(function (r) { return r.ok ? r.text() : ''; })
          .then(function (t) {
            var n = manifestName(t);
            if (n && !chosen) { name = n; apply(); }
          }, function () {});
      } catch (e) {}
    }

    function wire() {
      look();
      learn();
      try {
        var mo = new root.MutationObserver(look);
        var head = doc.head || doc.documentElement;
        mo.observe(head, {childList: true, subtree: true, characterData: true});
        if (doc.body) mo.observe(doc.body, {childList: true});
        var gate = doc.getElementById('hdw4s-gate');
        if (gate) mo.observe(gate, {attributes: true, attributeFilter: ['hidden']});
      } catch (e) {}
    }
    apply();
    if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', wire);
    else wire();

    return {
      // This browser's own name for the desktop (hdw4s-names.js). It wins over
      // the manifest's, which for a pool desktop is only the generic word.
      name: function (n) { name = String(n); chosen = true; apply(); },
      idle: function () { return idle; }
    };
  }

  var api = {IDLE: IDLE, compose: compose, connected: connected,
             manifestName: manifestName, install: install};
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.hdw4sTitle = api;
})(typeof window !== 'undefined' ? window : this);
