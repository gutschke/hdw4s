#!/usr/bin/env node
// The tab's title on a session page (hdw4s-title.js), driven with no browser.
//
//   node .github/title-test.js [path/to/hdw4s-title.js]
//
// Prints one "ok <name>" or "FAIL <name>" per check and exits non-zero on any
// failure. The path argument exists for the red arms in tests.sh.
//
// WHAT IS REAL AND WHAT IS STOOD IN FOR: the keeper is the shipped file,
// unmodified. The document is a fake whose title is an accessor on its
// PROTOTYPE, as a browser's is -- that is the shape the keeper overrides -- and
// whose gate and body are the few calls the keeper makes. The streaming
// client is one assignment to document.title. A real browser is driven by
// .github/live/tab_title.py; this is the half that needs none.
'use strict';
const path = require('path');
const file = path.resolve(process.argv[2] ||
  path.join(__dirname, '..', 'hdw4s-title.js'));

let failed = 0;
function check(name, cond, detail) {
  if (cond) console.log('ok   ' + name);
  else { failed++; console.log('FAIL ' + name + (detail ? '  -- ' + detail : '')); }
}

const SRC = './assets/client.js';
function fakeWindow() {
  const store = {v: 'Desktop'};
  class Document {
    get title() { return store.v; }
    set title(v) { store.v = String(v); }
  }
  const gate = {hidden: true};
  const scripts = [];
  const doc = new Document();
  Object.assign(doc, {
    readyState: 'complete',
    head: {},
    documentElement: {},
    body: {getElementsByTagName: () => scripts},
    getElementById: id => (id === 'hdw4s-gate' ? gate : null),
    querySelector: () => null,
    addEventListener: () => {},
  });
  const observers = [];
  function MutationObserver(cb) { this.observe = () => {}; observers.push(cb); }
  return {
    Document, document: doc, MutationObserver,
    // What a DOM change would do: every observer runs.
    changed: () => observers.forEach(cb => cb([])),
    gate, loadClient: () => scripts.push({type: 'module', getAttribute: () => SRC}),
    raw: () => store.v,
  };
}
// Loaded once per window, because the file binds to the window it is loaded in.
function load(win) {
  delete require.cache[file];
  global.window = win;
  try { return require(file); } finally { delete global.window; }
}

const T = load(fakeWindow());

// ---- pure ------------------------------------------------------------------
check('the idle marker follows the name', T.compose('Desktop 2', true) === 'Desktop 2' + T.IDLE);
check('and is absent while connected', T.compose('Desktop 2', false) === 'Desktop 2');
check('not connected before the client is loaded', !T.connected(SRC, [], true));
check('connected once it is, with the card down', T.connected(SRC, [SRC], true));
check('not connected while the card is up', !T.connected(SRC, [SRC], false));
check('a page with no card at all goes by the client alone', T.connected(SRC, [SRC], null));
check('a manifest names the desktop', T.manifestName('{"name":"Desktop: studio"}') === 'Desktop: studio');
check('an error page names nothing', T.manifestName('<!doctype html><title>x</title>') === null);
check('nor does an empty name', T.manifestName('{"name":"  "}') === null);

// ---- the keeper, on a document -----------------------------------------------
{
  const w = fakeWindow();
  const k = load(w).install('Desktop', SRC);
  check('on its card, the tab is ours and marked idle',
    w.document.title === 'Desktop' + T.IDLE, w.document.title);
  w.loadClient(); w.changed();
  check('the client loaded, the card down: unmarked', w.document.title === 'Desktop', w.document.title);
  w.document.title = 'Selkies';
  check('a foreign write lands as ours', w.raw() === 'Desktop', w.raw());
  w.document.title = 'Something else entirely';
  check('whatever it said', w.raw() === 'Desktop', w.raw());
  w.gate.hidden = false; w.changed();
  check('the card back up after a loss: marked idle again',
    w.document.title === 'Desktop' + T.IDLE, w.document.title);
  k.name('Desktop 3');
  check('this browser renames it, and the marker stays',
    w.document.title === 'Desktop 3' + T.IDLE, w.document.title);
  w.gate.hidden = true; w.changed();
  check('and it goes when the desktop is back', w.document.title === 'Desktop 3', w.document.title);
}

process.exitCode = failed ? 1 : 0;
console.log(failed + ' failed');
