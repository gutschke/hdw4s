#!/usr/bin/env node
// How a browser numbers its desktops (hdw4s-names.js), driven with no browser.
//
//   node .github/names-test.js [path/to/hdw4s-names.js]
//
// Prints one "ok <name>" or "FAIL <name>" per check and exits non-zero on any
// failure. The path argument exists for the red arms in tests.sh, which point
// this at a deliberately broken copy and require it to go red.
//
// WHAT IS REAL AND WHAT IS STOOD IN FOR: the allocation, decay, reconciliation
// and naming code is the shipped file, unmodified. The browser is not: storage
// is a Map behind the localStorage interface (or one that throws), and the DOM
// is the handful of calls the script makes. Nothing here shows that a page
// renders the name -- the rendered pages are looked at in a real browser.
'use strict';
const path = require('path');
const file = path.resolve(process.argv[2] ||
  path.join(__dirname, '..', 'hdw4s-names.js'));

let failed = 0;
function check(name, cond, detail) {
  if (cond) console.log('ok   ' + name);
  else { failed++; console.log('FAIL ' + name + (detail ? '  -- ' + detail : '')); }
}

function fakeWindow(storage, pathname) {
  const els = {};
  const title = {v: 'Selkies'};
  const doc = {
    head: {},
    getElementById: id => els[id] || null,
    querySelectorAll: () => [],
    get title() { return title.v; },
    set title(v) { title.v = v; },
  };
  return {
    localStorage: storage,
    location: {pathname: pathname || '/'},
    document: doc,
    setInterval: () => 0,
    MutationObserver: function () { this.observe = () => {}; },
    _els: els,
  };
}
function mapStorage() {
  const m = new Map();
  return {getItem: k => (m.has(k) ? m.get(k) : null),
          setItem: (k, v) => m.set(k, String(v)), _m: m};
}
function load(win) {
  delete require.cache[file];
  global.window = win;
  try { return require(file); } finally { delete global.window; }
}

const N = load(fakeWindow(mapStorage()));
const MIN = 60 * 1000;
const sid = i => ('0000000000000000000000000000000' + i.toString(16)).slice(-32);
const T0 = 1e12;

// ---- lowest free ----------------------------------------------------------
{
  const s = {};
  const a = N.assign(s, sid(1), T0);
  const b = N.assign(s, sid(2), T0);
  const c = N.assign(s, sid(3), T0);
  check('the first desktop is 1, then 2, then 3', a === 1 && b === 2 && c === 3,
        [a, b, c].join(','));
  check('a desktop keeps its number when asked again',
        N.assign(s, sid(2), T0 + MIN) === 2);
  // 2 goes away and fifteen minutes pass for it, while 1 and 3 stay in use.
  delete s[sid(2)];
  N.assign(s, sid(1), T0 + 20 * MIN); N.assign(s, sid(3), T0 + 20 * MIN);
  check('the LOWEST free number is taken, not the next one',
        N.assign(s, sid(4), T0 + 20 * MIN) === 2);
}

// ---- no reuse inside the window, reuse after it ---------------------------
{
  const s = {};
  N.assign(s, sid(1), T0);                     // desktop "1" is shown ...
  N.reconcile(s, [], T0 + 5 * MIN);            // ... then it ends
  check('an ended desktop keeps its number out of use for fifteen minutes',
        N.assign(s, sid(2), T0 + 5 * MIN) === 2);
  const t = {};
  N.assign(t, sid(1), T0);
  N.reconcile(t, [], T0 + 14 * MIN);
  check('still out of use at fourteen minutes',
        N.assign(t, sid(2), T0 + 14 * MIN + 59 * 1000) === 2);
  const u = {};
  N.assign(u, sid(1), T0);
  N.reconcile(u, [], T0 + 16 * MIN);
  check('and free again after fifteen, so numbers do not climb for ever',
        N.assign(u, sid(2), T0 + 16 * MIN) === 1);
  check('the ended desktop itself is forgotten once its window is over',
        !(sid(1) in u));
}

// ---- held by a live desktop, however long ago it was shown -----------------
{
  const s = {};
  N.assign(s, sid(1), T0);
  // Its tab has been closed for an hour, but the directory lists it: live.
  const live = [sid(1)];
  check('a desktop the directory lists keeps its number past the window',
        N.assign(s, sid(2), T0 + 60 * MIN, live) === 2);
  // The one case the window cannot see: a live desktop nobody has shown for an
  // hour loses its number to a new one on a page that cannot see the list...
  const t = {};
  N.assign(t, sid(1), T0);
  N.assign(t, sid(2), T0 + 60 * MIN);          // gets 1, because 1 looked unused
  // ... and the directory, which CAN see both, splits them.
  N.reconcile(t, [sid(1), sid(2)], T0 + 61 * MIN);
  check('two listed desktops never share a number',
        t[sid(1)].n !== t[sid(2)].n, t[sid(1)].n + ' vs ' + t[sid(2)].n);
  check('and the one used more recently keeps it', t[sid(2)].n === 1);
}

// ---- names ------------------------------------------------------------------
{
  const s = {};
  N.assign(s, sid(1), T0);
  check('the default name is "Desktop <n>" and never a slot', N.label(s, sid(1)) === 'Desktop 1');
  N.rename(s, sid(1), '  mail   and  <b>chat</b> ');
  check('a chosen name replaces it, spaces tidied, kept as TEXT',
        N.label(s, sid(1)) === 'mail and <b>chat</b>', N.label(s, sid(1)));
  N.rename(s, sid(1), '');
  check('an empty name goes back to the number', N.label(s, sid(1)) === 'Desktop 1');
  check('an unknown desktop is plainly "Desktop"', N.label(s, sid(9)) === 'Desktop');
  const c = N.clean({[sid(1)]: {n: 1, t: T0, name: 'x'}, 'not-a-sid': {n: 2, t: T0},
                     [sid(2)]: {n: 'two', t: T0}, [sid(3)]: {n: 3, t: T0 - 40 * 24 * 60 * MIN}},
                    T0);
  check('storage another tab could write is taken only in a sane shape',
        Object.keys(c).length === 1 && c[sid(1)].name === 'x', JSON.stringify(c));
}

// ---- the session page, through the storage it will really have -------------
{
  const st = mapStorage();
  const w = fakeWindow(st, '/s/' + sid(7) + '/');
  w._els['hdw4s-name'] = {textContent: 'Desktop'};
  const M = load(w);
  M.sessionPage('Desktop');
  check('the session page names itself on the card', w._els['hdw4s-name'].textContent === 'Desktop 1',
        w._els['hdw4s-name'].textContent);
  check('and in the tab', w.document.title === 'Desktop 1', w.document.title);
  check('and remembers it in this browser', /"n":1/.test(st.getItem(M.KEY) || ''));

  const w2 = fakeWindow(mapStorage(), '/s/' + sid(8) + '/');
  w2._els['hdw4s-name'] = {textContent: 'Template'};
  load(w2).sessionPage('Template');
  check('a name an administrator gave is left alone', w2._els['hdw4s-name'].textContent === 'Template'
        && w2.document.title === 'Selkies');

  const throwing = {getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }};
  const w3 = fakeWindow(throwing, '/s/' + sid(9) + '/');
  w3._els['hdw4s-name'] = {textContent: 'Desktop'};
  let threw = false;
  try { load(w3).sessionPage('Desktop'); } catch (e) { threw = true; }
  check('with storage refused nothing throws and the plain word stays',
        !threw && w3._els['hdw4s-name'].textContent === 'Desktop');
}

console.log(failed ? failed + ' failed' : 'all passed');
process.exit(failed ? 1 : 0);
