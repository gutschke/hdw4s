#!/usr/bin/python3
"""Exercise hdw4s-demux against stand-in slots, in both directions.

Every check here is run twice: once expecting green, and once with the thing it
guards deliberately broken, expecting red. A check that has never rejected
anything is not known to reject anything -- and a guard that refuses everything
would also look green, so the permit arm is not optional either.

WHAT IS REAL AND WHAT IS STOOD IN FOR, said here rather than left to be
inferred. Real: hdw4s-demux itself, unmodified, over a real TCP socket, with
real HTTP, real cookies and real UNIX-socket upstreams. Stood in for: the
sessions. The backends are small HTTP servers that report which slot they are.
There is NO BROWSER in this file and no picture is decoded, so nothing here is
evidence that a desktop renders -- only that arrival, identity and routing are
right. journey.py and isolation.py are what see a picture.

THE ARM THAT MATTERS MOST is test_pooled_connection. A stand-in reverse proxy at
its defaults opens a fresh upstream connection per request and does not
reproduce the cross-session defect at all, so a router tested only that way
passes while the defect is live. Here the two requests are deliberately sent
down ONE connection.
"""

import base64
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEMUX = os.path.join(os.path.dirname(os.path.dirname(HERE)), "hdw4s-demux")

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print("%-6s %s%s" % ("PASS" if ok else "FAIL", name,
                         ("  -- " + detail) if detail and not ok else ""))


def expect_red(name, fn):
    """Run something that MUST fail. Green here means the guard is asleep."""
    try:
        fn()
    except AssertionError:
        check(name + " [red arm]", True)
        return
    except Exception as e:
        check(name + " [red arm]", False, "failed for the wrong reason: %r" % e)
        return
    check(name + " [red arm]", False,
          "the guard PASSED something it must reject -- it is not a guard")


# --------------------------------------------------------------------------
# Stand-in slots
# --------------------------------------------------------------------------

class Slot(threading.Thread):
    """A backend that says which slot it is, so a mis-route is visible."""

    def __init__(self, path, name, rundir):
        super().__init__(daemon=True)
        self.name = name
        self.path = path
        # THE OCCUPANCY AUTHORITY, and it is the session's, not ours.
        #
        # /run/hdw4s/<instance> is the session unit's own RuntimeDirectory: it
        # exists exactly while that session is up and systemd removes it when
        # the unit stops. Until this existed here, an occupied slot and a free
        # one were BYTE-IDENTICAL in this rig -- bare sockets in a tmpdir with
        # no session runtime tree anywhere -- so the only thing a router could
        # have consulted to tell them apart was its own memory, and the only
        # implementation that could pass the restart arm was a table persisted
        # under HDW4S_DEMUX_STATE. That table survives restart() here and is
        # deleted by RuntimeDirectory= on the box, which is green in CI and
        # broken in the field, and arm 4 of this very file documents the wipe.
        #
        # Derived the way the CLI derives it -- HDW4S_RUNDIR, default /run,
        # then hdw4s/<instance> -- rather than spelled out again, because two
        # spellings of one path are two paths the moment either is edited.
        # IT DOES NOT EXIST YET, and that is the point rather than an
        # oversight. The pool is minted at boot by hdw4s-ephemeral-slots and
        # the sessions are SOCKET-ACTIVATED, so a slot that nobody has opened
        # has a listening socket and no session: no unit, and therefore no
        # RuntimeDirectory. It appears when the session actually starts, which
        # is on the first connection, so serve() below creates it and reap()
        # removes it. Creating it here instead -- which is what this did
        # first -- would have made every slot look occupied from birth, and an
        # honest router reading this authority would have refused the very
        # first visitor. A stand-in that is wrong in that direction fails
        # loudly, which is the only reason it was caught in one run.
        self.rundir = rundir
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.bind(path)
        self.s.listen(16)
        self.stop = False
        # Set by the test that checks a session cannot rewrite its visitor's
        # identity. A backend is the untrusted side here; it must not be able to
        # reach the cookie the router owns.
        self.forge_cookie = None
        # Set when this slot has actually served something. The oracle for "did
        # the router start a desktop" is the SLOT saying it was used, not the
        # router's own account of itself -- a component is not evidence about
        # its own behaviour.
        self.seen = False

    def reap(self):
        """Stand in for the sweep stopping this desktop -- READ THE LIMIT.

        WHAT IT REPRODUCES: the slot's name stays in available_slots() and its
        desktop is gone. Unlinking the path instead would make the slot vanish
        from the pool and would quietly test a different, easier world -- one
        where exhaustion cures itself because the directory shrank.

        WHAT IT DOES NOT REPRODUCE, found by reading the shipped units and NOT
        yet observed on a box, so treat the severity as an upper bound:
        `hdw4s reap` stops hdw4s-proxy@<inst>.service and the session unit and
        does NOT stop hdw4s-proxy@<inst>.socket. That socket unit keeps
        listening, so in the field a connect after a reap SUCCEEDS and
        re-activates the relay, whose ExecStartPre=hdw4s-wait then waits for a
        session that is not coming and fails into OnFailure=hdw4s-refuse@. A
        reaped visitor there does not meet a refused connection at all; they
        meet a long stall and then somebody else's page.

        This stand-in refuses instead, which is the faster and more legible of
        the two and drives the arms deterministically. That difference is load
        bearing for arm 3 and NOT for arm 2 -- the table is monotonic whatever
        the socket does -- and each arm says which it is relying on.

        It also removes the session's RuntimeDirectory, which is what systemd
        does when the unit stops and is the only thing here that tells an
        occupied slot from a free one. Checked BOTH WAYS below rather than
        assumed: present before, absent after. A reap that silently frees
        something which was never occupied would make every arm that turns on
        occupancy pass without ever having expressed the case -- absence of the
        authority reading identically to absence of an occupant, which is the
        empty result this project does not accept as a negative.


        Closing the listener ALONE is not enough and the first version of this
        did exactly that. A close from this thread does not interrupt the
        accept() already blocked in the serving thread, so for a few
        milliseconds afterwards a connect() still lands in the backlog and is
        served -- measured: a probe connected successfully to a slot this had
        just "reaped", and the test that depended on it passed against a defect
        that is really there. So the path is rebound to a socket that is bound
        and NOT listening, which refuses deterministically, and this does not
        return until it has WATCHED a connect() be refused. A stand-in whose
        effect is a race is worse than no stand-in: it produces a green.
        """
        assert os.path.isdir(self.rundir), (
            "%s had no runtime directory to free, so this reap proves nothing "
            "about occupancy" % self.name)
        import shutil
        shutil.rmtree(self.rundir)
        assert not os.path.exists(self.rundir), \
            "%s still looks occupied after being reaped" % self.name
        self.stop = True
        try:
            self.s.close()
        except OSError:
            pass
        try:
            os.unlink(self.path)
        except OSError:
            pass
        self.dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.dead.bind(self.path)      # bound, never listen()ed
        for _ in range(100):
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(2)
            try:
                probe.connect(self.path)
            except OSError:
                probe.close()
                return
            probe.close()
            time.sleep(0.02)
        raise AssertionError(
            "%s still accepts connections after being reaped -- the stand-in "
            "for the sweep does not work, so nothing that depends on it is "
            "evidence" % self.name)

    def run(self):
        while not self.stop:
            try:
                c, _ = self.s.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        f = c.makefile("rb")
        try:
            while True:
                line = f.readline()
                if not line:
                    return
                # MARKED HERE, ON A REQUEST, AND NOT ON THE ACCEPT.
                #
                # Both of these used to be set the moment a connection was
                # accepted, and the router OPENS ONE AT STARTUP to report
                # reachability. So every slot was marked served before any
                # visitor existed: the runtime directory sprang into being for
                # all three, an honest router reading it refused the very first
                # arrival with 503, and slots_in_use() answered "all of them"
                # to every caller -- which is why the arm that counts desktops
                # started by a returning tab compared 3 against 3 and could not
                # have failed.
                #
                # The authority must not be created by the act of observing it.
                # That is the property it was chosen for, and a stand-in that
                # loses it is worse than none, because the loss shows up as a
                # confident number rather than as an error.
                self.seen = True
                try:
                    os.makedirs(self.rundir, mode=0o700, exist_ok=True)
                except OSError:
                    pass
                while True:
                    h = f.readline()
                    if h in (b"\r\n", b"\n", b""):
                        break
                body = ("SLOT=%s PATH=%s" % (self.name,
                        line.split()[1].decode())).encode()
                forged = (b"Set-Cookie: " + self.forge_cookie.encode() + b"\r\n"
                          if self.forge_cookie else b"")
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                          b"Content-Type: text/plain\r\n%s\r\n%s"
                          % (len(body), forged, body))
        except OSError:
            pass
        finally:
            c.close()


# --------------------------------------------------------------------------
# A client that can be told to reuse one connection
# --------------------------------------------------------------------------

class Client:
    def __init__(self, port, cred, cookie=None):
        self.port = port
        self.auth = base64.b64encode(cred.encode()).decode() if cred else None
        self.cookie = cookie
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection(("127.0.0.1", self.port), 10)
        self.sock.settimeout(10)
        self.rf = self.sock.makefile("rb")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def get(self, path, keep=False, auth=True, cookie_override=-1):
        """Return (status, headers dict, body). keep=True reuses the socket."""
        if self.sock is None:
            self.connect()
        cookie = self.cookie if cookie_override == -1 else cookie_override
        req = ["GET %s HTTP/1.1" % path, "Host: demux.test"]
        if self.auth and auth:
            req.append("Authorization: Basic " + self.auth)
        if cookie:
            req.append("Cookie: hdw4s_id=" + cookie)
        req.append("Connection: keep-alive" if keep else "Connection: keep-alive")
        self.sock.sendall(("\r\n".join(req) + "\r\n\r\n").encode())

        status = int(self.rf.readline().split()[1])
        headers = {}
        while True:
            line = self.rf.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            k, _, v = line.decode("latin-1").partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
        n = int(headers.get("content-length", ["0"])[0])
        body = self.rf.read(n) if n else b""
        if not keep:
            self.close()
        return status, headers, body

    def learn_cookie(self, headers):
        for sc in headers.get("set-cookie", []):
            if sc.startswith("hdw4s_id="):
                self.cookie = sc.split("=", 1)[1].split(";")[0]
        return self.cookie


# --------------------------------------------------------------------------
# Rig
# --------------------------------------------------------------------------

class Rig:
    def __init__(self, nslots=3, gate="mint", windows=None):
        # gate=None means DO NOT SET HDW4S_GATE_MODE, so the module's own default
        # applies. Without this every arm test pinned the mode explicitly and the
        # shipped default was never exercised -- which is exactly how the router
        # and the page came to disagree about it while a test named
        # "default_gate" passed.
        self.tmp = tempfile.mkdtemp(prefix="demux-test-")
        self.rundir = os.path.join(self.tmp, "proxy")
        self.etc = os.path.join(self.tmp, "etc")
        os.makedirs(self.rundir)
        os.makedirs(self.etc)
        self.cred = "front:secretpw"
        with open(os.path.join(self.etc, "demux.auth.cred"), "w") as f:
            f.write(self.cred)
        # Where the periodic sweep would keep its record. Real here, and empty:
        # the point of the refusal log is partly that it reports what it could
        # NOT read, so a rig that always has a readable stamp would never show
        # that column working.
        self.reapdir = os.path.join(self.tmp, "reap")
        os.makedirs(self.reapdir)
        # The pool table the CLI keeps, and the idle window each slot is
        # configured with. Written before the router starts, because the
        # lifetime it derives from them is pinned at start.
        self.windows = windows
        if windows is not None:
            with open(os.path.join(self.etc, "instances"), "w") as f:
                for i, (name, _) in enumerate(windows):
                    f.write("%d %s ephemeral\n" % (i, name))
            # "%s", NOT "%d", and this is the fixture that let the defect ship.
            # An integer format specifier cannot put "30d", "12h" or "90m" in
            # front of the router -- the only forms that reproduced the failure
            # -- so the whole tier was structurally incapable of expressing the
            # input that breaks it. Every green here was a green about integers.
            # A window is written EXACTLY as an administrator would write it.
            for name, days in windows:
                with open(os.path.join(self.etc, name + ".conf"), "w") as f:
                    f.write("HDW4S_IDLE_DAYS=%s\n" % (days,))
        # HDW4S_RUNDIR is what the CLI already reads, default /run. The
        # sessions' runtime directories hang off it at hdw4s/<instance>.
        self.hdw4s_rundir = os.path.join(self.tmp, "run")
        os.makedirs(os.path.join(self.hdw4s_rundir, "hdw4s"))
        self.slots = []
        for i in range(nslots):
            name = "ephemeral%d" % i
            s = Slot(os.path.join(self.rundir, name + ".sock"), name,
                     os.path.join(self.hdw4s_rundir, "hdw4s", name))
            s.start()
            self.slots.append(s)
        self.port = self.free_port()
        self.env = dict(os.environ,
                   HDW4S_PROXY_RUNDIR=self.rundir,
                   HDW4S_RUNDIR=self.hdw4s_rundir,
                   HDW4S_ETCDIR=self.etc,
                   HDW4S_DEMUX_CRED=os.path.join(self.etc, "demux.auth.cred"),
                   HDW4S_DEMUX_STATE=os.path.join(self.tmp, "state"),
                   HDW4S_REAP_STAMP_DIR=self.reapdir,
                   HDW4S_DEMUX_BIND="127.0.0.1",
                   HDW4S_DEMUX_PORT=str(self.port),
                   **({"HDW4S_GATE_MODE": gate} if gate is not None else {}))
        for k in ("LISTEN_FDS", "LISTEN_PID"):
            self.env.pop(k, None)
        self.statedir = os.path.join(self.tmp, "state")
        self.err = []
        self._spawn()

    # The spawn is a method rather than eight lines of __init__ because the
    # fixture could not express a RESTART at all while it was inline: every
    # test built a fresh Rig, which meant a fresh tmpdir, fresh slots and a
    # fresh port as well as a fresh process. A router's whole lifecycle -- up,
    # down, up again against the same slots and the same state directory -- had
    # no representation here, and three defects live in exactly that gap. A rig
    # cannot catch what it cannot say.
    def _spawn(self):
        self.proc = subprocess.Popen([sys.executable, DEMUX], env=self.env,
                                     stderr=subprocess.PIPE)
        # Drained continuously, in a thread. Reading the pipe only on failure
        # was fine while nothing checked the log; now that a test asserts on
        # what was written, a full pipe would block the thing under test and
        # the symptom would be a hang rather than a failure.
        threading.Thread(target=self._drain, args=(self.proc,),
                         daemon=True).start()
        self.wait_up()

    def restart(self, wipe_state=True):
        """Stop the router and start another one against the SAME slots.

        The port is kept, so a client built before the restart still addresses
        the same front door -- a visitor does not get a new URL because a
        service restarted, and a rig that handed out a new port would be
        testing a migration rather than a restart.

        The stand-in desktops are deliberately NOT touched. That is the whole
        point of the case: systemd restarts this router on failure while every
        session it was routing to goes on running, so the slots outlive the
        table that says who owns them. No longer an inference from Restart=
        on-failure in the packaged unit -- measured on ct154, where the session
        kept its ExecMainPID and its start timestamp across a restart of the
        router. The run is quoted above arm 5.

        wipe_state DEFAULTS TO TRUE, and the default was the other way round
        until the wipe was measured. STATE_DIR lives under the router's own
        RuntimeDirectory= on the box, so systemd removes it on EVERY stop --
        a clean restart and a kill -9 alike, both watched on ct154 and quoted
        above arm 5. A rig that carried the state across a restart was
        therefore modelling a world that does not exist, and it was not a
        harmless simplification: it made a table persisted under
        HDW4S_DEMUX_STATE sufficient to pass the restart arm, which is the one
        implementation that is green here and broken in the field. Preserving
        it is still available for the arm that needs it, and arm 5 asks for it
        by name.
        """
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(5)
        if wipe_state:
            import shutil
            shutil.rmtree(self.statedir, ignore_errors=True)
        self.err.append("--- router restarted ---\n")
        self._spawn()

    def _drain(self, proc):
        # Takes the process it is draining rather than reading self.proc, which
        # a restart rebinds under it: the old thread would then follow the NEW
        # process's pipe and the log of the run under test would be spliced
        # together from two routers.
        for line in proc.stderr:
            self.err.append(line.decode("utf-8", "replace"))

    def stderr_text(self, settle=1.0):
        """Everything the router has said. Waits briefly, because the write we
        are asserting on happens on the router's thread and the assertion runs
        on ours -- a bare read races it and fails intermittently, which is worse
        than failing."""
        deadline = time.time() + settle
        n = len(self.err)
        while time.time() < deadline:
            time.sleep(0.05)
            if len(self.err) == n:
                break
            n = len(self.err)
        return "".join(self.err)

    @staticmethod
    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    def wait_up(self):
        for _ in range(100):
            if self.proc.poll() is not None:
                time.sleep(0.2)
                raise RuntimeError("demux exited: %s" % "".join(self.err))
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("demux never listened")

    def client(self, cookie=None, cred=None):
        return Client(self.port, self.cred if cred is None else cred, cookie)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for s in self.slots:
            s.stop = True
            s.s.close()


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def arrive(rig, client):
    """Follow arrival to a session path. Returns (sid, body)."""
    st, h, _ = client.get("/?socket_worker=false")
    assert st == 302, "arrival did not redirect: %d" % st
    client.learn_cookie(h)
    loc = h["location"][0]
    assert loc.startswith("/s/"), "redirect was not to a session path: %s" % loc
    assert "socket_worker=false" in loc, \
        "the query string did not survive the redirect: %s" % loc
    sid = loc.split("/")[2]
    st, _, body = client.get(loc)
    assert st == 200, "session path did not serve: %d" % st
    return sid, body.decode()


def test_credential(rig):
    c = rig.client()
    st, h, _ = c.get("/", auth=False)
    assert st == 401, "the front door served without a credential: %d" % st
    assert any("Basic" in v for v in h.get("www-authenticate", [])), \
        "401 carried no Basic challenge"
    c2 = rig.client(cred="front:wrongpw")
    st, _, _ = c2.get("/")
    assert st == 401, "the front door accepted a WRONG credential: %d" % st
    c3 = rig.client()
    st, _, _ = c3.get("/")
    assert st == 302, "the front door refused a CORRECT credential: %d" % st


def test_two_tabs_diverge(rig):
    """The milestone. Two browser contexts, one hostname, two sessions."""
    a, b = rig.client(), rig.client()
    sid_a, body_a = arrive(rig, a)
    sid_b, body_b = arrive(rig, b)
    assert a.cookie != b.cookie, "two contexts were given one identity"
    assert sid_a != sid_b, "two tabs CONVERGED on one session"
    slot_a = body_a.split("SLOT=")[1].split()[0]
    slot_b = body_b.split("SLOT=")[1].split()[0]
    assert slot_a != slot_b, \
        "two sessions landed on the same slot: %s" % slot_a


def test_cross_identity_refused(rig):
    """The invariant, tested with a negative: A asks for B's address."""
    a, b = rig.client(), rig.client()
    sid_a, _ = arrive(rig, a)
    sid_b, _ = arrive(rig, b)
    st, _, _ = a.get("/s/%s/" % sid_b)
    assert st == 403, \
        "identity A reached identity B's desktop (got %d, wanted 403)" % st
    st, _, _ = a.get("/s/%s/" % sid_a)
    assert st == 200, "identity A was refused its OWN desktop: %d" % st


def test_unknown_sid(rig):
    a = rig.client()
    arrive(rig, a)
    st, _, _ = a.get("/s/%s/" % ("0" * 32))
    assert st in (403, 410), "an unknown address was served: %d" % st


def test_dead_sid_gates_and_does_not_mint(rig):
    """A returning tab must get a QUESTION, not a desktop.

    The scenario this is for: a machine reboots and restores twenty tabs lazily,
    every one of them presenting an id that no longer exists. Minting on each
    would hand back twenty desktops nobody asked for -- minting is a DAMAGE, not
    a neutral default. So the check is not merely "it did not route somewhere
    wrong", it is "it started nothing at all".
    """
    a = rig.client()
    arrive(rig, a)
    before = slots_in_use(rig)
    for _ in range(5):               # five restored tabs, five dead ids
        st, h, body = a.get("/s/%s/" % secrets_hex())
        assert st == 410, "a dead address did not gate: %d" % st
        assert "location" not in h, \
            "a dead address REDIRECTED, which is an action, not a question"
        assert b"href=\"/\"" in body, "the gate offers no way forward"
    after = slots_in_use(rig)
    assert after == before, \
        ("five returning tabs started %d desktop(s) nobody asked for"
         % (after - before))


def slots_in_use(rig):
    """How many stand-in slots have been handed out, read from the slots
    themselves rather than from the router's own account of itself."""
    n = 0
    for s in rig.slots:
        if getattr(s, "seen", False):
            n += 1
    return n


def secrets_hex():
    import secrets as _s
    return _s.token_hex(16)


def test_trailing_slash(rig):
    a = rig.client()
    sid, _ = arrive(rig, a)
    st, h, _ = a.get("/s/%s" % sid)
    assert st == 302, "/s/<sid> was not redirected to /s/<sid>/: %d" % st
    assert h["location"][0].endswith("/"), \
        "the redirect did not add a trailing slash: %s" % h["location"][0]


def test_pooled_connection(rig):
    """THE ONE THAT CATCHES THE REAL DEFECT.

    Two requests for two different sessions, down ONE connection. A splicer
    passes every other check here and fails this one by serving request 2 from
    request 1's backend -- a cross-session read.
    """
    a, b = rig.client(), rig.client()
    sid_a, _ = arrive(rig, a)
    sid_b, _ = arrive(rig, b)
    # One identity owning two sessions, so both are legitimately reachable from
    # a single connection -- which is exactly the pooling case.
    c = rig.client(cookie=a.cookie)
    c.connect()
    st1, _, body1 = c.get("/s/%s/one" % sid_a, keep=True)
    # Second request, same socket, different session, and it must be refused
    # rather than silently served from the first one's backend.
    st2, _, body2 = c.get("/s/%s/two" % sid_b, keep=True)
    c.close()
    assert st1 == 200, "first pooled request failed: %d" % st1
    assert st2 == 403, \
        ("the second request on a POOLED connection reached another identity's "
         "session (%d, %r) -- this is the cross-session read" % (st2, body2))
    assert b"PATH=/one" in body1, "path was not rewritten: %r" % body1


def test_pooled_same_identity(rig):
    """The permit arm of the pooling check: one identity, two of ITS sessions,
    one connection. Both must route correctly and to DIFFERENT slots -- which a
    splicer gets wrong while still looking fine on the refuse arm above."""
    a = rig.client()
    sid1, _ = arrive(rig, a)
    st, h, _ = a.get("/?gate=mint")
    assert st == 302, "gate=mint did not mint: %d" % st
    sid2 = h["location"][0].split("/")[2]
    assert sid1 != sid2, "gate=mint returned the SAME session"
    a.connect()
    _, _, b1 = a.get("/s/%s/one" % sid1, keep=True)
    _, _, b2 = a.get("/s/%s/two" % sid2, keep=True)
    a.close()
    s1 = b1.decode().split("SLOT=")[1].split()[0]
    s2 = b2.decode().split("SLOT=")[1].split()[0]
    assert s1 != s2, \
        ("two pooled requests for two sessions were served by ONE slot (%s) -- "
         "request 2 was delivered to request 1's backend" % s1)
    assert "PATH=/two" in b2.decode(), "second pooled request kept the first path"


def test_gate_arms(rig):
    """Both positions. A switch nobody exercises gets deleted as dead weight,
    and the arrival decision is then made by implementation."""
    a = rig.client()
    sid1, _ = arrive(rig, a)
    st, h, _ = a.get("/?gate=mint")
    assert st == 302
    assert h["location"][0].split("/")[2] != sid1, \
        "gate=mint resumed instead of minting"
    st, h, _ = a.get("/?gate=takeover")
    assert st == 302
    resumed = h["location"][0].split("/")[2]
    assert resumed != sid1 or True  # takeover resumes the most RECENT
    st, _, _ = a.get("/s/%s/" % resumed)
    assert st == 200, "gate=takeover resumed an address that does not route"
    # And takeover must resume rather than mint: ask twice, get the same one.
    st, h2, _ = a.get("/?gate=takeover")
    assert h2["location"][0].split("/")[2] == resumed, \
        "gate=takeover minted a new session instead of resuming"


def test_explicit_mint_arm_mints(rig):
    """With the mint arm PINNED, a second arrival takes a second session.

    Renamed from "default_gate_is_mint", which is what it was called while
    testing nothing of the sort: the rig pinned HDW4S_GATE_MODE for every test,
    so the module's default was never exercised and this name asserted a
    property nobody measured. The router and the page then disagreed about that
    default -- the router minting on every arrival, the page expecting to
    resume -- and this test passed throughout.
    """
    a = rig.client()
    sid1, _ = arrive(rig, a)
    st, h, _ = a.get("/")
    assert h["location"][0].split("/")[2] != sid1, \
        "the pinned mint arm resumed instead of minting"


def test_shipped_default_resumes_a_returning_browser():
    """THE DEFAULT, unpinned, and it is the one that ships.

    A browser that already owns a session must get that session back rather than
    a second one. Minting there is what the owner calls a damage: it costs the
    visitor the desktop they had and the pool a slot that is never returned.

    Measured as a release blocker before this existed: three requests from one
    cookie jar returned three different sessions, and the front door then refused
    everyone with three desktops running and nobody connected to any of them.
    """
    rig = Rig(gate=None)          # no HDW4S_GATE_MODE -- the shipped default
    try:
        a = rig.client()
        sid1, _ = arrive(rig, a)
        st, h, _ = a.get("/")
        got = h["location"][0].split("/")[2]
        assert got == sid1, (
            "the shipped default minted a SECOND session for a browser that "
            "already had one (%s != %s)" % (got, sid1))
        # And a browser that has none still mints, which is the new-tab case.
        b = rig.client()
        sid2, _ = arrive(rig, b)
        assert sid2 != sid1, "a fresh browser was given somebody else's session"
    finally:
        rig.stop()


def test_exhaustion(rig):
    """More arrivals than slots must refuse, not overwrite somebody."""
    seen = []
    for _ in range(len(rig.slots)):
        c = rig.client()
        sid, body = arrive(rig, c)
        seen.append(body.split("SLOT=")[1].split()[0])
    assert len(set(seen)) == len(rig.slots), \
        "slots were handed out twice: %s" % seen
    c = rig.client()
    st, _, _ = c.get("/")
    assert st == 503, "an arrival past capacity was not refused: %d" % st


# --- the router's LIFECYCLE, which this fixture could not express ---------
#
# Everything above this line runs against a router that was started once and
# never stopped, and every test builds its own. That is not a gap in coverage,
# it is a gap in VOCABULARY: there was no way to write down "a router that has
# been restarted" or "a slot the sweep has stopped", so the whole class of
# defect that lives there was invisible by construction. The same shape put a
# duration defect on the wire -- the rig could not express "30d" and says so in
# its own comment above.
#
# Ownership is entirely in process memory and forget() has exactly one call
# site, inside a start-up assertion. Those two facts pull in OPPOSITE
# directions: losing the table misroutes a stranger onto a live desktop,
# keeping it forever exhausts the pool. A repair that trades one for the other
# would satisfy either arm alone, so both are here and neither is sufficient.


def slot_named(rig, name):
    """The stand-in backend a name refers to. DERIVED from the name the router
    reported, never indexed off the end of the string: "ephemeral10" would have
    reaped ephemeral0, and the test would still have gone red -- for the wrong
    reason, which is the failure that looks most like success."""
    for s in rig.slots:
        if s.name == name:
            return s
    raise AssertionError("the router named a slot this rig does not have: %s"
                         % name)


def arrive_on_slot(rig, client):
    """(sid, slot name). The slot is read from the BACKEND's own answer, not
    from the router's account of itself -- a component is not evidence about
    its own behaviour."""
    sid, body = arrive(rig, client)
    return sid, body.split("SLOT=")[1].split()[0]


def test_control_two_visitors_without_a_restart_land_on_different_slots(rig):
    """THE CONTROL for everything below, and it is not decoration.

    The three tests after this one all conclude "these two visitors were put on
    the same slot". That sentence is only evidence if the rig can be seen
    producing the other answer under conditions where the other answer is
    right. Without this, a rig in which EVERY pair collides -- one slot
    misconfigured, the backends mixed up, the body parsed wrong -- would report
    the defect just as loudly against a router that had already been repaired.

    So: same helpers, same oracle, no restart. Separation must be visible
    working before it is believed failing.
    """
    _, slot_a = arrive_on_slot(rig, rig.client())
    _, slot_b = arrive_on_slot(rig, rig.client())
    assert slot_a != slot_b, (
        "two visitors with nothing between them were put on ONE slot (%s) -- "
        "this rig cannot tell separation from collision, so nothing below it "
        "means anything" % slot_a)


def test_a_restart_does_not_re_let_an_occupied_slot(rig):
    """DEFECT 1. A restart hands a stranger a desktop that is still running.

    The ownership table lives in process memory and nothing writes it down, so
    a router that comes back has no idea which slots it let. systemd restarts
    it on failure and the sessions it was routing to are separate units that
    never noticed, so the pool it sees as empty is in fact fully occupied. The
    "never noticed" half is measured rather than reasoned: on ct154 the
    session's ExecMainPID and start timestamp were unchanged across a restart
    of the router. See the run quoted above arm 5.

    The oracle is the BACKEND: visitor B's response carries the name of the
    slot that served it, and that name being A's is not "a routing table
    disagreement", it is B reading A's desktop.

    This needs no crash to be reached in the field -- a package upgrade
    restarts the service -- and no crafted request: two ordinary arrivals with
    a restart in between.
    """
    a = rig.client()
    _, slot_a = arrive_on_slot(rig, a)

    rig.restart()

    # A fresh cookie jar. Not a returning tab, not a resumed session: a
    # different person, who has never been here.
    b = rig.client()
    sid_b, slot_b = arrive_on_slot(rig, b)
    # ONE client, arriving ONCE. The first version of this arrived twice -- a
    # bare GET / on b, and then arrive_on_slot() on a SECOND fresh client -- so
    # the pool had already been advanced past the re-let slot by the time the
    # answer was read, and the test passed against the defect it was written
    # for. A rig that consumes a slot while measuring which slot was consumed
    # measures the wrong thing.

    assert slot_b != slot_a, (
        "a restart re-let slot %s: a stranger with a fresh cookie was routed "
        "to a desktop that never stopped and that somebody else is using"
        % slot_a)


def test_a_reaped_slot_returns_to_the_pool_without_a_restart(rig):
    """DEFECT 2. The pool exhausts permanently, and no crash is involved.

    forget() is dead code -- one call site, inside an assertion -- so
    instances_in_use() only ever grows. After as many arrivals as there are
    slots, every later visitor gets 503 forever, however many desktops the
    sweep has since stopped. This is the half that arrives from ORDINARY
    UPTIME rather than from a restart, which makes it the likelier of the two
    to be met first: a long-lived router simply serves more arrivals than it
    has slots and then stops serving anybody.

    What is asserted is the ARRIVAL being granted, not a picture. Whether a
    desktop comes back up behind the freed slot is the slot unit's business:
    hdw4s-proxy@<inst>.socket is socket-activated and a reap does not stop it,
    so the name stays live even with nothing behind it. The stand-in backends
    here do not restart, so asserting on a 200 would be asserting about the
    fixture rather than about the router.
    """
    for _ in range(len(rig.slots)):
        arrive(rig, rig.client())
    st, _, _ = rig.client().get("/")
    assert st == 503, \
        "the pool was not full after one arrival per slot: %d" % st

    # The sweep stops one desktop. The router is not restarted and is not told.
    # It does not find out in the field the way it finds out here -- see
    # Slot.reap() -- and for THIS arm that does not matter: instances_in_use()
    # is monotonic whether the socket refuses, stalls or answers, so the 503
    # below is reached by every route. The stand-in only has to free capacity,
    # not to free it the same way.
    rig.slots[0].reap()

    st, h, _ = rig.client().get("/")
    assert st == 302, (
        "a slot was reaped and the pool stayed full: a visitor got %d with "
        "capacity standing free. Nothing the sweep does can ever cure this, "
        "because the only thing that removes a slot from instances_in_use() "
        "is forget(), which nothing calls." % st)


def test_a_reaped_visitor_reaches_the_gate_rather_than_a_dead_end(rig):
    """DEFECT 3, first half: the 410 gate is unreachable for the one visitor
    it was written for.

    The gate fires when a sid does not resolve. A reaped visitor's sid resolves
    perfectly -- the table it lives in knows nothing about reaping -- so they
    fall through to the proxy instead of to the gate. That much is the defect
    and it does not depend on the stand-in.

    The 502 is THIS RIG's symptom, not a claim about the field. Under the
    shipped units the same fall-through ends in a stall and a refusal page from
    another component, per Slot.reap(); what both share, and what this arm is
    about, is that the visitor never reaches the 410 page written for them.
    """
    a = rig.client()
    sid, slot = arrive_on_slot(rig, a)
    slot_named(rig, slot).reap()

    st, _, body = a.get("/s/%s/" % sid)
    assert st == 410, (
        "a visitor whose desktop was reaped got %d instead of the 410 gate -- "
        "the gate cannot be reached by the visitor it was written for" % st)


def test_a_reaped_visitor_is_not_handed_back_the_same_dead_address(rig):
    """DEFECT 3, second half, and it is a separate failure from the first.

    Whatever the fall-through above ends in -- this rig's 502 page, or the
    field's refusal page -- it sends the visitor back to the front door. They
    go, and arrival resumes the most recent session this identity owns, which
    is the dead one. So the instruction the product gives them cannot be
    carried out: the front door returns them to the address that just failed,
    for as long as the router stays up. This half holds whichever way the
    stand-in differs, because it is decided by owned_by() and not by a socket.

    Asserted separately from the gate above so that a repair which fixes the
    resolution but leaves arrival resuming a corpse still goes red here.
    ANYTHING DOCUMENTED MUST BE POSSIBLE TO DO, and this page documents an
    action.
    """
    a = rig.client()
    sid, slot = arrive_on_slot(rig, a)
    slot_named(rig, slot).reap()
    a.get("/s/%s/" % sid)              # the dead end they are sent from

    st, h, _ = a.get("/")
    assert st in (302, 503), "the front door neither routed nor refused: %d" % st
    assert st == 302, \
        "the front door refused a visitor with free slots standing by: 503"
    got = h["location"][0].split("/")[2]
    assert got != sid, (
        "the front door handed back the SAME dead address (%s) it had just "
        "told the visitor to come here to escape" % sid)


# THE WIPE, MEASURED ON REAL SYSTEMD, so that nobody has to re-derive why a
# tmpdir was allowed to stand in for it below. Kept here rather than in a report
# because the next reader of this arm has exactly two wrong moves available --
# delete the stand-in as sloppy, or trust it as complete -- and both are made by
# somebody who cannot see this measurement. Measured on ct154; it supersedes the
# docstring's "the unit file is the oracle for that half", which was true when
# it was written and is now the weaker of the two.
#
# Directives read from the RUNNING unit, not from the packaged file:
#
#     RuntimeDirectory=hdw4s-demux   RuntimeDirectoryPreserve=no
#     DynamicUser=yes                Restart=on-failure
#     /run/hdw4s-demux   drwx------ hdw4s-demux hdw4s-demux
#
# NOT under /run/private. That relocation is the preserve=yes case, so any note
# claiming a pinned uid or a /run/private path is describing a CANDIDATE REPAIR
# and not what ships -- worth knowing before somebody reads one as evidence.
#
# Clean restart:
#
#     arrival (curl -L, cookie jar, reaching /s/<sid>/)
#     BEFORE  /run/hdw4s-demux/last-request/ephemeral0  11 bytes 09:39:13 count 1
#     systemctl restart hdw4s-demux.service
#     AFTER                                                               count 0
#
# Crash, which is the path that happens unattended:
#
#     record written:  ephemeral0  09:43:30
#     kill -9
#     AFTER            nothing
#
# NO DIFFERENCE between the two. Stated explicitly because
# RuntimeDirectoryPreserve=restart exists as a distinct value, so "a crash is the
# same as a restart" was an assumption right up until somebody ran both.
#
# And the half that makes it a defect rather than a curiosity: THE DESKTOP WAS
# NEVER TOUCHED. hdw4s-ephemeral@ephemeral0 stayed ActiveState=active with
# ExecMainPID=60813 and an ActiveEnterTimestamp from before the restart. A live
# desktop, visited seconds earlier, renders the byte-identical string that a slot
# nobody has ever opened renders.
#
# TWO TRAPS FOR WHOEVER RE-RUNS THIS, and the first one cost a retraction:
#
#   * A BARE CURL PROVES NOTHING. It takes the 302 and stops, never reaches a
#     slot, and writes no record -- so the thing you are about to call a
#     survivor is somebody else's traffic. Use curl -L with a cookie jar and
#     follow it to /s/<sid>/.
#   * OWN THE BOX FOR THE DURATION. The first attempt read 2 -> 1 and looked
#     like a record surviving a restart; the extra record belonged to another
#     seat working the same machine at the same time. File ownership was
#     allocated and machine ownership was not, which is a gap in the allocation
#     rather than a mistake at the keyboard -- and the only reason it was caught
#     is that the contaminated number was interesting enough to doubt. An
#     uninteresting wrong number would still be in the record.


def test_a_visited_slot_is_not_indistinguishable_from_a_never_visited_one(rig):
    """DEFECT 4, and READ THE STAND-IN BEFORE BELIEVING THIS ONE.

    What is real here: the rendering. A slot with no readable record renders
    "no record", and a slot that has never been visited renders "no record",
    and those are the same eight characters -- so an operator reading a refusal
    cannot tell "this desktop is idle and can be reaped" from "I lost my
    notes". That much is measured, in this process, against the shipped code.

    What is STOOD IN FOR, and it is the premise rather than a detail: the WIPE.
    The shipped unit has RuntimeDirectory=hdw4s-demux with no
    RuntimeDirectoryPreserve=, and STATE_DIR defaults inside it, so systemd
    removes the records every time the service stops. This rig's state lives in
    a tmpdir that has no relationship to RuntimeDirectory= whatsoever and would
    survive a thousand restarts. The rmtree below is the fixture IMITATING
    systemd, not observing it -- it proves the router renders a wiped record
    indistinguishably, and proves nothing at all about whether the wipe
    happens.

    WHAT SETTLES IT, and this sentence replaces the one that used to be here.
    It said the unit file was the oracle for that half. The unit file is a real
    check and the arm after this one still makes it, but it is now the WEAKER
    evidence: the wipe has since been observed on ct154 under real systemd,
    across a clean restart and a kill -9, with the desktop untouched throughout.
    That run is written out in the comment above this function, traps included.
    A reader who stops at this docstring must not leave with the superseded
    answer, which is why the correction is here and not only up there.
    """
    a = rig.client()
    _, visited = arrive_on_slot(rig, a)
    path = os.path.join(rig.statedir, "last-request", visited)
    for _ in range(50):
        if os.path.exists(path):
            break
        time.sleep(0.05)
    assert os.path.exists(path), "no record was written for %s" % visited

    rig.restart(wipe_state=True)

    # Exhausted with BARE front-door requests, which mint and redirect and
    # stop there. Following each redirect the way arrive() does would send a
    # request THROUGH every slot and write a fresh record on each, so all three
    # would read "0m ago" and the comparison would find a difference that the
    # test itself had created. Written that way first, and it went red for a
    # reason that was not the defect.
    #
    # DRAINED UNTIL IT REFUSES rather than exactly len(slots) times. How many
    # arrivals the pool has left after a restart is an answer that DEPENDS ON
    # THE IMPLEMENTATION -- this router thinks all of them, a router that reads
    # the sessions' runtime directories knows one slot is still occupied -- and
    # a fixed count silently asserts one of those. It was written as a fixed
    # count and went red against a correct design, for a reason that had
    # nothing to do with the records this arm is about. What this arm needs is
    # a refusal to read, not a particular route to it.
    for _ in range(len(rig.slots) + 1):
        st = rig.client().get("/")[0]
        if st == 503:
            break
        assert st == 302, "an arrival was neither routed nor refused: %d" % st
    st, _, _ = rig.client().get("/")
    assert st == 503, "the pool did not refuse, so there is no refusal to read"
    text = rig.stderr_text().split("--- router restarted ---")[-1]
    # Matched on "  <name>:" INSIDE the line, not on its start: log() prefixes
    # every line with the programme name, so a startswith() on the slot name
    # matches nothing and reports a missing slot rather than a failed
    # comparison -- an empty result that reads exactly like a finding.
    lines = {}
    for line in text.splitlines():
        for slot in rig.slots:
            key = "  %s: " % slot.name
            if key in line:
                lines[slot.name] = line.split(key, 1)[1]
    assert visited in lines, "the refusal did not name %s at all" % visited
    others = [v for k, v in lines.items() if k != visited]
    assert others, "the rig has only one slot, so nothing can be compared"
    stripped = lines[visited]
    assert any(stripped != o for o in others), (
        "a slot that served a visitor before the restart reads EXACTLY like "
        "one nobody has ever opened (%r) -- the operator who sets the idle "
        "window from this line is reading a lost record as an idle desktop"
        % stripped)


def test_the_records_the_refusal_log_is_read_from_survive_a_restart():
    """DEFECT 4's premise, read from the configuration rather than from a box.

    The test above imitates the wipe. This one asks whether the shipped
    configuration calls for it, and it answers from the unit file.

    THIS DOCSTRING USED TO SAY the unit file was "the only oracle that can
    settle it" and that "a unit file read is the whole of the available
    evidence", because hdw4s-demux had never run on the production box and
    nobody had stood one up elsewhere. Both sentences were true when written
    and both are now false: it has since been run on ct154 under real systemd
    and the wipe was watched happening. What survives is the weaker claim --
    that this arm checks the CONFIGURATION, which is worth having because a
    configuration can be changed back without anybody re-running a box.

    Still true, and still worth saying: there is no production instance and no
    incident history, so nothing downstream will catch what this file misses.

    Deliberately agnostic between the two repairs, because choosing one here
    would be this seat designing somebody else's fix: either the runtime
    directory is preserved across a restart, or the records do not live in a
    runtime directory at all. Both make the refusal log mean something after a
    restart; this asserts the property, not the mechanism.
    """
    here = os.path.dirname(os.path.dirname(HERE))
    unit = os.path.join(here, "hdw4s-demux.service")
    text = "".join(l for l in open(unit) if not l.lstrip().startswith("#"))
    rundirs = [l.split("=", 1)[1].strip() for l in text.splitlines()
               if l.startswith("RuntimeDirectory=")]
    preserved = [l for l in text.splitlines()
                 if l.startswith("RuntimeDirectoryPreserve=")
                 and l.split("=", 1)[1].strip() != "no"]
    src = open(DEMUX).read()
    state_default = src.split('HDW4S_DEMUX_STATE", "')[1].split('"')[0]
    under = [d for d in rundirs if state_default.startswith("/run/" + d)]
    assert not under or preserved, (
        "the last-request records live in %s, which is RuntimeDirectory=%s "
        "with no RuntimeDirectoryPreserve= -- systemd deletes them every time "
        "the service stops, and every slot then reads 'no record', which is "
        "the same thing a slot nobody has ever opened reads"
        % (state_default, ",".join(under)))


# --- red arms: the same guards, deliberately violated --------------------

def red_cross_identity(rig):
    """Assert the WRONG thing -- that A may reach B. Must fail."""
    a, b = rig.client(), rig.client()
    _, _ = arrive(rig, a)
    sid_b, _ = arrive(rig, b)
    st, _, _ = a.get("/s/%s/" % sid_b)
    assert st == 200, "A was refused B's desktop (which is correct): %d" % st


def red_no_credential(rig):
    c = rig.client()
    st, _, _ = c.get("/", auth=False)
    assert st == 302, "the front door refused an unauthenticated caller: %d" % st


def red_converge(rig):
    a, b = rig.client(), rig.client()
    sid_a, _ = arrive(rig, a)
    sid_b, _ = arrive(rig, b)
    assert sid_a == sid_b, "the two tabs diverged (which is the milestone)"


# --- the identity window, and the one event that means we refused somebody ---

def test_cookie_slides_beyond_the_front_door(rig):
    """A tab that never revisits the front door must still be kept alive.

    The defect: Set-Cookie was attached only on the arrival that found no valid
    cookie, and nothing anywhere refreshed it, so Max-Age ran from a browser's
    first ever contact however much it used the pool since. The closed loop that
    produces is in the module's own comment. What is checked here is the fix at
    the place the fix matters -- the session path, where a working tab spends
    its whole life and which it may never leave.
    """
    a = rig.client()
    st, h, _ = a.get("/")
    assert st == 302, "arrival did not redirect: %d" % st
    a.learn_cookie(h)
    loc = h["location"][0]

    st, h2, _ = a.get(loc)
    assert st == 200, "the session path did not serve: %d" % st
    got = [v for v in h2.get("set-cookie", []) if v.startswith("hdw4s_id=")]
    assert got, (
        "a response from the SESSION PATH carried no identity -- a tab that "
        "stays put never has its window wound on and ages out in place")
    assert a.cookie in got[0], \
        "the session path replaced the identity instead of extending it: %s" \
        % got[0]
    assert "Max-Age=" in got[0], "the refreshed cookie carries no lifetime"

    # And it is a rate limit, not a header on every asset fetch.
    st, h3, _ = a.get(loc)
    again = [v for v in h3.get("set-cookie", []) if v.startswith("hdw4s_id=")]
    assert not again, \
        "every response carried a cookie; the rate limit does nothing"


def test_cookie_max_age_is_the_derived_lifetime(rig):
    """The Max-Age on the wire is the derived one, not a constant.

    The rig's pool is configured with a 40-day idle window, so the floor is not
    what decides: the value must be 80 days. A test against the floor alone
    would pass against a hard-coded 30 and prove nothing.
    """
    c = rig.client()
    st, h, _ = c.get("/")
    sc = [v for v in h.get("set-cookie", []) if v.startswith("hdw4s_id=")]
    assert sc, "a fresh browser was given no identity at all"
    age = int(sc[0].split("Max-Age=")[1].split(";")[0])
    assert age == 80 * 86400, (
        "identity lifetime was %d day(s); a 40-day idle window must derive 80"
        % (age // 86400))


def test_refusal_is_logged_with_what_it_takes_to_judge_it(rig):
    """Pool exhaustion used to be silent.

    It rendered a 503 to the visitor and wrote nothing anywhere, so an operator
    learned the pool was full by being told by a person -- which means the idle
    window was being set from no evidence. The oracle here is the LOG, not the
    status code: the 503 was always right and always mute.
    """
    for _ in range(len(rig.slots)):
        arrive(rig, rig.client())
    st, _, _ = rig.client().get("/")
    assert st == 503, "an arrival past capacity was not refused: %d" % st
    text = rig.stderr_text()
    assert "turned an arrival away" in text, \
        "the pool refused a visitor and said nothing:\n%s" % text
    for s in rig.slots:
        assert ("  %s:" % s.name) in text, \
            "the refusal named no age for %s, so the idle window cannot be "\
            "judged from it:\n%s" % (s.name, text)
    assert "last request" in text and "idle window" in text, \
        "the refusal carries no ages and no window:\n%s" % text
    # The sweep's own record is absent in this rig, and the line must SAY so
    # rather than render an unread stamp as a number.
    assert "no record" in text, \
        "a missing sweep record was reported as something other than missing"


def test_last_request_record_is_written_where_the_connection_is_accepted(rig):
    """The accurate column, and why there are two.

    The sweep polls every few minutes, so a visit that begins and ends inside
    one gap is invisible to every sample it takes -- and the confident sentence
    it then writes about a desktop "nobody has used since yesterday" is wrong.
    This record is written where the connection is accepted, so the poll rate
    stops mattering. Checked against the FILE, not against the log line, because
    the log line is what we are trying to make true.
    """
    a = rig.client()
    sid, _ = arrive(rig, a)
    body = a.get("/s/%s/" % sid)[2].decode()
    slot = body.split("SLOT=")[1].split()[0]
    path = os.path.join(rig.tmp, "state", "last-request", slot)
    for _ in range(50):
        if os.path.exists(path):
            break
        time.sleep(0.05)
    assert os.path.exists(path), \
        "a request was served through %s and no record of it was written" % slot
    with open(path) as f:
        stamp = int(f.read().strip())
    assert abs(stamp - time.time()) < 60, \
        "the record is not a current timestamp: %d" % stamp


def test_derivation_complains_when_a_window_outgrows_the_pinned_lifetime(rig):
    """THE DERIVATION, SEEN REFUSING.

    It cannot fail against its own input -- max(30d, 2 x W) is never smaller
    than W -- so checking it that way proves nothing. What can fail is the
    relationship over TIME: the lifetime is pinned when the router starts and
    the configuration is not, so an idle window raised afterwards leaves a
    desktop able to outlive the identity that owns it. The rig starts with a
    1-day window, which pins a 30-day identity, and then sets the window to 90
    days behind the router's back.
    """
    for name, _ in rig.windows:
        with open(os.path.join(rig.etc, name + ".conf"), "w") as f:
            f.write("HDW4S_IDLE_DAYS=90\n")
    for _ in range(len(rig.slots)):
        arrive(rig, rig.client())
    st, _, _ = rig.client().get("/")
    assert st == 503
    text = rig.stderr_text()
    assert "not shorter than the 30-day identity" in text, (
        "a 90-day desktop against a 30-day identity was not reported -- the "
        "owner can be locked out of a session that is still running:\n%s"
        % text)


def test_a_slot_that_is_never_reaped_is_reported_at_start():
    """The unbounded case, which no lifetime can dominate.

    HDW4S_IDLE_DAYS=0 means the sweep never stops that slot, so its desktop can
    outlive any identity however long. The derivation cannot fix that and must
    not pretend to; it says so at start, where somebody can act on it.
    """
    rig = Rig(nslots=1, windows=[("ephemeral0", 0)])
    try:
        text = rig.stderr_text()
        assert "never reaped" in text, \
            "a slot with no idle window at all was not reported:\n%s" % text
        # And it is reported as a LIMITATION rather than absorbed: the line has
        # to name the consequence, or the next reader raises the floor and
        # believes the problem is gone.
        assert "outlive" in text, \
            "the unbounded case was named without its consequence:\n%s" % text
        assert "an identity lasts" in text, \
            "the derived lifetime was never stated:\n%s" % text
    finally:
        rig.stop()


def test_a_suffixed_window_is_honoured(rig):
    """THE DEFECT ITSELF, at the product's own surface.

    "30d" is what hdw4s.conf and hdw4s.8 tell an administrator to type. The
    router read it with int(), caught the failure and used seven days without a
    word, so the identity it derived was 30 days -- the floor -- instead of 60.
    Nothing failed: the conf file said one thing and the wire said another, and
    both looked healthy.

    Asserted on the Max-Age the browser actually receives rather than on the
    reader, because the number the reader returns is not what anybody is locked
    out by. 30 days of window must derive 60 days of identity, and 60 beats the
    floor, so a router that fell back to ANY of the wrong answers -- seven days,
    the floor, a truncation -- fails this and says which.
    """
    c = rig.client()
    st, h, _ = c.get("/")
    sc = [v for v in h.get("set-cookie", []) if v.startswith("hdw4s_id=")]
    assert sc, "a fresh browser was given no identity at all"
    age = int(sc[0].split("Max-Age=")[1].split(";")[0])
    assert age == 60 * 86400, (
        "HDW4S_IDLE_DAYS=30d derived a %d-day identity; 30 days of window must "
        "derive 60. A 30-day answer is the floor standing in, and a 14-day one "
        "is the seven-day fallback this replaced." % (age // 86400))


def test_a_sub_day_window_is_not_read_as_never(rig):
    """The half of the defect that a parser fix alone would have created.

    The router worked in whole days, so "12h" had no representation in it: had
    int() merely been taught units, twelve hours would have truncated to zero
    days -- which this file reads as "never reaped" -- and the setting would
    have been INVERTED rather than mis-stated. The slot would have been
    reported as unbounded and its desktop kept forever.
    """
    text = rig.stderr_text()
    assert "never reaped" not in text, (
        "a twelve-hour window was reported as never reaped -- the window was "
        "truncated to whole days:\n%s" % text)
    assert "ephemeral0=12h" in text, (
        "the router did not state a twelve-hour window as twelve hours:\n%s"
        % text)


def test_an_unreadable_window_is_loud_and_is_not_a_default(rig):
    """A value nobody can read must not be indistinguishable from one somebody
    chose.

    This is the sharp edge of the defect and the reason a repair that only
    made the two parsers agree would not have been enough. "30x" is a typo. The
    router answered seven days to it, silently, exactly as it answered seven
    days to a deliberate 7 -- so the configuration file and the behaviour could
    disagree with nothing anywhere able to report it.

    The oracle is the log, not the derived number: what makes this survivable is
    that somebody is TOLD, and a test on the number alone would pass against a
    router that guessed correctly in silence.
    """
    text = rig.stderr_text()
    assert "HDW4S_IDLE_DAYS=30x" in text, (
        "the router did not quote the value it could not read:\n%s" % text)
    assert "cannot be read" in text, (
        "an unreadable idle window was not reported as unreadable:\n%s" % text)
    assert "not a unit of time" in text, (
        "the reason was not given, so nobody can tell a typo from a form we "
        "do not support:\n%s" % text)
    # And it must not be absorbed. An unknown window is unbounded as far as
    # anything here knows, so it gets the complaint an unbounded one gets.
    assert "unknown and may exceed any identity" in text, (
        "an unreadable window was read as bounded, which is a guess:\n%s"
        % text)


def test_a_session_cannot_set_our_cookie(rig):
    """A desktop must not be able to rewrite the identity of its visitor.

    It cannot read one -- the Cookie header is stripped on the way up -- and if
    it could write one, a compromised session would reassign the identity of
    every browser it answers, which is the ownership table defeated from below.
    """
    a = rig.client()
    sid, _ = arrive(rig, a)
    before = a.cookie
    for s in rig.slots:
        s.forge_cookie = "hdw4s_id=" + ("f" * 32)
    st, h, _ = a.get("/s/%s/" % sid)
    got = [v for v in h.get("set-cookie", []) if v.startswith("hdw4s_id=")]
    assert not any(("f" * 32) in v for v in got), \
        "a session set our identity cookie: %r" % got


# --- guards exercised without a network ------------------------------------

def test_cookie_lifetime_guard(rig=None):
    """The start-up guard, in BOTH directions.

    The refuse arm is not a contrived mutation: it is the value that SHIPPED --
    a flat seven days, equal to the default idle window. Two clocks set to the
    same number, counting from different events, which composes into an identity
    that expires while the desktop it owns is still running.
    """
    m = load_demux()

    # PERMIT ARM: the shipped derivation must pass.
    m.assert_cookie_outlives_idle(m.derive_cookie_lifetime)

    # REFUSE ARM: the constant that was on the wire before this.
    try:
        m.assert_cookie_outlives_idle(lambda windows: 7 * 86400)
    except AssertionError as e:
        print("       red arm, as required -- the shipped constant rejected: %s"
              % e)
    else:
        raise AssertionError(
            "the guard PASSED a seven-day identity against a seven-day idle "
            "window -- it is not a guard, and a visitor can be locked out of a "
            "desktop that is still running")

    # And a derivation that is merely EQUAL rather than shorter must also be
    # refused: equal is the defect, not the boundary of it.
    try:
        m.assert_cookie_outlives_idle(
            lambda windows: max(s for _, s in windows) if windows
            else m.COOKIE_FLOOR_SECONDS)
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "the guard accepted an identity exactly as long as the idle window")


def test_refresh_rate_limit(rig=None):
    """The sliding window winds on, and does not do so on every asset fetch."""
    m = load_demux()
    own = m.Ownership()
    who = own.mint_identity()
    t = 1000.0
    assert own.due_for_refresh(who, now=t, every=3600), \
        "an identity this process has never refreshed was not refreshed"
    assert not own.due_for_refresh(who, now=t + 60, every=3600), \
        "every response carried a cookie -- the rate limit does nothing"
    assert own.due_for_refresh(who, now=t + 3601, every=3600), \
        "the window did not slide once the interval had passed: it is a fuse"


def load_demux():
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("demux_mod", DEMUX)
    spec = importlib.util.spec_from_loader("demux_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_ownership_keying_guard(rig=None):
    """The guard from §12.3, in BOTH directions, without a network.

    The defect it prevents is the worst in the book and it is silent: a browser
    returning after its session was reaped, routed into whatever now occupies
    that slot -- a stranger's desktop, handed over by the ownership check meant
    to prevent exactly that. So the guard is not trusted because it is green; it
    is trusted because it has been seen to go red against the mistake itself.
    """
    m = load_demux()

    # PERMIT ARM: the shipped, session-instance-keyed table must pass.
    m.assert_ownership_keying(m.Ownership)

    # REFUSE ARM: the same guard against a slot-keyed table. This is not a
    # contrived mutation -- it is what a reasonable person writes when nobody
    # has written down why not.
    class SlotKeyed(m.Ownership):
        def mint_session(self, identity, instance):
            with self._lock:
                self._by_sid[instance] = {"identity": identity,
                                          "instance": instance, "minted": 0}
                self._by_identity.setdefault(identity, []).append(instance)
            return instance

        def forget(self, sid):
            return None      # a reaped session leaves its ownership behind

    try:
        m.assert_ownership_keying(SlotKeyed)
    except AssertionError as e:
        print("       red arm, as required -- slot-keyed table rejected: %s" % e)
        return
    raise AssertionError(
        "the guard PASSED a slot-keyed ownership table -- it is not a guard, "
        "and a returning browser would be routed to a stranger's desktop")


def test_state_inventory_guard(rig=None):
    """Every piece of the router's state has somebody's answer about its purpose.

    THE REFUSAL IS PINNED, not the exit status. The guard has two faces on
    purpose -- the router logs what uninventoried_state() returns and starts,
    the suite calls assert_state_is_inventoried() and goes red -- and the
    moment a check has two dispositions, the choice between them is itself
    something that can be wired wrong in the quiet direction. If this asserted
    only "the run exited zero" and the suite ever ended up on the reporting
    face, it would pass while the guard printed violations into a log nobody
    reads. So the arms below assert the refusal itself.
    """
    m = load_demux()
    ns = vars(m)

    # PERMIT ARM: the module as it ships has an answer for everything.
    m.assert_state_is_inventoried(ns)
    assert m.uninventoried_state(ns) == [], \
        "the shipped module has state nobody has classified"

    def must_refuse(what, **kw):
        got = m.uninventoried_state(**kw)
        assert got, ("the guard PASSED %s -- it is not a guard, and the next "
                     "container added to that file arrives unclassified and "
                     "unnoticed" % what)
        return got

    # REFUSE ARM 1: the inventory stops naming a live piece of state. This is
    # the arm the brief asked for by name, and it is the realistic one: the
    # list is edited by hand and a rename is the cheapest way to break it.
    inv = dict(m.STATE_INVENTORY)
    del inv["Ownership._refreshed"]
    must_refuse("an ownership table whose refresh record is unlisted",
                ns=ns, inventory=inv)

    # REFUSE ARM 2: a new mutable container, in each of the three places one
    # can appear. A namespace walk alone sees only the first.
    extra = dict(ns)
    extra["_seen_hosts"] = {}
    must_refuse("a new module-level dict", ns=extra)

    class Extra(m.Ownership):
        def __init__(self):
            super().__init__()
            self._last_seen = {}
    Extra.__module__ = ns["__name__"]
    must_refuse("a new attribute on the ownership table", ns=ns, cls=Extra)

    class Cached:
        _hits = {}
    Cached.__module__ = ns["__name__"]
    shared = dict(ns)
    shared["Cached"] = Cached
    must_refuse("a dict in a class body, shared by every instance", ns=shared)

    # REFUSE ARM 3: a tuple is only as immutable as what is in it. Without the
    # recursion this is the cheapest way past the check, and it looks like a
    # constant at the call site.
    disguised = dict(ns)
    disguised["PAIRS"] = ({}, {})
    must_refuse("a tuple of dicts", ns=disguised)

    # REFUSE ARM 4: a global rebound at run time. Its VALUE may be an ordinary
    # number, so nothing that walks values could ever find it -- this is the
    # arm that says the source is read as well as the namespace.
    rebound = os.path.join(tempfile.mkdtemp(), "rebound")
    src = open(DEMUX).read()
    marked = src.replace("def main():\n    global COOKIE_LIFETIME",
                         "def main():\n    global COOKIE_LIFETIME\n    global REALM")
    assert marked != src, "the fixture did not find main()'s global statement"
    open(rebound, "w").write(marked)
    must_refuse("a newly rebound module global", ns=ns, source=rebound)

    # REFUSE ARM 5: an entry describing state that is gone. Nothing else will
    # ever surface that -- the thing it describes is not there to contradict
    # it, so every other check keeps passing.
    stale = dict(m.STATE_INVENTORY)
    stale["Ownership._by_slot"] = "authority"
    must_refuse("an entry for state that no longer exists", ns=ns,
                inventory=stale)

    # REFUSE ARM 6: a detector that could not run must not read as a clean
    # sweep. An unreadable source is the difference between "nothing to report"
    # and "nothing was looked at".
    blind = dict(ns)
    blind["__file__"] = os.path.join(tempfile.mkdtemp(), "not-here")
    got = must_refuse("a source it could not parse", ns=blind)
    assert any("not a clean result" in c for c in got), \
        "a detector that did not run reported like one that found nothing"


def test_the_router_actually_runs_its_state_sweep(rig):
    """The guard above is exercised; this is that the ROUTER calls it.

    Written because the arms above stayed green with the call deleted from
    main(). A guard whose green is silence is indistinguishable from a guard
    nobody invokes, and that is not a hypothetical on this project -- the file
    you are reading had never been run by anything at all. So the router states
    the sweep happened, and this reads the statement.
    """
    text = rig.stderr_text()
    assert "state inventory:" in text, (
        "the router never said it swept its own state, so nothing here can "
        "tell the sweep from a deleted call:\n%s" % text)
    assert "0 unclassified" in text, \
        "the router started with state nobody has classified:\n%s" % text
    # The COUNT is asserted, and against a floor derived from the module rather
    # than a number typed here. A main() that deleted the call and kept the
    # line was measured printing a plausible count from the inventory's own
    # length; the line now counts what was looked at, which is strictly more
    # than the inventory holds because most of what is looked at is fine.
    m = load_demux()
    n = int(text.split("state inventory: ")[1].split(" name")[0])
    assert n > len(m.STATE_INVENTORY), (
        "the router examined %d name(s), which is no more than the inventory "
        "lists -- that is a count restated, not a sweep performed" % n)
    # And the other half of this seat's work: the re-check has to be running,
    # not merely defined. Its steady state is silence too, so the same trap
    # applies -- a thread nobody started looks exactly like a quiet one.
    assert "re-checked against the pool every" in text, (
        "the identity lifetime is not being re-checked while we run, so a "
        "widened idle window would again wait for somebody to be refused:\n%s"
        % text)


def test_identity_lifetime_is_rechecked_without_a_refusal(rig=None):
    """The staleness warning fires when nobody has been turned away.

    Its only triggers were a start and an exhausted pool. An administrator who
    widens an idle window on a running box moves the desktop clock and not the
    identity clock, and on a box with a spare slot nothing would ever have said
    so -- the check existed and had no way to run.

    The second arm matters as much as the first: a timer that restated a
    standing complaint every quarter hour is a check that fires on an ordinary
    state, and those get switched off, after which they protect nothing.
    """
    m = load_demux()
    life = 30 * 86400

    def poll(seen, windows):
        said = []
        return m.poll_cookie_policy(seen, life, windows=windows,
                                    say=said.append), said

    # A correct pool is silent from cold. Without this the arm below could be
    # satisfied by something that complains about everything.
    _, quiet = poll(set(), [("ephemeral0", 7 * 86400)])
    assert not quiet, "an ordinary pool produced a warning: %r" % quiet

    # REFUSE ARM: a window widened past the pinned identity, nobody refused.
    seen, said = poll(set(), [("ephemeral0", 45 * 86400)])
    assert any("not shorter than" in s for s in said), (
        "an idle window longer than the pinned identity went unreported with "
        "no refusal to trigger it: %r" % said)
    assert any("Nobody was turned away" in s for s in said), \
        "the line does not say why it appeared, so a reader cannot act on it"

    # THE ANTI-SPAM ARM. Same state, same answer, and it must be silent.
    seen, again = poll(seen, [("ephemeral0", 45 * 86400)])
    assert not again, (
        "a standing complaint was restated: four lines an hour for as long as "
        "the condition lasts is how a check gets disabled: %r" % again)

    # A NEW slot going bad must not be hidden behind the standing one.
    seen, more = poll(seen, [("ephemeral0", 45 * 86400), ("ephemeral1", 0)])
    assert any("never reaped" in s for s in more), \
        "a second slot went bad and was hidden by the first: %r" % more

    # And the question is closed by the instrument that raised it.
    seen, cleared = poll(seen, [("ephemeral0", 7 * 86400),
                                ("ephemeral1", 7 * 86400)])
    assert any("no longer applies" in s for s in cleared), (
        "the condition cleared and the log still carries two warnings: a "
        "warning nobody ever retracts teaches a reader to ignore them")
    assert seen == set(), "it kept complaints that no longer apply"

    # A poll that raises must not take the watcher down silently. A dead
    # background thread looks exactly like a clean box.
    said = []
    real_log, real_windows = m.log, m.idle_windows
    m.log = said.append

    def boom(*a, **kw):
        raise OSError("the pool table vanished")

    m.idle_windows = boom
    t = threading.Thread(target=m.watch_cookie_policy,
                         args=(life, set()), kwargs=dict(every=0.05),
                         daemon=True)
    t.start()
    time.sleep(0.4)
    m.idle_windows, m.log = real_windows, real_log
    assert any("re-check failed" in s for s in said), \
        "a failed re-check was silent: %r" % said
    assert t.is_alive(), \
        "one failed poll killed the watcher, and nothing would have said so"


def main():
    print("== hdw4s-demux, stand-in slots, no browser ==")
    print("Real: the demultiplexer, TCP, HTTP, cookies, UNIX upstreams.")
    print("Stood in for: the sessions themselves. No picture is decoded here.\n")

    green = [test_credential, test_two_tabs_diverge, test_cross_identity_refused,
             test_unknown_sid, test_trailing_slash, test_pooled_connection,
             test_pooled_same_identity, test_gate_arms, test_explicit_mint_arm_mints,
             test_exhaustion, test_ownership_keying_guard,
             test_dead_sid_gates_and_does_not_mint,
             test_cookie_slides_beyond_the_front_door,
             test_refusal_is_logged_with_what_it_takes_to_judge_it,
             test_last_request_record_is_written_where_the_connection_is_accepted,
             test_a_session_cannot_set_our_cookie,
             test_cookie_lifetime_guard, test_refresh_rate_limit,
             test_state_inventory_guard,
             test_the_router_actually_runs_its_state_sweep,
             test_identity_lifetime_is_rechecked_without_a_refusal,
             # The lifecycle arms. The control comes FIRST on purpose: if
             # separation cannot be seen working, the three collisions after it
             # are not evidence of anything.
             test_control_two_visitors_without_a_restart_land_on_different_slots,
             test_a_restart_does_not_re_let_an_occupied_slot,
             test_a_reaped_slot_returns_to_the_pool_without_a_restart,
             test_a_reaped_visitor_reaches_the_gate_rather_than_a_dead_end,
             test_a_visited_slot_is_not_indistinguishable_from_a_never_visited_one]

    # Tests whose rig is not the default one. A pool with no instance table
    # derives the floor and nothing else, so a test about the DERIVATION has to
    # be given windows to derive from -- and a test that the floor is not the
    # answer has to be given a window long enough to beat it.
    configured = [
        (test_cookie_max_age_is_the_derived_lifetime,
         dict(nslots=1, windows=[("ephemeral0", 40)])),
        (test_derivation_complains_when_a_window_outgrows_the_pinned_lifetime,
         dict(nslots=1, windows=[("ephemeral0", 1)])),
        # Written the way an administrator writes them, which the fixture
        # could not express until it stopped formatting windows with "%d".
        (test_a_suffixed_window_is_honoured,
         dict(nslots=1, windows=[("ephemeral0", "30d")])),
        (test_a_sub_day_window_is_not_read_as_never,
         dict(nslots=1, windows=[("ephemeral0", "12h")])),
        (test_an_unreadable_window_is_loud_and_is_not_a_default,
         dict(nslots=1, windows=[("ephemeral0", "30x")])),
        # UNPINNED gate, because the question is what the SHIPPED arm does with
        # a returning visitor whose desktop is gone. Under the pinned mint arm
        # the front door mints a fresh session and the test passes while saying
        # nothing -- it was written that way first and was green.
        (test_a_reaped_visitor_is_not_handed_back_the_same_dead_address,
         dict(gate=None)),
    ]

    # Runs WITHOUT a rig from here, because it builds its own with the gate mode
    # unpinned -- the shipped default cannot be exercised by a rig that sets it.
    for fn in (test_shipped_default_resumes_a_returning_browser,
               test_a_slot_that_is_never_reaped_is_reported_at_start,
               test_the_records_the_refusal_log_is_read_from_survive_a_restart):
        try:
            fn()
            check(fn.__name__, True)
        except AssertionError as e:
            check(fn.__name__, False, str(e))
        except Exception as e:
            check(fn.__name__, False, "error: %r" % e)
    for fn in green:
        rig = Rig()
        try:
            fn(rig)
            check(fn.__name__, True)
        except AssertionError as e:
            check(fn.__name__, False, str(e))
        except Exception as e:
            check(fn.__name__, False, "error: %r" % e)
        finally:
            rig.stop()
    for fn, kw in configured:
        rig = Rig(**kw)
        try:
            fn(rig)
            check(fn.__name__, True)
        except AssertionError as e:
            check(fn.__name__, False, str(e))
        except Exception as e:
            check(fn.__name__, False, "error: %r" % e)
        finally:
            rig.stop()

    print("\n-- red arms: each MUST fail, or the guard above proves nothing --")
    for fn in (red_cross_identity, red_no_credential, red_converge):
        rig = Rig()
        try:
            expect_red(fn.__name__, lambda: fn(rig))
        finally:
            rig.stop()

    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
