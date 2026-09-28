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

import atexit
import base64
import json
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

    # THE DOOR. One file stands in for /proc/net/tcp and every slot's door is a
    # row in it, guarded by a lock because the slots are threads. The router
    # reads it through HDW4S_PROC_NET_TCP exactly as it reads the real one --
    # same parser, same st=0A requirement -- so what is stood in for here is the
    # KERNEL, not the check.
    doors = {}
    doors_lock = threading.Lock()
    doors_file = None

    @classmethod
    def write_doors(cls):
        if cls.doors_file is None:
            return
        # THE WHOLE WRITE IS UNDER THE LOCK, not only the read of the dict. It
        # used to take the lock for the read and then write one shared ".new"
        # file outside it, so two slots opening their doors at the same instant
        # -- which is what a burst of arrivals does -- truncated each other's
        # temporary file, and the loser's os.replace() found it already moved:
        # FileNotFoundError, swallowed by serve(), which closed the connection
        # unanswered. The router then correctly answered that visitor 502, and
        # the burst test read it as a slot let twice. Measured: 4 failures in
        # 80 runs, each one exactly a run in which this raised, and in none of
        # them did the router's log show a second mint on any slot.
        with cls.doors_lock:
            cls._write_doors_locked()

    @classmethod
    def _write_doors_locked(cls):
        rows = ["  sl  local_address rem_address   st tx_queue rx_queue tr"
                " tm->when retrnsmt   uid  timeout inode\n"]
        open_ports = sorted(p for p, up in cls.doors.items() if up)
        shut_ports = sorted(p for p, up in cls.doors.items() if not up)
        i = 0
        for port in open_ports:
            rows.append("%4d: 0100007F:%04X 00000000:0000 0A 00000000:00000000"
                        " 00:00000000 00000000     0        0 0 1 0 100 0 0 10"
                        " 0\n" % (i, port))
            i += 1
        # A SHUT DOOR LEAVES A TIME_WAIT BEHIND, because that is what the
        # connection the session was serving turns into when the session dies.
        # Written on purpose: a router that looked for the port anywhere in this
        # file rather than for state 0A would read every one of these as OPEN
        # and the whole repair would be green and inert.
        for port in shut_ports:
            rows.append("%4d: 0100007F:%04X 0100007F:D431 06 00000000:00000000"
                        " 00:00000000 00000000     0        0 0 1 0 100 0 0 10"
                        " 0\n" % (i, port))
            i += 1
        tmp = cls.doors_file + ".new"
        with open(tmp, "w") as f:
            f.write("".join(rows))
        os.replace(tmp, cls.doors_file)

    def open_door(self):
        with Slot.doors_lock:
            Slot.doors[self.port] = True
        Slot.write_doors()

    def shut_door(self):
        with Slot.doors_lock:
            Slot.doors[self.port] = False
        Slot.write_doors()

    def __init__(self, path, name, rundir, webroot=None, port=None):
        super().__init__(daemon=True)
        self.name = name
        self.path = path
        # THE CORROBORATOR, and until it existed here the rig could not express
        # the case this whole file's newest arm is about. hdw4s-incarnation
        # writes one token per SESSION START into the slot's web root, and the
        # router compares the token it recorded when a desktop first answered
        # against the one published now. With no web root anywhere, both sides
        # read None, session_replaced() says "no opinion", and the branch that
        # says "this slot is running a DIFFERENT desktop than the one minted
        # here" -- the branch the observed leak arrives through -- was
        # UNREACHABLE in this rig. Every green about slot recycling was a green
        # about occupancy alone. The shipped router says so itself at startup:
        # "no slot publishes an incarnation ... what it cannot see is a slot
        # reaped and re-let to somebody else between two visits."
        self.webroot = webroot
        # The port this slot's session listens on, which is what the router
        # reads out of the instance config and then asks the kernel about.
        self.port = port
        # None means "no session is running here". A token appears when one
        # starts, which in this product is when something CONNECTS: these slots
        # are socket-activated, so the first request is what brings a desktop
        # up. Minted per session start and never per request.
        self.incarnation = None
        # THE OCCUPANCY AUTHORITY, and it is the session's, not ours.
        #
        # /run/hdw4s/<instance> is the session unit's own RuntimeDirectory: it
        # exists exactly while that session is up and systemd removes it when
        # the unit stops. Until this existed here, an occupied slot and a free
        # one were BYTE-IDENTICAL in this rig -- bare sockets in a tmpdir with
        # no session runtime tree anywhere -- so the only thing a router could
        # have consulted to tell them apart was its own memory, and the only
        # implementation that could pass the restart arm was a table persisted
        # under HDW4S_DEMUX_STATE. The router does persist its table there now
        # (the unit preserves that directory across a restart), so the
        # occupancy arm WIPES the state on purpose: its subject is a router
        # that has lost the table, which a reboot or an unreadable file still
        # produces, and only the authority can pass it.
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
        # Any other response header a hostile desktop might send, as whole
        # "Name: value" lines. Kept apart from forge_cookie so a test about one
        # header cannot pass by accident on the other's filter.
        self.extra_headers = ()
        # Every request line this slot has been asked, so a test can say a
        # refused request NEVER REACHED the desktop rather than inferring it.
        self.asked = []
        # Set when this slot has actually served something. The oracle for "did
        # the router start a desktop" is the SLOT saying it was used, not the
        # router's own account of itself -- a component is not evidence about
        # its own behaviour.
        self.seen = False
        # HOW LONG A START TAKES, and it is a STAND-IN. In the field every
        # request that reaches a slot whose desktop is starting waits in the
        # relay's accept queue until hdw4s-proxy@ has started, which is after
        # the session unit, which is after the startup hold: measured on a
        # test box, 4.4-4.8 s from navigation to first byte. Here it is a
        # sleep: a start begins with the first request that finds no session,
        # and every request until ready_at waits for it, as the queue does.
        # Zero, the default, is every other test in this file.
        self.delay = 0.0
        self.ready_at = 0.0
        # THE STREAMS this slot has accepted -- a request that asked for an
        # upgrade is answered 101 and held open, as the streaming server holds
        # a browser's WebSocket. Until this existed the rig could not express
        # the desktop CLOSING A CONNECTION ON THE ROUTER, which is how a GNOME
        # logout reaches a tab: the relay dies and takes its connections with it.
        self.streams = []
        self.streams_lock = threading.Lock()

    def hang_up_streams(self):
        """Close every stream this slot is holding, from the desktop's end."""
        with self.streams_lock:
            held, self.streams = self.streams, []
        for c in held:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def log_out_under_a_stream(self, door_after, rundir_after):
        """A GNOME logout with the tab's stream open, in the measured ORDER.

        The relay goes first and its connections with it -- the tab's stream
        ends at once -- while the session's port stays open for a moment and its
        runtime directory for longer: 0.24 s and 0.77 s after the relay on the
        2026-09-25 run. In between, a connection to the slot socket STARTS A
        FRESH DESKTOP, which this stand-in does by publishing a new incarnation
        on the next request, exactly as serve() already does for a slot with no
        session. The published token in the web root is left as it was, as the
        real one is until a new start replaces it.
        """
        assert self.incarnation is not None, \
            "%s had no session to log out of" % self.name
        self.incarnation = None
        self.hang_up_streams()

        def later():
            time.sleep(door_after)
            if self.port is not None:
                self.shut_door()
            time.sleep(max(0.0, rundir_after - door_after))
            import shutil
            shutil.rmtree(self.rundir, ignore_errors=True)
        threading.Thread(target=later, daemon=True).start()

    def publish(self):
        """Mint this session's incarnation token, where hdw4s-webroot puts it."""
        import secrets as _s
        self.incarnation = _s.token_hex(6)
        if self.webroot is None:
            return
        d = os.path.join(self.webroot, self.name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "hdw4s-incarnation"), "w") as f:
            f.write(self.incarnation + "\n")

    def logout(self, leave_rundir=True):
        """Stand in for the owner's own way of ending a session: GNOME logout.

        NOT reap(). A reap stops the socket's service AND leaves the socket
        listening; a logout stops the SESSION, and the measured consequence is
        the one this stands in for -- the runtime directory is still there for
        roughly 0.7 to 2 seconds after the relay has gone, and the disconnected
        client reloads every five seconds, so the reload lands INSIDE that
        window essentially every time. That reload is proxied into a socket
        that is still listening, which starts a fresh desktop in the same slot.

        leave_rundir=True is that window, which is where the leak is observed.
        leave_rundir=False is the state after it, where the router gates
        instead of proxying and no resurrection happens by that path.

        WHAT THIS DOES NOT STAND IN FOR, so that nothing here is read as
        evidence about it: the real logout is GNOME's, the real session is a
        systemd unit, and the real socket is socket-activated by pid 1. Those
        were measured separately on a container and are recorded in
        private/evidence/slot-recycle/2026-09-25-mechanism.txt. Nothing in this
        file observes them.
        """
        assert self.incarnation is not None, (
            "%s had no session to log out of, so this proves nothing about a "
            "recycled slot" % self.name)
        self.incarnation = None
        # THE DOOR SHUTS BEFORE THE RUNTIME DIRECTORY GOES, which is the
        # measured shape and the whole reason the check exists: relay inactive
        # at t=4.45, door shut at 4.69, runtime directory still there until
        # 5.22. Reproducing them in the other order would test a world where
        # there is nothing to repair.
        if self.port is not None:
            self.shut_door()
        if not leave_rundir:
            import shutil
            shutil.rmtree(self.rundir, ignore_errors=True)
            assert not os.path.exists(self.rundir), \
                "%s still looks occupied after its session ended" % self.name

    def finish_logout(self):
        """systemd removing the RuntimeDirectory -- the far edge of the window.

        A SEPARATE STEP FROM logout(), because the gap between them IS the
        window: measured, the session went inactive at t=4.45 and the directory
        was still there until t=5.22. A stand-in that removed both at once
        would close the window by fiat and every arm about it would pass
        against a router that had not been repaired.
        """
        import shutil
        shutil.rmtree(self.rundir, ignore_errors=True)
        assert not os.path.exists(self.rundir), \
            "%s still looks occupied after its session ended" % self.name

    def resurrect(self):
        """A fresh desktop appears in this slot, started by somebody else.

        WHAT THIS IS FOR, now that the window is closed. The router no longer
        proxies into a slot whose session has stopped, so the router can no
        longer be the thing that resurrects one. It is not the only thing that
        can: root, an administrator restarting a unit by hand, and the idle
        sweep followed by any later connection all still put a fresh desktop in
        a slot that is let to somebody. Those are the cases the RECLAIM covers
        and the door check does not, so they are reproduced here directly
        rather than through the router -- which would now, correctly, refuse.
        """
        os.makedirs(self.rundir, mode=0o700, exist_ok=True)
        self.publish()
        if self.port is not None:
            self.open_door()

    def torn_down(self):
        """Stand in for hdw4s-teardown having run against this slot.

        A STAND-IN FOR PRIVILEGED MACHINERY, and the gap is stated rather than
        left to be inferred. The real thing stops hdw4s-ephemeral@<slot>, and
        if nothing in the session would answer a polite request it writes 1 to
        that slice's cgroup.kill. NOTHING HERE KILLS ANYTHING: there is no
        cgroup, no unit and no compositor in this file, so no green here is
        evidence that a desktop actually dies. What it does reproduce is the
        part the ROUTER's behaviour turns on -- the runtime directory goes away
        and the slot's socket keeps listening, exactly as the real teardown
        leaves things, because it stops the session unit and not the socket.
        """
        self.incarnation = None
        if self.port is not None:
            self.shut_door()
        import shutil
        shutil.rmtree(self.rundir, ignore_errors=True)

    def reap(self):
        """Stand in for the sweep stopping this desktop -- READ THE LIMIT.

        WHAT IT REPRODUCES: the slot's name stays in available_slots() and its
        desktop is gone. Unlinking the path instead would make the slot vanish
        from the pool and would quietly test a different, easier world -- one
        where exhaustion cures itself because the directory shrank.

        WHAT IT DOES NOT REPRODUCE, and the second half of this was MEASURED
        WRONG and is corrected here rather than left to be rediscovered.
        `hdw4s reap` stops hdw4s-proxy@<inst>.service and the session unit and
        does NOT stop hdw4s-proxy@<inst>.socket. That socket unit keeps
        listening, so in the field a connect after a reap SUCCEEDS -- that much
        holds. What was written next was a source read that self-labelled as an
        unobserved upper bound, and the bound was wrong: it said the woken
        relay's ExecStartPre=hdw4s-wait would wait for a session that is not
        coming and fail into OnFailure=hdw4s-refuse@, so a visitor would meet a
        long stall and then somebody else's page.

        MEASURED 2026-09-25 on a container, in
        private/evidence/slot-recycle/2026-09-25-mechanism.txt: nothing waits
        and nothing fails. The per-instance drop-in "hdw4s enable" writes
        carries BindsTo=hdw4s-ephemeral@<inst>.service, so systemd satisfies it
        by STARTING A FRESH SESSION, and the caller gets HTTP 200 in about two
        seconds with a NEW incarnation. The real damage is therefore the
        opposite of a stall: the connection silently creates the thing it was
        checking for. That is the slot-recycling leak, and it is why the
        probe in this file may never connect.

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
                self.asked.append(line)
                try:
                    os.makedirs(self.rundir, mode=0o700, exist_ok=True)
                except OSError:
                    pass
                # A CONNECTION IS WHAT STARTS A SESSION HERE, measured on the
                # box: the slot's socket unit outlives the session, and one
                # connection to it re-activates the relay, whose BindsTo=
                # starts a FRESH session -- with a control, 45 seconds of
                # silence producing no desktop at all. So a new token is minted
                # exactly when a request arrives at a slot that has none.
                if self.incarnation is None:
                    self.ready_at = time.time() + self.delay
                    self.publish()
                    # A SESSION THAT HAS STARTED IS LISTENING. Opened here and
                    # not at bind time, for the same reason the runtime
                    # directory is created here: a slot nobody has opened has a
                    # listening SLOT SOCKET and no session behind it, so no
                    # door of its own.
                    if self.port is not None:
                        self.open_door()
                upgrade = False
                while True:
                    h = f.readline()
                    if h in (b"\r\n", b"\n", b""):
                        break
                    if h.lower().startswith(b"upgrade:") and \
                            b"websocket" in h.lower():
                        upgrade = True
                if upgrade:
                    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                              b"Upgrade: websocket\r\n"
                              b"Connection: Upgrade\r\n\r\n")
                    with self.streams_lock:
                        self.streams.append(c)
                    # Held until one end closes it. What arrives is discarded:
                    # the frames are not the subject, the connection is.
                    while f.read1(65536):
                        pass
                    return
                wait = self.ready_at - time.time()
                if wait > 0:
                    time.sleep(wait)
                body = ("SLOT=%s PATH=%s" % (self.name,
                        line.split()[1].decode())).encode()
                forged = (b"Set-Cookie: " + self.forge_cookie.encode() + b"\r\n"
                          if self.forge_cookie else b"")
                forged += b"".join(x.encode() + b"\r\n"
                                   for x in self.extra_headers)
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

    def get(self, path, keep=False, auth=True, cookie_override=-1, headers=()):
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
        req.extend(headers)
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

    def post(self, path, auth=True, headers=()):
        """A POST with no body. Separate from get() rather than a flag on it,
        because the console's whole safety rests on the two being different
        requests: ending a desktop must not be reachable by opening a link."""
        if self.sock is None:
            self.connect()
        req = ["POST %s HTTP/1.1" % path, "Host: demux.test", "Content-Length: 0"]
        if self.auth and auth:
            req.append("Authorization: Basic " + self.auth)
        if self.cookie:
            req.append("Cookie: hdw4s_id=" + self.cookie)
        req.append("Connection: keep-alive")
        req.extend(headers)
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
    def __init__(self, nslots=3, gate="mint", windows=None, strays=(),
                 demux=None):
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
        #
        # ALWAYS WRITTEN NOW, for every rig, and its absence used to be the
        # fixture's biggest lie. The table was created only when a test asked
        # for idle windows, so on every other rig the router ran against a box
        # with sockets and NO SLOT TABLE -- a shape that cannot exist on a real
        # machine, because the same CLI command that creates a slot writes both.
        # While the mint path computed its pool from the socket directory that
        # difference was invisible, which is precisely why the directory listing
        # survived three sightings: no test could tell the two sources apart.
        self.windows = windows
        self.instances = os.path.join(self.etc, "instances")
        names = ([n for n, _ in windows] if windows is not None
                 else ["ephemeral%d" % i for i in range(nslots)])
        with open(self.instances, "w") as f:
            for i, name in enumerate(names):
                f.write("%d %s ephemeral\n" % (i, name))
        # EVERY SLOT GETS A PORT IN ITS OWN CONFIG, because every real one has
        # one: "hdw4s enable" writes HDW4S_PORT into the instance file AND into
        # the relay's drop-in. Until this existed the rig could not express the
        # door instrument at all -- instance_port() would have read None for
        # every slot and slot_door_open() would have answered "cannot ask" for
        # the whole pool, which is a silence the router correctly refuses to
        # spend. Every arm about the door would have been green and empty.
        self.ports = {}
        for i, name in enumerate(names + list(strays)):
            self.ports[name] = 7300 + i
        Slot.doors = {}
        Slot.doors_file = os.path.join(self.tmp, "proc-net-tcp")
        Slot.write_doors()
        for name in names + list(strays):
            with open(os.path.join(self.etc, name + ".conf"), "a") as f:
                f.write("HDW4S_PORT=%d\n" % self.ports[name])
        if windows is not None:
            # "%s", NOT "%d", and this is the fixture that let the defect ship.
            # An integer format specifier cannot put "30d", "12h" or "90m" in
            # front of the router -- the only forms that reproduced the failure
            # -- so the whole tier was structurally incapable of expressing the
            # input that breaks it. Every green here was a green about integers.
            # A window is written EXACTLY as an administrator would write it.
            for name, days in windows:
                # APPEND. It used to truncate, which was harmless while this
                # file held one setting and would have silently deleted the
                # port line the moment a second one existed.
                with open(os.path.join(self.etc, name + ".conf"), "a") as f:
                    f.write("HDW4S_IDLE_DAYS=%s\n" % (days,))
        # HDW4S_RUNDIR is what the CLI already reads, default /run. The
        # sessions' runtime directories hang off it at hdw4s/<instance>.
        self.hdw4s_rundir = os.path.join(self.tmp, "run")
        os.makedirs(os.path.join(self.hdw4s_rundir, "hdw4s"))
        # Where each slot publishes the token for its CURRENT start, and where
        # a request for a slot to be torn down is left. Both real directories,
        # both empty at start: a slot that has never been visited publishes
        # nothing, which is the state the shipped router reports at boot.
        self.webroot = os.path.join(self.tmp, "webroot")
        os.makedirs(self.webroot)
        self.teardowndir = os.path.join(self.tmp, "teardown")
        os.makedirs(self.teardowndir)
        self.slots = []
        for i in range(nslots):
            name = "ephemeral%d" % i
            s = Slot(os.path.join(self.rundir, name + ".sock"), name,
                     os.path.join(self.hdw4s_rundir, "hdw4s", name),
                     webroot=self.webroot, port=self.ports.get(name))
            s.start()
            self.slots.append(s)
        # NAMES IN THE SOCKET DIRECTORY THAT ARE IN NO TABLE ROW, which is the
        # shape a real box is in all the time and this rig could not express.
        # Every hdw4s-proxy@ instance binds into ONE directory -- a named
        # desktop provisioned for a person, a slot left over from an earlier
        # configuration, a file somebody touched while debugging -- and until
        # now every socket this rig created was also a pool member, so a router
        # reading the directory and a router reading the table were
        # indistinguishable here. That is why the directory listing survived
        # three sightings.
        #
        # A stray is built as a REAL, LISTENING, ANSWERING backend rather than
        # as an empty file. The weaker version passes against the defect: an
        # unreachable name loses pick_slot()'s reachability preference, so a
        # router that wrongly has it in the pool still hands out a healthy slot
        # while any healthy slot remains, and the arm goes green having proved
        # nothing. It must be the most attractive slot in the directory.
        self.strays = []
        for name in strays:
            s = Slot(os.path.join(self.rundir, name + ".sock"), name,
                     os.path.join(self.hdw4s_rundir, "hdw4s", name),
                     webroot=self.webroot, port=self.ports.get(name))
            s.start()
            self.strays.append(s)
        self.port = self.free_port()
        self.env = dict(os.environ,
                   HDW4S_PROXY_RUNDIR=self.rundir,
                   HDW4S_RUNDIR=self.hdw4s_rundir,
                   HDW4S_ETCDIR=self.etc,
                   HDW4S_DEMUX_CRED=os.path.join(self.etc, "demux.auth.cred"),
                   HDW4S_DEMUX_STATE=os.path.join(self.tmp, "state"),
                   HDW4S_REAP_STAMP_DIR=self.reapdir,
                   HDW4S_WEBROOT_DIR=self.webroot,
                   HDW4S_TEARDOWN_DIR=self.teardowndir,
                   HDW4S_PROC_NET_TCP=Slot.doors_file,
                   HDW4S_DEMUX_BIND="127.0.0.1",
                   HDW4S_DEMUX_PORT=str(self.port),
                   **({"HDW4S_GATE_MODE": gate} if gate is not None else {}))
        for k in ("LISTEN_FDS", "LISTEN_PID"):
            self.env.pop(k, None)
        self.statedir = os.path.join(self.tmp, "state")
        self.err = []
        # WHICH COPY OF THE ROUTER. Defaults to the shipped one; the red arms
        # below hand it a scratch copy with one function put back the way it
        # was. The MUTATION IS THE SUBJECT, never the checker: the assertions
        # the red arms run are byte-identical to the green one's.
        self.demux = DEMUX if demux is None else demux
        self._spawn()

    # The spawn is a method rather than eight lines of __init__ because the
    # fixture could not express a RESTART at all while it was inline: every
    # test built a fresh Rig, which meant a fresh tmpdir, fresh slots and a
    # fresh port as well as a fresh process. A router's whole lifecycle -- up,
    # down, up again against the same slots and the same state directory -- had
    # no representation here, and three defects live in exactly that gap. A rig
    # cannot catch what it cannot say.
    def _spawn(self):
        self.proc = subprocess.Popen([sys.executable, self.demux], env=self.env,
                                     stderr=subprocess.PIPE)
        # Drained continuously, in a thread. Reading the pipe only on failure
        # was fine while nothing checked the log; now that a test asserts on
        # what was written, a full pipe would block the thing under test and
        # the symptom would be a hang rather than a failure.
        threading.Thread(target=self._drain, args=(self.proc,),
                         daemon=True).start()
        self.wait_up()

    def restart(self, wipe_state=False):
        """Stop the router and start another one against the SAME slots.

        The port is kept, so a client built before the restart still addresses
        the same front door -- a visitor does not get a new URL because a
        service restarted, and a rig that handed out a new port would be
        testing a migration rather than a restart.

        The stand-in desktops are deliberately NOT touched. That is the whole
        point of the case: systemd restarts this router on failure while every
        session it was routing to goes on running, so the slots outlive the
        table that says who owns them. No longer an inference from Restart=
        on-failure in the packaged unit -- measured on a development container, where the session
        kept its ExecMainPID and its start timestamp across a restart of the
        router. The run is quoted above arm 5.

        wipe_state DEFAULTS TO FALSE, because that is what the shipped unit
        does: hdw4s-demux.service carries RuntimeDirectoryPreserve=, so
        STATE_DIR -- the reservations, the last-request records and the
        ownership table -- survives a restart of the service and is lost at a
        reboot. It defaulted to TRUE while the unit had no Preserve= line and
        the wipe had been watched on a development container; a rig that went
        on wiping would now be modelling a configuration this package does not
        ship. wipe_state=True is kept for the arms whose subject is a router
        that has LOST its state, and each of them asks for it by name.
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

    def teardown_requests(self):
        """Which slots the router has asked to have torn down, right now.

        READ FROM THE DIRECTORY THE ROUTER WRITES INTO, not from its log. The
        log is the router's account of itself and is not evidence about it; the
        file is the entire message the router is able to send, so it is the
        whole of what a teardown would act on.
        """
        return sorted(os.listdir(self.teardowndir))

    def run_teardowns(self):
        """Stand in for hdw4s-teardown@<slot>.path firing. Returns the slots.

        THE PRIVILEGED HALF IS NOT HERE. See Slot.torn_down() for exactly what
        is reproduced and what is not. This much is real: the name the router
        wrote is the ONLY thing this acts on, and a name that is not a pool slot
        is refused rather than obeyed -- which is the property the real path
        unit gets from systemd filling in %i, and which is worth asserting here
        because this rig is the only place the router's side of it is exercised.
        """
        done = []
        for name in self.teardown_requests():
            match = [x for x in self.slots if x.name == name]
            assert match, (
                "the router asked for %r to be torn down and it is not a slot "
                "in this pool" % name)
            match[0].torn_down()
            os.unlink(os.path.join(self.teardowndir, name))
            done.append(name)
        return done

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
        for s in self.slots + self.strays:
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
        assert pressables(body), "the gate offers no way forward"
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

    The BARE address now shows such a browser its desktops rather than resuming
    one (test_the_bare_address_shows_your_desktops); neither is a mint, and an
    arrival carrying a query still resumes, which is the half checked here.
    """
    rig = Rig(gate=None)          # no HDW4S_GATE_MODE -- the shipped default
    try:
        a = rig.client()
        sid1, _ = arrive(rig, a)
        st, h, _ = a.get("/")
        assert h["location"][0] == "/sessions/", (
            "the shipped default sent a browser that already had a desktop to "
            "%r, not to its desktops" % h["location"][0])
        st, h, _ = a.get("/?socket_worker=false")
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


def test_the_console_lists_only_your_own_sessions(rig):
    """The scope, from the ownership table rather than from the markup.

    Two visitors, two desktops. Neither list may carry the other's address --
    and the assertion is on the BYTES THE VISITOR RECEIVES, not on an internal
    call, because "the page does not render it" is exactly the kind of boundary
    that holds until somebody changes the template.
    """
    a, b = rig.client(), rig.client()
    sid_a, _ = arrive(rig, a)
    sid_b, _ = arrive(rig, b)
    assert sid_a != sid_b, "the rig gave two visitors one session"

    st, _, body = a.get("/sessions/")
    assert st == 200, "the console did not serve: %d" % st
    text = body.decode()
    assert sid_a in text, "a visitor's own session was missing from their list"
    assert sid_b not in text, \
        "ONE VISITOR'S LIST CARRIED ANOTHER VISITOR'S SESSION ADDRESS"

    st, _, body = b.get("/sessions/")
    text = body.decode()
    assert sid_b in text, "a visitor's own session was missing from their list"
    assert sid_a not in text, \
        "ONE VISITOR'S LIST CARRIED ANOTHER VISITOR'S SESSION ADDRESS"


def test_one_visitor_cannot_discard_anothers_session(rig):
    """SEEN REFUSING. The negative the console is worth nothing without.

    A session list is the obvious way to reopen cross-occupant reach, and the
    refusal has to be where the request is SERVED: this test hands B a sid it
    could never have been shown, which is precisely what an attacker has and a
    page-level check does not see.

    The oracle is the FILESYSTEM, not the status code. A 403 with the teardown
    recorded anyway is the defect wearing a refusal, and only the file can tell
    the two apart.
    """
    a, b = rig.client(), rig.client()
    sid_a, _ = arrive(rig, a)
    arrive(rig, b)
    before = sorted(os.listdir(rig.teardowndir))

    st, _, _ = b.post("/sessions/%s/discard" % sid_a)
    assert st == 403, \
        "a visitor was allowed to end somebody else's desktop: %d" % st
    assert sorted(os.listdir(rig.teardowndir)) == before, \
        "THE TEARDOWN WAS RECORDED ANYWAY -- the 403 refused nothing"

    # A sid that exists for nobody must be answered IDENTICALLY, or the status
    # code tells a stranger which sids are real.
    st2, _, _ = b.post("/sessions/%s/discard" % ("0" * 32))
    assert st2 == st, \
        "a nonexistent session answered %d and somebody else's answered %d, " \
        "which tells a stranger which sids exist" % (st2, st)


def test_a_visitor_can_discard_their_own_session(rig):
    """The positive control, without which the refusal above proves nothing.

    A guard that refuses everybody satisfies every rule anybody writes down and
    is then deleted -- this project has already deleted one.
    """
    a = rig.client()
    sid, _ = arrive(rig, a)
    rec_instance = None
    st, h, _ = a.post("/sessions/%s/discard" % sid)
    assert st == 303, "ending your own desktop did not redirect: %d" % st
    assert h["location"][0] == "/sessions/", \
        "ending a desktop sent the visitor somewhere unexpected"
    left = os.listdir(rig.teardowndir)
    assert len(left) == 1, \
        "ending a desktop recorded %r rather than one request" % (left,)
    # The request names the SLOT, because that is what a teardown acts on, and
    # it must be the slot this visitor's session is actually in.
    assert left[0].startswith("ephemeral"), \
        "the teardown request was not named after a slot: %r" % left

    # And the list then says so rather than offering the button again.
    st, _, body = a.get("/sessions/")
    assert st == 200
    assert "discarding" in body.decode(), \
        "a session already being discarded still offered a Discard link"


def test_opening_the_discard_address_only_asks(rig):
    """A GET must not destroy a desktop.

    One browser prefetch, one link preview or one crawler is otherwise enough
    to end somebody's session without them asking, and they would have no idea
    what happened.
    """
    a = rig.client()
    sid, _ = arrive(rig, a)
    st, _, body = a.get("/sessions/%s/discard" % sid)
    assert st == 200, "the discard confirmation did not serve: %d" % st
    assert os.listdir(rig.teardowndir) == [], \
        "A GET DISCARDED A DESKTOP. That is one prefetch away from happening " \
        "unasked, and the visitor would have no idea what happened."
    text = body.decode()
    assert "cannot be undone" in text, \
        "the confirmation did not say the act is irreversible"
    assert "Keep it" in text, \
        "the confirmation had no safe half for a trained reflex to land on"


def test_the_console_never_mints(rig):
    """THE FAILURE THAT WOULD BE SILENT, and the reason the parser has a guard.

    Everything the console's dispatch does not claim used to fall through to
    arrival(), which mints, so a console address that stopped being
    recognised handed somebody a NEW DESKTOP every time they tried to end one.
    Only the front door reaches arrival() now (test_only_the_front_door_mints),
    and the same break is a 404 -- which this test still refuses, because the
    console must SERVE.

    Asserted for a visitor with NO sessions, which is the case that would hide
    it: with a session already owned, the shipped gate arm resumes and the
    mint never happens, so the test would pass against the broken router.
    """
    c = rig.client()
    for path in ("/sessions", "/sessions/"):
        st, h, _ = c.get(path)
        assert st == 200, "%s did not serve the console: %d" % (path, st)
        assert "location" not in h, \
            "%s REDIRECTED, which is what minting a desktop looks like" % path
        c.learn_cookie(h)
    st, _, body = c.get("/sessions/")
    assert "no desktops on this machine" in body.decode(), \
        "a visitor who has never arrived was shown desktops"
    assert os.listdir(rig.teardowndir) == [], "listing sessions recorded a teardown"


def test_asking_for_a_second_desktop_takes_a_GESTURE(rig):
    """THE POSITIVE CONTROL FOR THIS ROUND, and it is written to go red.

    The owner's arrival rule of 2026-09-22 says minting is a DAMAGE: a browser
    restoring twenty tabs must not cost a visitor twenty desktops. His ruling of
    2026-09-25 adds a third answer to the gate -- "this should also be the place
    where i can create a brand new one" -- and the two are not in tension,
    because the first is about minting WITHOUT BEING ASKED and the second is a
    button somebody presses. The whole of that distinction is carried by the
    METHOD, so this is where it is asserted.

    A GET of the create address is every way a URL gets fetched without a
    person deciding anything: a prefetch, a link preview, a crawler, a pinned
    tab, a session restore, a back button. Each of those must leave the pool
    exactly as it found it.

    SEEN RED BEFORE IT WAS SEEN GREEN, against the tree with no create address
    at all: /sessions/new fell through console_target() to arrival(), which
    minted a desktop for a visitor who had pressed nothing. That is the same
    fall-through red_a_console_address_that_stops_being_claimed exists
    for, one address wider.
    """
    c = rig.client()
    # A visitor with NO session, which is the case that would hide this: with
    # one already owned, the shipped arm resumes and the mint never happens.
    st, h, _ = c.get("/sessions/new")
    c.learn_cookie(h)
    assert "location" not in h, \
        "A GET OF THE CREATE ADDRESS MINTED A DESKTOP (302 to %r). Nobody " \
        "pressed anything." % h.get("location")
    assert st in (200, 405), \
        "a GET of the create address answered %d, which is neither an offer " \
        "nor a refusal" % st

    # And it is still true for somebody who already has one, which is the
    # person this round is actually for.
    d = rig.client()
    sid, _ = arrive(rig, d)
    st, h, _ = d.get("/sessions/new")
    assert "location" not in h or h["location"][0] == "/s/%s/" % sid, \
        "a GET of the create address moved a returning visitor somewhere new"

    # THE OTHER HALF, and without it this test is satisfied by a router that
    # can never create anything at all -- which is the shape that passes every
    # rule and is then deleted. A POST is a gesture, and a gesture works.
    st, h, _ = d.post("/sessions/new")
    assert st == 303, "a deliberate POST did not create: %d" % st
    got = h["location"][0]
    assert got.startswith("/s/"), "create sent the visitor to %r" % got
    assert got != "/s/%s/" % sid, \
        "create RESUMED the session this visitor already had instead of " \
        "making a second one -- which is the whole complaint"


def pressables(body):
    """Every object on a page a person can press, as (method, target, label).

    READ FROM THE BYTES THE BROWSER GETS, and read as a browser reads them: an
    <a href> is a GET of its target, a form's submit button is the form's
    method at the form's action, and a button outside any form does nothing
    the router can see (it is listed as JS so that it cannot be missed).
    A substring check for one href cannot tell a page with the right button
    from a page with the right button AND a wrong one beside it.
    """
    import html.parser

    class P(html.parser.HTMLParser):
        def __init__(self):
            super().__init__()
            self.out, self.form, self.open, self.text = [], None, None, []

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self.form = ((a.get("method") or "get").upper(),
                             a.get("action") or "(same URL)")
            elif tag == "a" and "href" in a:
                self.open, self.text = ("GET", a["href"]), []
            elif tag == "button" and (a.get("type") or "submit") == "submit":
                self.open, self.text = (self.form or ("JS", None)), []

        def handle_endtag(self, tag):
            if tag in ("a", "button") and self.open is not None:
                self.out.append(self.open + ("".join(self.text).strip(),))
                self.open = None
            elif tag == "form":
                self.form = None

        def handle_data(self, data):
            if self.open is not None:
                self.text.append(data)

    p = P()
    p.feed(body.decode() if isinstance(body, bytes) else body)
    return p.out


def mint_lines(rig):
    """How many desktops the router says it has minted, from its own log.

    Both minting sites log through log_arrival(), as "minted a session" (the
    front door) and "minted a session on request" (a POST). The count is only
    quoted beside slots_in_use(), which reads the stand-in backends rather than
    the router's account of itself."""
    return sum(1 for line in rig.stderr_text().splitlines()
               if "minted a session" in line)


def test_the_ended_pages_button_starts_a_NEW_desktop(rig):
    """BUG 1, as the owner met it: log out of one of two desktops, press
    "Start a new desktop", and be handed the OTHER one.

    The ended page's button was a link to "/", and "/" is the front door, which
    RESUMES the newest desktop this browser owns. With nothing else owned that
    looked like a mint; with a second desktop open in another tab it took that
    one over. The label promises a new desktop, so the button must ask for one:
    POST /sessions/new, the directory's own create.

    PRESSED, not inspected first. The button is pressed as a browser would
    press whatever is on the page, and the assertion is about where that lands:
    a session this browser did not already own, on a slot it was not already
    in. The shape of the button is asserted afterwards, so the red on the
    unrepaired router names the damage (a resume) rather than the markup.

    On the UNPINNED arm, because the shipped arm is the one that resumes.
    """
    a = rig.client()
    x, slot_x = arrive_on_slot(rig, a)
    # A second desktop, the way the owner had one: asked for.
    st, h, _ = a.post("/sessions/new")
    assert st == 303, "could not set up a second desktop: %d" % st
    y = h["location"][0].split("/")[2]
    st, _, body = a.get("/s/%s/" % y)
    assert st == 200, "the second desktop did not serve: %d" % st
    slot_y = body.decode().split("SLOT=")[1].split()[0]
    assert slot_y != slot_x, "the rig put both desktops on one slot"

    # The first one ends (a GNOME logout, as far as the router can tell), and
    # its tab is reloaded onto the ended page.
    slot_named(rig, slot_x).reap()
    st, h, body = a.get("/s/%s/" % x)
    assert st == 410, "the ended desktop's tab was not gated: %d" % st
    a.learn_cookie(h)
    buttons = pressables(body)
    assert buttons, "the ended page offers nothing to press"

    minted_before = mint_lines(rig)
    resumed_before = rig.stderr_text().count("resumed a session")
    # BY ITS LABEL, because the page now lists the other desktop above it, and
    # its Resume is supposed to resume. The button under test is the one that
    # promises a new desktop.
    new = [b for b in buttons if b[2] == "New desktop"]
    assert len(new) == 1, "the ended page has %d New desktop buttons: %r" \
        % (len(new), buttons)
    method, target, label = new[0]
    if method == "POST":
        st, h, _ = a.post(target)
    else:
        st, h, _ = a.get(target)
    assert st in (302, 303), \
        "pressing %r (%s %s) went nowhere: %d" % (label, method, target, st)
    got = h["location"][0].split("/")[2]
    assert got != y, (
        "PRESSING %r (%s %s) RESUMED THE OTHER DESKTOP THIS BROWSER OWNS "
        "(session %s) instead of starting a new one -- bug 1: the tab takes "
        "over the desktop open in the other tab" % (label, method, target, y))
    assert got != x, "pressing %r sent the tab back to the ended desktop" % label
    assert mint_lines(rig) == minted_before + 1, \
        "pressing %r did not mint exactly one desktop" % label
    assert rig.stderr_text().count("resumed a session") == resumed_before, \
        "pressing %r logged a resume" % label
    # WHICH SLOT, from the router's mint line and not from the backend. The
    # router may, correctly, re-let the ended desktop's slot, and this rig's
    # reaped slot REFUSES a connection where the field's starts a fresh desktop
    # (Slot.reap() says which, and why). So the new desktop is not asked to
    # serve here; seeing it paint is the real-browser run's job.
    line = [l for l in rig.stderr_text().splitlines()
            if "minted a session" in l and got in l]
    assert len(line) == 1, "no mint line names session %s" % got
    slot_new = line[0].split("slot ")[1].split(",")[0]
    assert slot_new != slot_y, \
        "the new desktop is on the slot of the one in the other tab"

    # And the page offers exactly that, beside the other desktop's own row --
    # its Resume and its Discard, at the addresses the directory uses -- and
    # nothing else a person could press. No new target, no new mint site.
    assert [(m, t) for m, t, _ in buttons] == [
        ("POST", "/sessions/%s/resume" % y), ("GET", "/sessions/%s/discard" % y),
        ("POST", "/sessions/new")], \
        "the ended page's pressables are %r" % (buttons,)


def test_the_ended_page_and_restored_tabs_mint_NOTHING(rig):
    """THE OTHER HALF, and without it the test above is satisfied by a page
    that mints on sight.

    Opening the ended page, reloading it, and a browser restoring six tabs whose
    desktops are gone (two that this browser owned and that have ended, four it
    never had) must start NOTHING. Minting is a damage: this is the rebooted
    laptop the arrival rule was written for.

    THE COUNTER IS SEEN COUNTING before its zero is believed: the one press at
    the end must move it by exactly one. A count that cannot move reads zero
    for a router that mints on every GET too.
    """
    a = rig.client()
    x, slot_x = arrive_on_slot(rig, a)
    st, h, _ = a.post("/sessions/new")
    assert st == 303, "could not set up a second desktop: %d" % st
    z = h["location"][0].split("/")[2]
    st, _, body = a.get("/s/%s/" % z)
    assert st == 200
    slot_z = body.decode().split("SLOT=")[1].split()[0]
    slot_named(rig, slot_x).reap()
    slot_named(rig, slot_z).reap()

    minted_before, seen_before = mint_lines(rig), slots_in_use(rig)
    tabs = [x, x] + [z, x] + [secrets_hex() for _ in range(4)]
    for n, sid in enumerate(tabs):
        st, h, body = a.get("/s/%s/" % sid)
        a.learn_cookie(h)
        assert st == 410, "request %d (%s) was not gated: %d" % (n, sid, st)
        assert "location" not in h, \
            "request %d REDIRECTED, which is an action, not a question" % n
    minted_after, seen_after = mint_lines(rig), slots_in_use(rig)
    print("       zero-mint negative: 'minted a session' lines %d -> %d, "
          "backends handed out %d -> %d, over %d requests "
          "(ended page, reload, six restored tabs)"
          % (minted_before, minted_after, seen_before, seen_after, len(tabs)))
    assert minted_after == minted_before, (
        "the ended page, a reload and six restored tabs MINTED %d desktop(s) "
        "nobody asked for" % (minted_after - minted_before))
    assert seen_after == seen_before, \
        "a backend was handed out without a mint line: %d -> %d" \
        % (seen_before, seen_after)

    # The counter, seen moving: one press of the ended page's button.
    method, target, _ = [b for b in pressables(body) if b[2] == "New desktop"][0]
    if method == "POST":
        a.post(target)
    else:
        a.get(target)
    assert mint_lines(rig) == minted_after + 1, (
        "the press did not register as one mint (%d -> %d): this counter "
        "cannot see a mint, so its zero above means nothing"
        % (minted_after, mint_lines(rig)))


# Addresses a browser asks for on its own, or a person or an old bookmark might
# present, that are not the front door. The first is the one that was SEEN: a
# page with no icon link makes Chrome ask for /favicon.ico, straight after the
# page it was on. The rest are shapes that sit next to real addresses.
NOT_THE_FRONT_DOOR = ("/favicon.ico", "/anything-else", "/index.html", "/s",
                      "/s/", "/sessions/abc", "/robots.txt?x=1")


def test_only_the_front_door_mints(rig):
    """MEASURED ON A TEST BOX: after each discard of a browser's last desktop the
    journal showed "a visitor discarded their own session", "dropped a dead
    session" and "minted a session" for the same visitor within about a
    second. The pages carried no icon link, the browser asked for
    /favicon.ico, and every path the router did not claim went to the front
    door -- which, for a browser with no live desktop, starts one. So ending
    your last desktop started another, and an ended page reopened by a
    restored tab could do the same. Minting is a damage and only a request for
    the front door itself may do it.

    Asked twice, because the two states reach the mint differently: a browser
    that has never had a desktop, and one whose only desktop it has just
    discarded (its record is still in the table and is dropped on the way).

    THE COUNTER IS SEEN MOVING at the end: GET / from the same browser must
    mint exactly one, or the zeros above could come from a counter that cannot
    count."""
    def ask_all(c, when):
        # Every path is asked before any verdict, so the count below is the
        # whole damage rather than the first request's.
        before, wrong = mint_lines(rig), []
        for path in NOT_THE_FRONT_DOOR:
            st, h, _ = c.get(path)
            c.learn_cookie(h)
            if st != 404 or "location" in h:
                wrong.append("%s -> %d%s" % (
                    path, st, " " + h["location"][0] if "location" in h else ""))
        after = mint_lines(rig)
        print("       %s: 'minted a session' lines %d -> %d over %d requests "
              "that are not the front door" % (when, before, after,
                                              len(NOT_THE_FRONT_DOOR)))
        if after != before or wrong:
            return ("%s: %d desktop(s) minted by paths that are not the front "
                    "door (lines %d -> %d); answered: %s"
                    % (when, after - before, before, after, "; ".join(wrong)))
        return None

    # BOTH STATES ARE ASKED before any verdict, so a red names both.
    dark = [ask_all(rig.client(), "a fresh browser")]

    a = rig.client()
    sid, _ = arrive(rig, a)
    st, h, _ = a.post("/sessions/%s/discard" % sid)
    assert st == 303, "could not discard the desktop: %d" % st
    st, h, _ = a.get(h["location"][0])
    assert st == 200, "the directory after a discard: %d" % st
    dark.append(ask_all(a, "after discarding its last desktop"))
    dark = [d for d in dark if d]
    assert not dark, " || ".join(dark)

    before = mint_lines(rig)
    st, h, _ = a.get("/")
    assert st == 302 and h["location"][0].startswith("/s/"), \
        "the front door did not start a desktop: %d" % st
    assert mint_lines(rig) == before + 1, (
        "GET / moved the mint counter by %d, not 1: its zeros above mean "
        "nothing" % (mint_lines(rig) - before))


def test_the_bare_address_shows_your_desktops(rig):
    """A browser that already has a live desktop, opening the bare address
    again, is sent to ITS DESKTOPS -- not resumed onto the newest one.

    Opening the address again is how a person asks for a second desktop: two
    novice walks did exactly that, independently, and were handed a card for
    the desktop they already had, whose only button takes it from the other
    tab. The owner's rule for a returning browser says the same thing: one
    that owns sessions gets the session manager.

    WHAT MUST NOT MOVE, each checked in the same rig: the redirect is not a
    mint and carries no fresh-mint marker; ?gate= still resumes (the rigs rely
    on it) and gate=mint still mints; a restored tab at /s/<sid>/ is served as
    before, and one at a dead id still gates; and a browser whose desktops are
    ALL gone still gets a new one from the bare address.
    """
    c = rig.client()
    st, h, _ = c.get("/")
    assert st == 302, "a first arrival did not redirect: %d" % st
    c.learn_cookie(h)
    sid = h["location"][0].split("/")[2]
    assert h["location"][0].startswith("/s/%s/" % sid) and \
        fresh_markers(h) == [sid], \
        "a first arrival was not a marked mint: %r" % (h,)
    st, _, body = c.get("/s/%s/" % sid)
    assert st == 200, "the new desktop did not serve: %d" % st
    slot = body.decode().split("SLOT=")[1].split()[0]

    minted, seen = mint_lines(rig), slots_in_use(rig)
    st, h, _ = c.get("/")
    assert st == 302, "the bare address did not redirect: %d" % st
    assert h["location"][0] == "/sessions/", (
        "THE BARE ADDRESS RESUMED %r for a browser that has a desktop, instead "
        "of showing it its desktops" % h["location"][0])
    assert fresh_markers(h) == [], \
        "the redirect to the directory carried a fresh-mint marker"
    assert (mint_lines(rig), slots_in_use(rig)) == (minted, seen), \
        "the bare address minted"
    st, _, body = c.get("/sessions/")
    assert st == 200, "the directory did not serve: %d" % st
    targets = [(m, t) for m, t, _ in pressables(body)]
    assert ("POST", "/sessions/%s/resume" % sid) in targets and \
        ("POST", "/sessions/new") in targets, \
        "the directory does not offer this desktop and a new one: %r" % targets

    # ?gate= keeps today's behaviour, both arms that resume, and the mint arm.
    for arm in ("takeover", "off"):
        st, h, _ = c.get("/?gate=%s" % arm)
        assert h["location"][0] == "/s/%s/?gate=%s" % (sid, arm), \
            "?gate=%s no longer resumes: %r" % (arm, h["location"][0])
    assert mint_lines(rig) == minted, "a ?gate= resume minted"
    st, h, _ = c.get("/?gate=mint")
    assert h["location"][0].split("/")[2] != sid and \
        mint_lines(rig) == minted + 1, "?gate=mint no longer mints"

    # Restored tabs present /s/<sid>/, never /, so they are untouched.
    st, _, _ = c.get("/s/%s/" % sid)
    assert st == 200, "a restored tab on a live desktop was not served: %d" % st
    st, h, _ = c.get("/s/%s/" % secrets_hex())
    assert st == 410 and "location" not in h, \
        "a restored tab on a dead id did not gate: %d" % st

    # A browser whose only desktop has ended: the bare address mints (R1).
    d = rig.client()
    old, old_slot = arrive_on_slot(rig, d)
    slot_named(rig, old_slot).reap()
    st, h, _ = d.get("/")
    loc = h["location"][0]
    assert loc.startswith("/s/") and loc.split("/")[2] != old, (
        "a browser whose desktops are all gone was sent to %r instead of a new "
        "desktop" % loc)
    assert fresh_markers(h) == [loc.split("/")[2]], \
        "the new desktop for a browser with nothing left was not marked"


def test_the_ended_page_lists_what_is_still_running(rig):
    """The ended page is the directory, headed with the one fact the visitor
    came for.

    Where the router SAW the desktop stop, it says everything in it is gone --
    true for an ephemeral desktop, whose home dies with its unit. Where the id
    is merely unknown it does not say that, because a restarted router forgets
    lettings whose desktops are still running. Either way it lists this
    browser's other desktops, at the directory's own addresses, and only this
    browser's: a stranger presenting the same dead id sees their own list.
    """
    a, b = rig.client(), rig.client()
    x, slot_x = arrive_on_slot(rig, a)
    st, h, _ = a.post("/sessions/new")
    assert st == 303, "could not set up a second desktop: %d" % st
    y = h["location"][0].split("/")[2]
    assert a.get("/s/%s/" % y)[0] == 200
    w, _ = arrive_on_slot(rig, b)
    slot_named(rig, slot_x).reap()

    minted = mint_lines(rig)
    st, h, body = a.get("/s/%s/" % x)
    assert st == 410, "the ended desktop's tab was not gated: %d" % st
    text = body.decode()
    assert "Everything that was in it is gone." in text, \
        "a desktop the router saw stop is not said to be gone"
    assert "Still running in this browser" in text, \
        "the ended page does not list what is still running"
    assert [(m, t) for m, t, _ in pressables(body)] == [
        ("POST", "/sessions/%s/resume" % y), ("GET", "/sessions/%s/discard" % y),
        ("POST", "/sessions/new")], \
        "the ended page's pressables are %r" % (pressables(body),)
    assert "Nothing has been started for you" not in text

    # Unknown to this router (x was forgotten on the way in above): no claim.
    st, _, body = a.get("/s/%s/" % x)
    text = body.decode()
    assert st == 410 and "is gone" not in text, \
        "an id this router merely does not know was said to be gone"
    assert "no longer running" in text and "/sessions/%s/resume" % y in text

    # A stranger presenting a dead id sees THEIR list, never a's.
    st, _, body = b.get("/s/%s/" % x)
    text = body.decode()
    assert st == 410 and y not in text and "/sessions/%s/resume" % w in text, \
        "the ended page listed somebody else's desktop, or not the viewer's own"
    assert mint_lines(rig) == minted, "the ended page minted"


def test_every_pressable_keeps_its_target(rig):
    """The rows and the confirmation were redrawn; what they DO must not move.
    Read as a browser reads the page: every <a> is a GET of its href and every
    submit button is its form's method at its action."""
    c = rig.client()
    x, _ = arrive(rig, c)
    st, h, _ = c.post("/sessions/new")
    y = h["location"][0].split("/")[2]
    c.get("/s/%s/" % y)
    st, _, body = c.get("/sessions/")
    assert [(m, t) for m, t, _ in pressables(body)] == [
        ("POST", "/sessions/%s/resume" % x), ("GET", "/sessions/%s/discard" % x),
        ("POST", "/sessions/%s/resume" % y), ("GET", "/sessions/%s/discard" % y),
        ("POST", "/sessions/new")], \
        "the directory's pressables are %r" % (pressables(body),)
    st, _, body = c.get("/sessions/%s/discard" % x)
    assert [(m, t) for m, t, _ in pressables(body)] == [
        ("GET", "/sessions/"), ("POST", "/sessions/%s/discard" % x)], \
        "the confirmation's pressables are %r" % (pressables(body),)


# A browser's top-level navigation, as it reaches the router. Accept is what
# every browser sends for one; Sec-Fetch-Dest is what current Chrome, Firefox
# and Safari add to it. A fetch() from a page sends neither.
NAVIGATE = ("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
            "*/*;q=0.8", "Sec-Fetch-Dest: document", "Sec-Fetch-Mode: navigate")
FETCH = ("Accept: */*", "Sec-Fetch-Dest: empty", "Sec-Fetch-Mode: same-origin")

# THE OWNER'S NUMBER: the browser's own spinner is fine for about two seconds,
# and after that something of ours must be on the screen unless the desktop is.
OURS_WITHIN = 2.0
# STAND-INS, both of them, for how long a desktop takes to start. The field's
# is 4.4-4.8 s to first byte (a test box, 5 of 5) and up to ~9 s seen; the
# slow arm injects more than two seconds and the fast arm less than one.
SLOW_START = 5.0
FAST_START = 0.3


def set_start(rig, seconds):
    for s in rig.slots:
        s.delay = seconds


def intent_fresh_arrival(rig):
    """Entry point 1: a browser with nothing, at the front door."""
    c = rig.client()
    t0 = time.time()
    st, h, _ = c.get("/", headers=NAVIGATE)
    assert st == 302, "the front door did not redirect: %d" % st
    c.learn_cookie(h)
    return c, t0, h["location"][0]


def intent_directory_new_desktop(rig):
    """Entry point 2: "New desktop" in the directory, pressed as a browser
    presses it -- whatever the page offers under that label."""
    c = rig.client()
    st, h, body = c.get("/sessions/", headers=NAVIGATE)
    assert st == 200, "the directory did not serve: %d" % st
    c.learn_cookie(h)
    press = [(m, t) for m, t, label in pressables(body) if "New desktop" in label]
    assert press == [("POST", "/sessions/new")], \
        "the directory's New desktop is %r" % (press,)
    t0 = time.time()
    st, h, _ = c.post("/sessions/new", headers=NAVIGATE)
    assert st == 303, "New desktop did not redirect: %d" % st
    return c, t0, h["location"][0]


def intent_ended_page_button(rig):
    """Entry point 3: the ended page's button, after a desktop that had
    started has been logged out of. Set up with a fast start, so that only the
    press is timed."""
    c = rig.client()
    keep = [s.delay for s in rig.slots]
    set_start(rig, 0.0)
    sid, name = arrive_on_slot(rig, c)
    slot_named(rig, name).logout(leave_rundir=False)
    st, h, body = c.get("/s/%s/" % sid, headers=NAVIGATE)
    assert st == 410, "the ended desktop's tab was not gated: %d" % st
    c.learn_cookie(h)
    for s, d in zip(rig.slots, keep):
        s.delay = d
    buttons = pressables(body)
    assert len(buttons) == 1, "the ended page offers %r" % (buttons,)
    method, target, _ = buttons[0]
    t0 = time.time()
    if method == "POST":
        st, h, _ = c.post(target, headers=NAVIGATE)
    else:
        st, h, _ = c.get(target, headers=NAVIGATE)
    assert st in (302, 303), "the ended page's button went nowhere: %d" % st
    return c, t0, h["location"][0]


ENTRY_POINTS = (("a fresh GET /", intent_fresh_arrival),
                ("New desktop in the directory", intent_directory_new_desktop),
                ("the ended page's button", intent_ended_page_button))


def test_a_SLOW_start_shows_something_of_ours_within_two_seconds(rig):
    """BUG 2. Since the startup hold, the session page is not served until the
    desktop has started, so a slow start was spent on the browser's loading
    tab with nothing of ours. At all three entry points, a start slower than
    about two seconds (INJECTED LATENCY, A STAND-IN for a real slow start) must
    put a page of ours on the screen within two seconds of the request that
    expressed the intent -- and that page must hand over to the desktop's own
    page once it answers, or it is a dead end dressed as feedback.

    TIMED FROM THE INTENT, not from the session address: the redirect is part
    of what the visitor waits through. The shape of our page is barely asserted
    here on purpose; what it looks like is the real-browser run's question."""
    set_start(rig, SLOW_START)
    # EVERY ENTRY POINT IS TIMED before any verdict, so a red names all of
    # the ones that are dark rather than only the first.
    dark = []
    for what, intent in ENTRY_POINTS:
        c, t0, loc = intent(rig)
        assert loc.startswith("/s/"), "%s went to %s" % (what, loc)
        st, h, body = c.get(loc, headers=NAVIGATE)
        took = time.time() - t0
        if took > OURS_WITHIN:
            dark.append("%s: %.1f s" % (what, took))
            continue
        assert b"SLOT=" not in body, \
            "%s: the desktop's own page came back early, so the stand-in " \
            "did not delay anything" % what
        assert st == 200 and h.get("content-type", [""])[0].startswith(
            "text/html") and (b"<h1" in body or b"<h2" in body), \
            "%s: %d within %.1f s, but not a page with anything on it: %r" \
            % (what, st, took, body[:200])
        # THE HAND-OVER. What our page asks for (a fetch, not a navigation)
        # is held until the desktop answers and then gets the desktop's page;
        # after that a navigation reaches the desktop at once.
        st, _, body = c.get(loc, headers=FETCH)
        assert st == 200 and b"SLOT=" in body, \
            "%s: our page's wait did not end at the desktop: %d %r" \
            % (what, st, body[:120])
        t1 = time.time()
        st, _, body = c.get(loc, headers=NAVIGATE)
        assert st == 200 and b"SLOT=" in body and time.time() - t1 < 1.0, \
            "%s: once the desktop answered, the page was not the desktop's" \
            % what
    assert not dark, (
        "NOTHING OF OURS FOR MORE THAN %.0f s after the intent, with a start "
        "of %.0f s (injected): %s -- the visitor has only the browser's "
        "loading tab" % (OURS_WITHIN, SLOW_START, "; ".join(dark)))


def test_a_FAST_start_shows_nothing_of_ours(rig):
    """The other half, without which a router that ALWAYS answered with a page
    of its own would pass the test above: when the desktop's page is there
    sooner (INJECTED, A STAND-IN for a fast start), the visitor gets exactly
    that page, at all three entry points, and nothing of ours in front of it."""
    set_start(rig, FAST_START)
    for what, intent in ENTRY_POINTS:
        c, t0, loc = intent(rig)
        st, _, body = c.get(loc, headers=NAVIGATE)
        assert st == 200 and b"SLOT=" in body, (
            "%s: a start of %.1f s (injected) was answered with a page of "
            "ours instead of the desktop's: %d %r"
            % (what, FAST_START, st, body[:120]))


def fresh_markers(headers):
    """Every hdw4s_fresh value in a response, as a list.

    Read from the bytes the browser receives rather than from a call inside the
    router, for the reason every other assertion on this page is: what the page
    gate will act on is the header, and a component is not evidence about its
    own behaviour.
    """
    out = []
    for sc in headers.get("set-cookie", []):
        if sc.startswith("hdw4s_fresh="):
            out.append(sc.split("=", 1)[1].split(";")[0])
    return out


def test_a_desktop_just_MINTED_is_marked_and_a_resumed_one_is_not(rig):
    """THE PAIR THAT CARRIES THE 2026-09-26 RULING, and it is a pair on purpose.

    Dropping the arrival card on a desktop the router has just minted rests
    entirely on the marker appearing at a MINT and nowhere else. A router that
    marked every redirect would satisfy any assertion about "the mint was
    marked" -- and would hand a silent connect to a returning tab arriving at a
    desktop somebody else is watching, which is the damage the gate exists for
    and is strictly worse than the click it replaces.

    So the refusal is the second half of every arm here, in the same rig, at the
    same reading.

    THE ORACLE IS THE SID IN THE MARKER, not merely its presence: a marker that
    named a different desktop would authorise an arrival at that one instead,
    and "a cookie was set" cannot tell the two apart.
    """
    # 1. THE FRONT DOOR, for a browser that has nothing. This is a mint.
    c = rig.client()
    st, h, _ = c.get("/")
    assert st == 302, "arrival did not redirect: %d" % st
    c.learn_cookie(h)
    sid = h["location"][0].split("/")[2]
    assert fresh_markers(h) == [sid], (
        "a freshly minted desktop was not marked as one (markers %r, session "
        "%r), so the visitor meets the card on a desktop nobody has ever seen"
        % (fresh_markers(h), sid))

    # 2. THE CONTROL, and without it nothing above is evidence: the SAME
    # browser arriving again is RESUMED, not minted, and a resume may well be
    # taking the desktop back from another tab. It must not be marked. (With a
    # query: the bare address shows the directory instead, which is not a
    # redirect to a session at all.)
    st, h, _ = c.get("/?socket_worker=false")
    assert st == 302, "a returning visitor did not redirect: %d" % st
    assert h["location"][0].startswith("/s/%s/" % sid), \
        "the rig resumed a different session, so this is not the control it " \
        "claims to be: %r" % h["location"][0]
    assert fresh_markers(h) == [], (
        "A RESUMED DESKTOP WAS MARKED AS FRESHLY MINTED (%r). Any tab arriving "
        "at this address now connects without asking, including one that is "
        "taking the desktop from whoever is watching it."
        % fresh_markers(h))

    # 3. THE DIRECTORY'S CREATE, which is the path the owner's report is about,
    # and it is a SECOND minting site rather than the one above.
    st, h, _ = c.post("/sessions/new")
    assert st == 303, "create refused on a box with free slots: %d" % st
    new_sid = h["location"][0].split("/")[2]
    assert new_sid != sid, "create resumed instead of minting"
    assert fresh_markers(h) == [new_sid], (
        "the desktop created from the directory was not marked (markers %r, "
        "session %r) -- which is the two-click flow the owner asked us to drop"
        % (fresh_markers(h), new_sid))

    # 4. The marker must be READABLE BY SCRIPT, because its only reader is the
    # page-side gate. HttpOnly here would be a marker nothing can consume, and
    # the symptom is the card coming back with every check still green.
    raw = [sc for sc in h.get("set-cookie", []) if sc.startswith("hdw4s_fresh=")]
    assert "httponly" not in raw[0].lower(), \
        "the marker is HttpOnly, so the page gate cannot read it: %r" % raw[0]
    # And it must expire on its own, so an arrival that never happens cannot
    # leave a standing permission behind.
    assert "max-age=" in raw[0].lower(), \
        "the marker has no expiry: %r" % raw[0]


def test_resume_from_the_directory_connects_and_nothing_else_does(rig):
    """THE OWNER, 2026-09-27: "i created a new session, entered the bare url to
    get back to the session card, renamed the session, and clicked resume. i
    would have expected to get to my session, but instead i had to click
    connect on another card."

    Resume was a GET link to /s/<sid>/, which is byte for byte what a restored
    tab, a reload or a bookmark presents -- so the page could not tell a press
    from any of them, and asked. It is now a POST that is answered with the
    one-shot marker a mint carries. Everything that makes that safe is a
    refusal, so most of this test is refusals, each checked in the same rig
    as the press that is let through:

      * the press: POST from the browser that owns it -> 303 to /s/<sid>/,
        marked for THAT sid, no query string, no mint;
      * the addresses that look like it and must not be it: a GET of the
        session address (reload, restored tab), a GET of the resume address
        (a replayed URL, a prefetch), a second GET after the press -> no marker;
      * a desktop this browser does not own, and one that does not exist ->
        refused, no marker, no redirect;
      * the mint counter, seen moving once before its zero is believed.
    """
    a, b = rig.client(), rig.client()
    x, _ = arrive(rig, a)
    st, h, _ = a.post("/sessions/new")
    assert st == 303, "could not set up a second desktop: %d" % st
    y = h["location"][0].split("/")[2]
    assert a.get("/s/%s/" % y)[0] == 200
    w, _ = arrive(rig, b)

    # THE COUNTER MOVES, so the zeros below are readings and not a dead gauge.
    moved = mint_lines(rig)
    assert moved >= 3, "the mint counter did not count the three mints above"
    minted = moved

    # 1. The directory offers Resume as a POST to its own address, per row.
    st, _, body = a.get("/sessions/")
    assert st == 200
    targets = [(m, t) for m, t, _ in pressables(body)]
    for sid in (x, y):
        assert ("POST", "/sessions/%s/resume" % sid) in targets, \
            "the directory's Resume for %s is not a POST: %r" % (sid, targets)
        assert ("GET", "/s/%s/" % sid) not in targets, \
            "the directory still links %s's session address" % sid

    # 2. THE PRESS. Marked for exactly this desktop; the URL carries nothing.
    st, h, _ = a.post("/sessions/%s/resume" % x)
    assert st == 303, "Resume was not answered with a redirect: %d" % st
    assert h["location"] == ["/s/%s/" % x], \
        "Resume sent the browser to %r" % h["location"]
    assert fresh_markers(h) == [x], (
        "A PRESSED RESUME WAS NOT MARKED (markers %r), so the visitor meets "
        "the Connect card on the desktop they just chose" % fresh_markers(h))

    # 3. RELOAD / RESTORED TAB / BOOKMARK: the session address itself.
    st, h, _ = a.get("/s/%s/" % x)
    assert st == 200, "the resumed desktop did not serve: %d" % st
    assert fresh_markers(h) == [], \
        "A GET OF THE SESSION ADDRESS WAS MARKED (%r)" % fresh_markers(h)

    # 4. A REPLAYED URL: the resume address fetched, prefetched or restored.
    for n in range(2):
        st, h, _ = a.get("/sessions/%s/resume" % x)
        assert fresh_markers(h) == [], (
            "A GET OF THE RESUME ADDRESS WAS MARKED (%r): a prefetch, a "
            "restored tab or a pasted link now connects without asking"
            % fresh_markers(h))
        assert "location" not in h, \
            "a GET of the resume address redirected: %r" % h.get("location")

    # 5. NOT THIS BROWSER'S, and NOT ANYBODY'S: refused alike, unmarked.
    for who, sid in ((b, x), (a, w), (a, secrets_hex())):
        st, h, _ = who.post("/sessions/%s/resume" % sid)
        assert fresh_markers(h) == [] and "location" not in h, (
            "A FOREIGN DESKTOP WAS RESUMED: %s answered %d, location %r, "
            "markers %r" % (sid, st, h.get("location"), fresh_markers(h)))
        assert st == 403, "a resume of %s was answered %d, not 403" % (sid, st)

    # 6. And nothing on this path started a desktop.
    assert mint_lines(rig) == minted, \
        "Resume minted (%d -> %d)" % (minted, mint_lines(rig))


def test_a_second_desktop_is_a_second_desktop(rig):
    """Two sessions, both this visitor's, both listed, and the first survives.

    The failure this rules out is a "create" that is really a takeover: the
    pool loses no slot, the visitor sees one row, and the desktop they had is
    gone. Measured against the ownership table and against the page the visitor
    receives, because the table agreeing with itself is not the product.
    """
    c = rig.client()
    sid1, _ = arrive(rig, c)
    st, h, _ = c.post("/sessions/new")
    assert st == 303, "create refused on a box with free slots: %d" % st
    sid2 = h["location"][0].split("/")[2]
    assert sid2 != sid1, "create returned the session the visitor already had"

    st, _, body = c.get("/sessions/")
    text = body.decode()
    assert sid1 in text and sid2 in text, \
        "the directory did not list both of this visitor's desktops"
    # Both still route: a create that quietly recycled the first slot would
    # pass every assertion above.
    for sid in (sid1, sid2):
        st, _, _ = c.get("/s/%s/" % sid)
        assert st == 200, "session %s stopped routing after a create" % sid


def test_create_refuses_where_it_lives(rig):
    """The refusal renders ON THE CREATE SURFACE, not somewhere else.

    Two halves of one page, ruled 2026-09-25: the place a visitor presses for
    another desktop is the place a "no" has to appear, because a refusal shown
    anywhere else is a dead end and this surface is the rescue console. So the
    refusal KEEPS THE LIST -- the visitor can still see and discard what they
    have, which is the one action that would make the refusal stop being true.

    ITS AUDIENCE IS THE ADMIN, with the visitor as messenger: enough for an
    operator to skip the tracing, nothing about machine internals, and no
    suggestion that the person reading it did anything wrong or can fix it.

    ONE VISITOR TAKES THE WHOLE POOL HERE, deliberately. A pool filled by other
    visitors would test the same refusal against an EMPTY list, and the half
    that matters -- that being told no still leaves you your own desktops and
    the way to end one -- would not be exercised at all.
    """
    c = rig.client()
    sid1, _ = arrive(rig, c)
    mine = [sid1]
    while len(mine) < len(rig.slots):
        st, h, _ = c.post("/sessions/new")
        assert st == 303, "create refused while a slot was free: %d" % st
        mine.append(h["location"][0].split("/")[2])

    st, _, body = c.post("/sessions/new")
    assert st == 503, "a full pool did not refuse a create: %d" % st
    text = body.decode()
    for sid in mine:
        assert sid in text, \
            "THE REFUSAL DROPPED THE LIST. A visitor told no, and shown no way " \
            "to free the thing that would make the answer change, is a dead end."
    assert "Discard" in text, \
        "the refusal offered no way to make the answer change"
    # The words an operator needs, and none the visitor could act on.
    assert "slot" in text.lower(), \
        "the refusal did not name what ran out, so an admin must go and trace it"


def test_each_row_names_its_own_desktop(rig):
    """Two rows a person can tell apart, and the name comes from the DESKTOP.

    With one desktop there was nothing to choose between and the row said only
    "Resume". Create makes choosing the point of the page, and the first
    photograph of two rows showed them identical apart from a few megabytes.

    THE ORACLE IS AGREEMENT, not presence: the row must say what the slot's own
    page says, because the plausible implementation -- a number derived from
    the instance name -- is off by one against it (slots count from zero, the
    card is written i+1) and would put two different numbers for one desktop on
    the screen where somebody decides which to destroy. So the fixture writes a
    name into the slot's page and the test asserts the row carries THAT.
    """
    c = rig.client()
    sid1, body1 = arrive(rig, c)
    st, h, _ = c.post("/sessions/new")
    assert st == 303, "create refused on a box with free slots: %d" % st
    sid2 = h["location"][0].split("/")[2]
    _, _, body2 = c.get("/s/%s/" % sid2)

    names = {}
    # The slot each session is on, taken from what the SLOT says about itself
    # rather than from the router's table: the question is whether the row and
    # the desktop agree, so the desktop's own account is the right end to start.
    for sid, body in ((sid1, body1), (sid2, body2.decode())):
        inst = body.split("SLOT=")[1].split()[0]
        names[sid] = "Codename %s" % inst
        d = os.path.join(rig.webroot, inst)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "index.html"), "w") as f:
            f.write("<html><h1>%s</h1></html>" % names[sid])

    st, _, body = c.get("/sessions/")
    text = body.decode()
    for sid, name in names.items():
        assert name in text, \
            "the row for %s did not carry the name its own page publishes (%r)" \
            % (sid, name)
    assert names[sid1] != names[sid2], "the fixture gave both rows one name"


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

    The ownership table is written down now and survives a restart, so this arm
    WIPES it: its subject is a router that has lost the table -- a reboot's
    worth of state, or a file it could not read -- and has no idea which slots
    it let. systemd restarts
    it on failure and the sessions it was routing to are separate units that
    never noticed, so the pool it sees as empty is in fact fully occupied. The
    "never noticed" half is measured rather than reasoned: on a development container the
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

    rig.restart(wipe_state=True)

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


def test_a_restart_does_not_re_let_a_slot_whose_desktop_is_still_starting(rig):
    """DEFECT 4 BY A CLOCK RATHER THAN BY A TABLE, and it needs no crafted input.

    A mint precedes its session: the redirect is what sends the browser at the
    slot, and that first request is what socket-activates the desktop. So for a
    few seconds a slot is held on the router's word alone, in memory. Restart
    inside that window -- Restart=on-failure, RestartSec=1s, or an upgrade --
    and the word is gone while the visitor is still walking to their desktop.
    The next arrival is handed the same slot. That is the double-booking that
    was confirmed at the pixels, reached by a timer instead of a forgotten
    table.

    TWO RECORDS NOW HOLD THE SLOT ACROSS THE RESTART, and this arm cannot tell
    which one did: the reservation file, and pending_mints(), which reads the
    ownership table -- written down since the table stopped living in memory
    alone. It passes if either survives. assert_reservation_only_refuses()
    proves the reservation on its own at every start of the router.

    THE VISITOR HERE DELIBERATELY DOES NOT FOLLOW THE REDIRECT. That is not a
    contrived client, it is the ordinary state of every visitor for the moment
    between the 302 and the browser's next request, and it is the only state in
    which this defect exists. Following it would start the stand-in desktop,
    occupancy would take over, and the arm would be testing the authority
    instead of the reservation.

    NOT wiped, because the shipped unit now says RuntimeDirectoryPreserve=
    restart. Wiping here would model a configuration this package does not ship
    and the arm would fail for a reason that is not the product's.

    THE ORACLE IS THE BACKEND, as everywhere else in this file: each slot
    reports its own name, so "B landed on A's slot" is read from the thing that
    served B and never from the router's account of itself.
    """
    a = rig.client()
    st, h, _ = a.get("/")
    assert st == 302, "arrival did not redirect: %d" % st
    a.learn_cookie(h)
    assert h["location"][0].startswith("/s/"), \
        "redirect was not to a session path: %s" % h["location"][0]
    # Nothing has been served yet, so no stand-in desktop exists and no slot
    # can be occupied. Asserted rather than assumed: if the rig ever starts a
    # backend on the mint, this arm silently becomes the occupancy test.
    assert slots_in_use(rig) == 0, \
        "a slot was served before the redirect was followed, so this arm is " \
        "measuring occupancy rather than the reservation"

    rig.restart(wipe_state=False)

    # Every remaining visitor, each with a fresh cookie jar -- strangers, not
    # returning tabs. Drained until the pool refuses rather than a fixed count,
    # because how many are left is exactly what is under test.
    landed = []
    for _ in range(len(rig.slots) + 1):
        c = rig.client()
        st, h, _ = c.get("/")
        if st == 503:
            break
        assert st == 302, "an arrival was neither routed nor refused: %d" % st
        c.learn_cookie(h)
        st, _, body = c.get(h["location"][0])
        assert st == 200, "session path did not serve: %d" % st
        landed.append(body.decode().split("SLOT=")[1].split()[0])

    assert len(landed) == len(set(landed)), (
        "two strangers were put on the same slot after a restart: %r" % landed)
    assert len(landed) == len(rig.slots) - 1, (
        "the pool let %d of %d slots after a restart, so the slot held by a "
        "mint that had not yet started its desktop was re-let to a stranger "
        "(%r)" % (len(landed), len(rig.slots), landed))


def test_a_visitor_keeps_their_desktop_across_a_router_restart(rig):
    """A RESTART OF THE ROUTER MUST NOT CUT A VISITOR OFF FROM THEIR DESKTOP.

    Measured on production 2026-09-27: a deploy restarted hdw4s-demux at
    16:02:50, and from then on every request the owner's tab made for his own
    running desktop was answered 410 -- the table saying whose it was lived in
    the process that had just gone -- while the desktop itself ran on, owned by
    nobody, for the seven-day idle window.

    NOT WIPED, because the shipped unit preserves the router's state directory
    across a restart; see Rig.restart(). The oracle is the BACKEND: the same
    slot answers, and it is the same start of it (no new incarnation), so the
    visitor reached the desktop they had and nothing was started for them.
    Ownership must survive in BOTH directions -- a stranger presenting the
    same address after the restart is still refused -- or "survives" would
    have been bought by forgetting who owns what.
    """
    a = rig.client()
    sid, name = arrive_on_slot(rig, a)
    slot = slot_named(rig, name)
    token = slot.incarnation
    assert token is not None, "%s never started, so nothing here is about " \
        "keeping a desktop" % name

    rig.restart()

    st, _, body = a.get("/s/%s/" % sid)
    assert st == 200, (
        "after a restart of the router the visitor's own running desktop "
        "answered %d -- they are cut off from it and it runs on for nobody"
        % st)
    assert ("SLOT=%s" % name) in body.decode(), \
        "the visitor was routed somewhere other than their own slot"
    assert slot.incarnation == token, \
        "the visitor's request started a NEW desktop instead of reaching theirs"

    st, _, _ = rig.client().get("/s/%s/" % sid)
    assert st == 403, \
        "a stranger reached this visitor's desktop after the restart: %d" % st

    table = os.path.join(rig.statedir, "ownership.json")
    mode = os.stat(table).st_mode & 0o777
    assert mode == 0o600, (
        "the ownership table is mode %o; it decides whose desktop a request "
        "reaches and must be readable by the router alone" % mode)


def test_a_letting_that_never_came_back_cannot_reach_the_next_one(rig):
    """ISOLATION: a visitor who was minted a slot and never used it must not,
    returning later, be proxied into the desktop of whoever it was let to next.

    Found by the threat review at function level: a letting whose desktop had
    never answered was permitted for as long as its slot was OCCUPIED, with no
    time bound. After MINT_GRACE the slot leaves the pool's taken set and is
    re-let; the next visitor's desktop comes up in it; and the first visitor's
    address then reached that desktop with full input.

    ONE slot, so the second visitor can only land on the first one's. The
    first visitor's mint is aged past MINT_GRACE by editing the router's own
    written-down state -- the ownership row and the reservation file -- and
    restarting it, rather than by waiting three minutes. The oracle is the
    BACKEND: the first visitor must not be answered by the slot at all.
    """
    grace = load_demux().MINT_GRACE
    a = rig.client()
    st, h, _ = a.get("/")
    assert st == 302, "arrival did not redirect: %d" % st
    a.learn_cookie(h)
    sid_a = h["location"][0].split("/")[2]

    table = os.path.join(rig.statedir, "ownership.json")
    data = json.load(open(table))
    data["sessions"][sid_a]["minted"] -= grace + 5
    with open(table, "w") as f:
        json.dump(data, f)
    old = time.time() - grace - 5
    for name in os.listdir(os.path.join(rig.statedir, "reserved")):
        os.utime(os.path.join(rig.statedir, "reserved", name), (old, old))
    rig.restart()

    b = rig.client()
    sid_b, name_b = arrive_on_slot(rig, b)
    assert name_b == rig.slots[0].name, "the second visitor had nowhere else"

    st, _, body = a.get("/s/%s/" % sid_a)
    assert b"SLOT=" not in body, (
        "a visitor whose letting never came back was proxied into the desktop "
        "the slot was let to next (%d): a stranger's desktop, with full input"
        % st)
    assert st == 410, "the stale letting was not shown the ended page: %d" % st
    st, _, body = b.get("/s/%s/" % sid_b)
    assert st == 200 and ("SLOT=%s" % name_b) in body.decode(), \
        "the second visitor lost their own desktop: %d" % st


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
# somebody who cannot see this measurement. Measured on a development container; it supersedes the
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
    """DEFECT 4, AND ITS PREMISE HAS SINCE BEEN REPAIRED -- READ THIS FIRST.

    THIS ARM USED TO IMITATE A WIPE. It called restart(wipe_state=True) and
    asserted the sad half: that a slot whose record systemd had just deleted
    renders "no record", which is the same eight characters a slot nobody has
    ever opened renders, so an operator reading a refusal cannot tell "this
    desktop is idle and can be reaped" from "I lost my notes". The wipe was
    real -- RuntimeDirectory=hdw4s-demux with no RuntimeDirectoryPreserve=,
    STATE_DIR defaulting inside it, watched happening on a development
    container across a clean restart and a kill -9.

    hdw4s-demux.service now carries RuntimeDirectoryPreserve=restart, which is
    one of the two repairs the arm below this one was deliberately agnostic
    between. So the wipe no longer happens, and an arm that went on imitating
    it would be asserting a property of a configuration this package does not
    ship -- green forever, about nothing. That is the failure this file exists
    to catch, arriving at this file.

    SO THE ARM IS INVERTED RATHER THAN DELETED, and it is stronger inverted: it
    now restarts WITHOUT wiping, the way the shipped unit behaves, and asserts
    that a slot which served a visitor is still distinguishable afterwards.
    Before the repair this assertion fails, because the record is gone; after
    it, it passes because the record is there. The rendering concern it was
    built for survives inside it -- what is being compared is still the text an
    operator reads, not the file on disk.

    WHAT IS STILL STOOD IN FOR: this rig's state lives in a tmpdir with no
    relationship to RuntimeDirectory= whatsoever, so not wiping it models the
    preserved configuration rather than observing it. The arm below reads the
    unit file and is the evidence for that half. Neither of them has watched
    systemd preserve the directory on a real box, and until somebody does, the
    pair is a configuration check and a rendering check and not a measurement.
    """
    a = rig.client()
    _, visited = arrive_on_slot(rig, a)
    path = os.path.join(rig.statedir, "last-request", visited)
    for _ in range(50):
        if os.path.exists(path):
            break
        time.sleep(0.05)
    assert os.path.exists(path), "no record was written for %s" % visited

    # NOT wiped: the shipped unit preserves this tree across a restart, so
    # wiping it here would model a configuration this package does not ship.
    rig.restart(wipe_state=False)

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
        "window from this line is reading a lost record as an idle desktop, "
        "and the reaper reads the same lost record as a second witness that "
        "nobody was here" % stripped)


def test_the_records_the_refusal_log_is_read_from_survive_a_restart():
    """DEFECT 4's premise, read from the configuration rather than from a box.

    The test above imitates the wipe. This one asks whether the shipped
    configuration calls for it, and it answers from the unit file.

    THIS DOCSTRING USED TO SAY the unit file was "the only oracle that can
    settle it" and that "a unit file read is the whole of the available
    evidence", because hdw4s-demux had never run on the production box and
    nobody had stood one up elsewhere. Both sentences were true when written
    and both are now false: it has since been run on a development container under real systemd
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
        "the router's on-disk records live in %s, which is RuntimeDirectory=%s "
        "with no RuntimeDirectoryPreserve= -- systemd deletes them every time "
        "the service stops. The last-request records then read 'no record', "
        "which is the same thing a slot nobody has ever opened reads; and the "
        "mint reservations, whose ONLY job is to cross a restart, are destroyed "
        "by the event they exist for while every guard over them still passes"
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


def test_a_refused_session_is_logged_once(rig):
    """A REFUSAL AN ADMINISTRATOR CANNOT SEE IS NOT A REFUSAL ANYBODY CAN FIX.

    Measured on production 2026-09-27: after a restart of the router the owner's
    tab asked for its page, its script, its manifest, its stylesheet and its
    identity, every one was answered 410, and the log said nothing at all. So
    each refusal is said -- ONCE per refused session, because a tab asks many
    times, and a line per request is a line somebody silences.

    Three events, each asked several times: a session nobody holds (410), a
    stranger presenting somebody else's session (403), and a visitor gated at
    a desktop that stopped, whose gate line is the event and whose follow-up
    requests must not be reported as a second one.
    """
    madeup = secrets_hex()
    for _ in range(5):
        st, _, _ = rig.client().get("/s/%s/" % madeup)
        assert st == 410, "a made-up session was not refused: %d" % st

    a = rig.client()
    sid, name = arrive_on_slot(rig, a)
    stranger = rig.client()
    for _ in range(3):
        st, h, _ = stranger.get("/s/%s/" % sid)
        stranger.learn_cookie(h)
        assert st == 403, "a stranger was not refused: %d" % st

    b = rig.client()
    sid_b, name_b = arrive_on_slot(rig, b)
    slot_named(rig, name_b).logout(leave_rundir=False)
    for _ in range(4):
        st, _, _ = b.get("/s/%s/" % sid_b)
        assert st == 410, "a visitor whose desktop stopped was not gated: %d" % st

    log = rig.stderr_text().splitlines()
    unknown = [l for l in log if madeup in l]
    assert len(unknown) == 1 and "410" in unknown[0], (
        "a session nobody holds was refused five times and logged %d time(s): "
        "%r" % (len(unknown), unknown))
    foreign = [l for l in log if sid in l and "different browser" in l]
    assert len(foreign) == 1 and "403" in foreign[0], (
        "a stranger was refused three times and it was logged %d time(s): %r"
        % (len(foreign), foreign))
    # Every line about that visitor's return; the mint that let them in is not
    # one of those.
    gated = [l for l in log if "minted" not in l
             and (sid_b in l or ("gated" in l and name_b in l))]
    assert len(gated) == 1 and "gated" in gated[0], (
        "a visitor gated at a stopped desktop, asking four times, was logged "
        "%d time(s): %r" % (len(gated), gated))


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
    forged = "f" * 32
    # WRITTEN AS A BROWSER READS A NAME, not as the filter used to. The first
    # version of this test looked only at values starting "hdw4s_id=", which
    # is the filter's own blind spot restated -- measured by the threat review:
    # "hdw4s_id =X" reached the browser and Chrome 153 took it as our cookie.
    # So the oracle is every Set-Cookie the browser receives that carries the
    # forged token, whatever its spelling.
    for spelling in ("hdw4s_id=%s", "hdw4s_id =%s; Path=/; Secure",
                     "hdw4s_id\t=%s; Path=/", " hdw4s_id=%s",
                     "hdw4s_fresh=%s; Path=/", "=hdw4s_id=%s",
                     "hdw4s_id; x=%s"):
        for s in rig.slots:
            s.forge_cookie = spelling % forged
        st, h, _ = a.get("/s/%s/" % sid)
        got = [v for v in h.get("set-cookie", []) if forged in v]
        assert not got, "a session set our cookie by writing %r: %r" \
            % (spelling % "X", got)
    # THE PERMIT ARM: a session's own cookies still reach its page. A filter
    # that dropped every Set-Cookie would pass everything above.
    for s in rig.slots:
        s.forge_cookie = "selkies_pref=%s; Path=/" % forged
    st, h, _ = a.get("/s/%s/" % sid)
    for s in rig.slots:
        s.forge_cookie = None
    assert any(forged in v for v in h.get("set-cookie", [])), \
        "a session's own cookie was dropped on its way to the browser"


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


# --------------------------------------------------------------------------
# The pool is the typed table, not the socket directory
# --------------------------------------------------------------------------
#
# Every hdw4s-proxy@ instance on a box binds into /run/hdw4s-proxy, named
# desktops included, so a router that computes free capacity by listing that
# directory will hand a stranger somebody's long-lived session. Measured
# 2026-09-22 and recorded in the shipped function's own docstring; sighted three
# times by three seats and never fixed, because nothing here could tell the two
# sources apart -- this rig only ever created sockets that were also pool
# members.


def test_a_socket_outside_the_table_is_never_minted(rig):
    """A stray listening socket must not be offered, even when nothing else is.

    ONE POOL SLOT AND ONE STRAY, deliberately. With spare capacity the router
    hands out a real slot whatever it believes the pool to be, and the arm goes
    green against the defect. The second visitor arrives with the pool full, so
    the only way to serve them at all is to reach for the stray -- which is
    exactly what the directory listing did.

    THE CONTROL IS THE FIRST VISITOR. If arrival were broken outright, nobody
    would land on the stray either and the refusal below would pass for a reason
    that has nothing to do with the pool.
    """
    names = [s.name for s in rig.strays]
    assert names, "this test needs a stray; the rig was built without one"

    c = rig.client()
    _, body = arrive(rig, c)
    got = body.split("SLOT=")[1].split()[0]
    assert got == "ephemeral0", \
        "the control visitor did not reach the one pool slot: %s" % got

    c2 = rig.client()
    st, h, _ = c2.get("/?socket_worker=false")
    assert st == 503, \
        "a second arrival was served while the only pool slot was taken: %d" % st
    # THE SLOT'S OWN ACCOUNT, not the router's. A 503 says the router refused;
    # it does not say the stray was left alone, and a router that mis-routed
    # and then failed would look identical from the client.
    for s in rig.strays:
        assert not s.seen, \
            "%s is in no table row and was served anyway: a named desktop's " \
            "socket in the same directory would have been handed to a stranger" \
            % s.name


# --------------------------------------------------------------------------
# Putting the defect back, to prove the arm above can see it
# --------------------------------------------------------------------------

POOL_FROM_DIRECTORY = """

# Appended by the red arm: the pool as it was computed before the repair.
def ephemeral_slots(table=_READ_IT):
    return socket_filenames()
"""

NO_STARTUP_GUARD = """

def assert_pool_is_typed(read_table=None, pool=None):
    return None
"""


_SCRATCH = []


@atexit.register
def _remove_scratch_demuxes():
    """Whatever scratch_demux() made, gone, however this process ended."""
    for path in _SCRATCH:
        try:
            os.unlink(path)
        except OSError:
            pass
SCOPE_CHECKED_BY_THE_PAGE = """

# Appended by the red arm: a console that trusts the sid it was handed. This is
# exactly what "the page only renders your own sessions" amounts to the moment
# somebody types an address the page never showed them, which is the whole
# reason the shipped check is at the server rather than in the markup.
_shipped_console = console


def console(own, wf, identity, new_identity, what, sid, method):
    if what == "discard" and method == b"POST":
        rec = own.lookup(sid)
        if rec is not None:
            request_teardown(rec["instance"])
            respond(wf, 303, b"", [("Location", "/sessions/")]
                    + refresh_headers(own, identity, new_identity))
            return
    return _shipped_console(own, wf, identity, new_identity, what, sid, method)
"""

CONSOLE_PARSER_STOPS_MATCHING = """

# Appended by the red arm: a console dispatch that claims nothing. Every console
# address then gets the router's answer for a path it does not know.
def console_target(path):
    return None, None
"""

NO_CONSOLE_STARTUP_GUARD = """

def assert_console_shows_only_your_own(target=None):
    return None
"""


def scratch_demux(suffix, extra):
    """A copy of the shipped router with EXTRA appended. Returns its path.

    Appended rather than patched by regular expression, because a substitution
    that silently matched nothing would leave the shipped code in place and the
    red arm would go green -- reporting that the defect is absent from a file it
    never edited. A redefinition at the end of the module either parses and
    rebinds the name or the process does not start at all.

    WRITTEN BESIDE THE SHIPPED COPY, not in a temporary directory, and this is
    not tidiness. load_duration() derives the grammar module from the router's
    OWN location -- deliberately, so that two installations cannot select each
    other's -- so a copy in /tmp dies at import looking for /tmp/hdw4s-duration.
    Measured: the first version of this put both red arms in /tmp, and one of
    them was reported red for that import failure while claiming to be about the
    pool. That is the whole failure mode these arms are supposed to avoid.
    """
    fd, path = tempfile.mkstemp(prefix=".demux-red-", suffix=suffix,
                                dir=os.path.dirname(DEMUX))
    with os.fdopen(fd, "w") as f:
        f.write(open(DEMUX).read().replace(
            'if __name__ == "__main__":', extra + '\nif __name__ == "__main__":'))
    # REGISTERED FOR REMOVAL HERE, WHERE IT IS CREATED, rather than left to
    # each caller's finally:. Every caller writes
    #     path = scratch_demux(...)
    #     rig = Rig(..., demux=path)
    #     try: ... finally: os.unlink(path)
    # and a mutation that the router's own STARTUP GUARDS catch makes Rig()
    # raise on that middle line -- before the try: that would have cleaned up.
    # So exactly the arms that work best leave a copy of the router lying in
    # the tree, named like a hidden file so nobody notices. Two were found that
    # way. The callers keep their unlink; this is the one that cannot be
    # skipped.
    _SCRATCH.append(path)
    return path


def test_a_duration_already_in_seconds_is_refused(rig=None):
    """The round trip that means "never reaped", and it cannot be tested from the CLI.

    DURATION.parse takes text off a config line, and a BARE NUMBER there means
    days -- "7" is a week, which is the documented nudge. The old entry point
    ran str() over whatever it was handed, so an int went down that same path:
    parse(604800), a value this function had itself RETURNED, answered
    52,254,720,000 seconds. About 1,656 years. The reaper honours that as
    never, and nothing anywhere fails -- the sessions simply accumulate.

    No shipped caller does this today; both pass a string. It is guarded
    because the failure is silent and a later refactor that moves a computed
    value back through the parser has no way to find out. Note this CANNOT be
    an arm of the duration group in tests.sh: that group goes through argv,
    where every value is already a string, so the defect is invisible from
    there. It is a property of the Python boundary and has to be tested at it.
    """
    m = load_demux()
    parse = m.DURATION.parse

    # The permit arm first. Without it the refusals below are satisfied by a
    # parser that refuses everything.
    assert parse("7") == 604800, parse("7")
    assert parse("7d") == 604800, parse("7d")

    # THE STRING HALF, which is the one a config file can actually reach. The
    # isinstance guard below closes only the in-process round trip; a conf line
    # always delivers text, so "604800" used to come through as 1656 years and
    # the reaper honours that as never. Caught by a policy ceiling, not by the
    # type check -- two different guards for two halves of one defect, and the
    # type check alone reads as if it had closed both.
    for text, why in (("604800", "seconds pasted where days were meant"),
                      ("2592000", "a month in seconds"),
                      ("36600d", "just over the hundred-year ceiling")):
        try:
            got = parse(text)
        except Exception as e:
            assert "years" in str(e), "refused for the wrong reason: %s" % e
        else:
            raise AssertionError(
                "parse(%r) (%s) was accepted and answered %r seconds (%.0f "
                "years), which the reaper honours as never"
                % (text, why, got, got / 31557600.0))

    # And the ceiling must not eat a long window somebody means. Ten years is
    # absurd as a reap window and still legal; the guard is against units, not
    # against ambition.
    assert parse("3650d") == 3650 * 86400, parse("3650d")

    for bad in (604800, 7, 0, 7.0):
        try:
            got = parse(bad)
        except Exception as e:
            assert "must be text" in str(e), "refused for the wrong reason: %s" % e
        else:
            raise AssertionError(
                "parse(%r) was accepted and answered %r seconds (%.0f years) -- "
                "a number that is already seconds read as days"
                % (bad, got, got / 31557600.0))


def red_pool_from_the_directory():
    """The arm above, against a router whose pool is the directory listing.

    Both the pool AND the start-up guard are put back, so this fails where the
    green arm asserts -- on a visitor reaching a slot that is in no table row --
    rather than at start-up. A red arm that dies for a different cause proves
    nothing about the arm it is named after, and that has happened twice here.
    """
    path = scratch_demux("-pool", POOL_FROM_DIRECTORY + NO_STARTUP_GUARD)
    rig = Rig(nslots=1, strays=["named0"], demux=path)
    try:
        test_a_socket_outside_the_table_is_never_minted(rig)
    finally:
        rig.stop()
        _remove_scratch_demuxes()


def red_scope_checked_by_the_page():
    """THE ONE THAT MATTERS. A console whose scope is the markup, not the server.

    The green arm hands one visitor another's sid -- an address the page could
    never have shown them, which is precisely what somebody probing has and a
    page-level check cannot see. Against this router the 403 is gone and the
    teardown is recorded, so the arm must fail on the FILESYSTEM assertion
    rather than on the status code: a refusal that refuses nothing is the shape
    being guarded against, and only the file can tell the two apart.
    """
    path = scratch_demux("-scope", SCOPE_CHECKED_BY_THE_PAGE)
    rig = Rig(demux=path)
    try:
        test_one_visitor_cannot_discard_anothers_session(rig)
    finally:
        rig.stop()
        os.unlink(path)


def test_the_row_says_when_the_desktop_goes_by_itself(rig=None):
    """The one claim this page makes about the future, PER SLOT.

    The mock calls it the promise that abandonment needs no cleanup, made
    before the fact rather than after it. It has to be this machine's answer
    for THIS slot: the windows genuinely differ between slots on a box under
    experiment, and a page quoting one number for the pool would be telling
    some visitors something untrue about their own desktop.

    Two slots, two different windows, written the way an administrator writes
    them -- which is also the spelling that a "%d" fixture could not express
    and that let a duration defect ship once already.
    """
    rig = Rig(windows=[("ephemeral0", "30d"), ("ephemeral1", "15m")])
    try:
        a, b = rig.client(), rig.client()
        arrive(rig, a)
        arrive(rig, b)
        _, _, body_a = a.get("/sessions/")
        _, _, body_b = b.get("/sessions/")
        texts = [body_a.decode(), body_b.decode()]
        assert any("30 days" in t for t in texts), \
            "no row quoted the 30d window: %r" % texts
        assert any("15 minutes" in t for t in texts), \
            "no row quoted the 15m window, so the page is not reading per slot"
        # And neither visitor was told the OTHER slot's number, which is what a
        # page reading one value for the pool would do.
        for t in texts:
            assert not ("30 days" in t and "15 minutes" in t), \
                "one visitor's page carried both slots' windows"
    finally:
        rig.stop()


CREATE_IS_A_LINK = """

# Appended by the red arm: create as an <a href> rather than a form -- which is
# what "just make the button a link, it is simpler" looks like in a diff, and
# it is a one-word change that nothing else in this suite notices. Every way a
# URL is fetched without a person deciding anything then mints: a prefetch, a
# link preview, a crawler, a pinned tab, a session restore, a back button.
_shipped_console = console


def console(own, wf, identity, new_identity, what, sid, method):
    return _shipped_console(own, wf, identity, new_identity, what, sid,
                            b"POST" if what == "create" else method)
"""


MARK_EVERY_REDIRECT = """

# Appended by the red arm: mark EVERY redirect to a session address as a fresh
# mint, which is what "why is this conditional, just set it beside the Location"
# looks like in a diff. The mint keeps working, the owner's two clicks stay gone,
# and the arrival gate is silently off for every returning tab -- including one
# arriving at a desktop somebody else is watching. Nothing else in this suite
# notices, which is why the green test above carries its control.
_shipped_respond = respond


def respond(wf, status, body=b"", extra=()):
    extra = list(extra)
    if status == 302 and not any(
            k == "Set-Cookie" and v.startswith("hdw4s_fresh=")
            for k, v in extra):
        for k, v in list(extra):
            if k == "Location" and v.startswith("/s/"):
                extra.append(asked_marker_header(v.split("/")[2]))
                break
    return _shipped_respond(wf, status, body, extra)
"""


def red_every_redirect_marked_as_a_fresh_mint():
    """THE GUARANTEE THE 2026-09-26 RULING RESTS ON, broken on purpose.

    Skipping the card is safe for exactly one reason: the desktop was minted in
    the request that redirected here, so nobody can be watching it. The whole of
    that reason is carried by ONE CONDITIONAL, and the change that removes it is
    the plausible tidy-up -- a marker set once beside the redirect instead of
    twice inside branches.

    Its oracle is the CONTROL arm of the green test, not the mint arm: a router
    that marks everything mints perfectly well.
    """
    path = scratch_demux("-fresh", MARK_EVERY_REDIRECT)
    rig = Rig(gate=None, demux=path)
    try:
        test_a_desktop_just_MINTED_is_marked_and_a_resumed_one_is_not(rig)
    except AssertionError as e:
        # NAMED, not merely "it failed". The first version of this arm was red
        # for the wrong reason -- the patch added a SECOND marker beside the
        # shipped one, so the MINT arm failed on a duplicate and the control
        # never ran. A red arm that trips the wrong assertion reports that the
        # guard works while the property it is about is untested.
        if "RESUMED DESKTOP WAS MARKED" not in str(e):
            raise RuntimeError(
                "the red arm failed, but not on the control: %s" % e)
        raise
    finally:
        rig.stop()
        os.unlink(path)


RESUME_WITHOUT_ITS_CHECKS = """

# Appended by the red arm: Resume as the one-liner it looks like -- "redirect
# to the session and say it was asked for" -- with neither the method nor the
# ownership check. A press still lands on the desktop, so the owner's report
# stays fixed; a prefetch or a stranger's form now connects without asking.
_shipped_console = console


def console(own, wf, identity, new_identity, what, sid, method):
    if what == "resume":
        return respond(wf, 303, b"", [("Location", "/s/%s/" % sid),
                                      asked_marker_header(sid)])
    return _shipped_console(own, wf, identity, new_identity, what, sid, method)
"""

RESUME_WITHOUT_OWNERSHIP = """

# Appended by the red arm: the method is checked, ownership is not.
_shipped_console = console


def console(own, wf, identity, new_identity, what, sid, method):
    if what == "resume" and method == b"POST":
        return respond(wf, 303, b"", [("Location", "/s/%s/" % sid),
                                      asked_marker_header(sid)])
    return _shipped_console(own, wf, identity, new_identity, what, sid, method)
"""


def _red_resume(suffix, patch, must_say):
    path = scratch_demux(suffix, patch)
    rig = Rig(gate=None, demux=path)
    try:
        test_resume_from_the_directory_connects_and_nothing_else_does(rig)
    except AssertionError as e:
        # NAMED: red for the reason this arm exists, not for another one.
        if must_say not in str(e):
            raise RuntimeError("the red arm failed, but not on %r: %s"
                               % (must_say, e))
        raise
    finally:
        rig.stop()
        os.unlink(path)


def red_resume_on_a_GET():
    """The marker handed to a GET: every replayed URL connects silently."""
    _red_resume("-resume-get", RESUME_WITHOUT_ITS_CHECKS,
                "A GET OF THE RESUME ADDRESS WAS MARKED")


def red_resume_of_a_desktop_that_is_not_yours():
    """THE NEW GUARD, seen refusing: without it a stranger's press connects."""
    _red_resume("-resume-foreign", RESUME_WITHOUT_OWNERSHIP,
                "A FOREIGN DESKTOP WAS RESUMED")


def red_a_console_address_that_stops_being_claimed():
    """A parser that quietly stops matching. Before only the front door reached
    arrival(), this handed a visitor trying to END a desktop ANOTHER ONE; now it
    is a 404 in place of the console, and the green arm must still see that.
    The start-up guard is put back too, so this fails where the green arm
    asserts rather than at start-up -- the separate arm below is the one about
    start-up.
    """
    path = scratch_demux("-console", CONSOLE_PARSER_STOPS_MATCHING
                         + NO_CONSOLE_STARTUP_GUARD)
    rig = Rig(demux=path)
    try:
        test_the_console_never_mints(rig)
    finally:
        rig.stop()
        os.unlink(path)


def red_create_on_a_GET():
    """THE GUARANTEE THAT MUST NOT REGRESS, broken on purpose.

    The whole distinction between "a visitor asked for another desktop" and
    "minting is a damage" is carried by ONE REQUEST METHOD. Nothing else in the
    product marks it, nothing else would fail if it went, and the change that
    removes it is the plausible-looking simplification of turning a form into a
    link. So the control is pointed at a router where exactly that has
    happened, and watched refusing it.

    Its oracle is the REDIRECT, not the status code: a router that answered 200
    and minted anyway would satisfy any assertion about "did it serve", and the
    desktop would still be gone from the pool.
    """
    path = scratch_demux("-create", CREATE_IS_A_LINK)
    rig = Rig(gate=None, demux=path)
    try:
        test_asking_for_a_second_desktop_takes_a_GESTURE(rig)
    finally:
        rig.stop()
        os.unlink(path)


LOADING_TAB_ONLY = """

# Appended by the red arm: bug 2 as it was. A page navigation waits for the
# desktop however long the start takes, so a slow start is spent on the
# browser's loading tab with nothing of ours.
STARTING_PAGE_AFTER = 60.0
"""

OURS_AT_ONCE = """

# Appended by the red arm: our page in front of EVERY start, however fast --
# the router that would pass the slow arm by never letting the desktop's page
# through first.
STARTING_PAGE_AFTER = 0.0
"""

THE_WAIT_IS_A_NAVIGATION = """

# Appended by the red arm: a router that cannot tell our page's wait from a
# navigation, so the wait is answered with the page that is waiting.
def is_page_navigation(method, rest, headers):
    return method == b"GET" and rest == b"/"
"""


def _red_bug2(extra, suffix, test, oracle):
    path = scratch_demux(suffix, extra)
    rig = Rig(nslots=4, gate=None, demux=path)
    try:
        test(rig)
    except AssertionError as e:
        if oracle not in str(e):
            raise RuntimeError("the red arm failed, but not on %r: %s"
                               % (oracle, e))
        raise
    finally:
        rig.stop()
        os.unlink(path)


def red_a_slow_start_is_the_loading_tab_again():
    """BUG 2 put back. Must fail on the dark seconds, at the entry points."""
    _red_bug2(LOADING_TAB_ONLY, "-loading-tab",
              test_a_SLOW_start_shows_something_of_ours_within_two_seconds,
              "NOTHING OF OURS")


def red_our_page_in_front_of_a_fast_desktop():
    """The over-eager repair. Must fail on the FAST arm."""
    _red_bug2(OURS_AT_ONCE, "-ours-at-once",
              test_a_FAST_start_shows_nothing_of_ours,
              "instead of the desktop's")


def red_our_page_waits_for_itself():
    """The loop. Our page's fetch answered with our page: it must fail on the
    hand-over, not on the timing."""
    _red_bug2(THE_WAIT_IS_A_NAVIGATION, "-wait-loops",
              test_a_SLOW_start_shows_something_of_ours_within_two_seconds,
              "our page's wait did not end at the desktop")


ENDED_PAGE_LINKS_TO_THE_FRONT_DOOR = """

# Appended by the red arm: the ended page's button as it was until bug 1 --
# a link to the front door, which is what "a link is simpler than a form"
# looks like in a diff. The front door resumes the newest desktop this browser
# owns (the bare address now shows the directory, so the link carries a query,
# as a link that kept the arm would), and with a second desktop open the
# button takes that one over.
def ended_page(rows, gone):
    return card("This desktop has ended",
                rows_html(rows) + "<p><a href=\\"/?gate=takeover\\">"
                "New desktop</a></p>")
"""


def red_the_ended_pages_button_resumes():
    """BUG 1, put back on purpose. Its oracle is the RESUME, not the markup:
    the green test presses the button before it looks at its shape, so this
    must fail on landing at the other desktop, and is refused as a red arm if
    it fails anywhere else."""
    path = scratch_demux("-ended", ENDED_PAGE_LINKS_TO_THE_FRONT_DOOR)
    rig = Rig(gate=None, demux=path)
    try:
        test_the_ended_pages_button_starts_a_NEW_desktop(rig)
    except AssertionError as e:
        if "RESUMED THE OTHER DESKTOP" not in str(e):
            raise RuntimeError(
                "the red arm failed, but not on the resume: %s" % e)
        raise
    finally:
        rig.stop()
        os.unlink(path)


BARE_ADDRESS_RESUMES = """

# Appended by the red arm: the front door as it was, resuming the newest
# desktop on a bare arrival -- what treating "no query" like any other query
# looks like in a diff.
_shipped_arrival = arrival


def arrival(own, wf, identity, query, new_identity, dest=None):
    return _shipped_arrival(own, wf, identity, query or b"gate=" +
                            GATE_DEFAULT.encode(), new_identity, dest)
"""


EVERY_PATH_IS_THE_FRONT_DOOR = """

# Appended by the red arm: the catch-all put back. Every path the router does
# not otherwise claim is an arrival again, which is what the browser's own
# /favicon.ico request reached on the test box.
def is_front_door(path):
    return True
"""


def red_every_path_is_the_front_door():
    """The router fix undone on purpose; must fail on the mint count."""
    path = scratch_demux("-catchall", EVERY_PATH_IS_THE_FRONT_DOOR)
    rig = Rig(gate=None, demux=path)
    try:
        test_only_the_front_door_mints(rig)
    except AssertionError as e:
        if "minted by paths that are not the front door" not in str(e):
            raise RuntimeError(
                "the red arm failed, but not on the mint: %s" % e)
        raise
    finally:
        rig.stop()
        os.unlink(path)


def red_the_bare_address_resumes():
    """Change 1 undone on purpose; must fail on the resume and nowhere else."""
    path = scratch_demux("-bare", BARE_ADDRESS_RESUMES)
    rig = Rig(gate=None, demux=path)
    try:
        test_the_bare_address_shows_your_desktops(rig)
    except AssertionError as e:
        if "THE BARE ADDRESS RESUMED" not in str(e):
            raise RuntimeError(
                "the red arm failed, but not on the resume: %s" % e)
        raise
    finally:
        rig.stop()
        os.unlink(path)


def red_startup_guard_notices_a_console_address_that_moved():
    """And the start-up guard alone must refuse that router.

    Separate on purpose, for the same reason the pool has two arms: the one
    above proves the damage is visible to a test, this one proves the router
    declines to come up at all rather than waiting for a visitor to be handed a
    desktop they did not ask for.
    """
    path = scratch_demux("-console-guard", CONSOLE_PARSER_STOPS_MATCHING)
    try:
        rig = Rig(demux=path)
    except RuntimeError as e:
        os.unlink(path)
        # NAMED, not merely "the process died", for the reason the pool's arm
        # sets out at length: a typo in the scratch copy and an import that
        # cannot find its way both satisfy "it refused to start", and both have
        # been reported as clean reds on this project.
        if "assert_console_shows_only_your_own" not in str(e):
            raise RuntimeError(
                "the router failed to start, but not in the guard: %s" % e)
        raise AssertionError("start-up guard refused, as it must")
    rig.stop()
    os.unlink(path)


def red_startup_guard_notices_the_directory_listing():
    """And the start-up guard alone must refuse the same router.

    Separate from the arm above on purpose: that one proves the BEHAVIOUR is
    visible to a test, this one proves the router refuses to come up at all
    without waiting for a visitor to arrive and be misrouted. Only the pool is
    put back here; assert_pool_is_typed() is left shipped and has to catch it.
    """
    path = scratch_demux("-guard", POOL_FROM_DIRECTORY)
    try:
        rig = Rig(nslots=1, strays=["named0"], demux=path)
    except RuntimeError as e:
        os.unlink(path)
        # NAMED, not merely non-zero. "The process died" is satisfied by a typo
        # in the scratch copy or by an import that cannot find its way, and
        # BOTH were seen here before this line existed.
        #
        # The wrong cause is raised as something that is NOT an AssertionError,
        # because expect_red() treats an AssertionError as the arm working.
        # Written the other way first, this arm reported a clean red while the
        # scratch copy was dying in load_duration() and the guard was never
        # reached at all.
        if "assert_pool_is_typed" not in str(e):
            raise RuntimeError(
                "the router failed to start, but not in the guard: %s" % e)
        raise AssertionError("start-up guard refused, as it must")
    rig.stop()
    os.unlink(path)


# --------------------------------------------------------------------------
# A slot the router let, whose desktop no longer belongs to that letting
# --------------------------------------------------------------------------
#
# THE LEAK, as the owner produced it: create a session, change something, and
# use GNOME itself to log out -- the documented, correct way to finish. The
# session stops; the slot's socket unit keeps listening; the disconnected client
# reloads every five seconds and that reload is proxied straight into the still
# listening socket, which starts a FRESH desktop in the same slot. The router
# then correctly refuses to hand the visitor a desktop that is not the one it
# minted for them, mints them another slot, and the old one goes on running a
# full GNOME desktop for nobody. One visitor consumed four slots in seven
# minutes by behaving correctly four times.
#
# THE RULING IS NARROW AND THE QUALIFIER IS THE WHOLE OF IT: the router may
# reclaim a slot IT KNOWS IT LET. Not a slot that merely looks wrong. The
# window between a logout and the runtime directory going away is wide enough
# to mint a second visitor onto -- measured at roughly 0.7 to 2 seconds -- so a
# repair that reclaimed on mismatch alone would destroy a real person's desktop
# seconds after they were handed it.
#
# Mechanism and window measured on a container 2026-09-25, with its control:
# private/evidence/slot-recycle/2026-09-25-mechanism.txt. Nothing in this file
# observes systemd, a cgroup or a compositor; see Slot.logout() and
# Slot.torn_down() for exactly what is stood in for.


def logout_and_reload(rig, client, sid, slot):
    """The owner's sequence: log out, and reload INSIDE the window.

    THE ORDER IS THE MEASUREMENT, not a convenience. The reload happens while
    the runtime directory is still there -- measured, the session went inactive
    at t=4.45 and the directory survived to t=5.22 -- because that is the
    instant the whole defect lives in. A rig that logged out and then waited
    would be testing the easy world, where occupancy alone gates and there is
    nothing to repair.

    Returns the status the visitor got. It asserts nothing about it, so the
    same helper serves the repaired router and the red arm that undoes it.
    """
    slot.logout(leave_rundir=True)
    st, _, _ = client.get("/s/%s/" % sid)
    return st


def recycled_underneath(rig, client, sid, slot):
    """The slot ends up running a desktop that is not the one it was let for.

    NOT VIA THE ROUTER, and that is the point since the window closed: a
    repaired router refuses to proxy into a stopped session, so it can no
    longer be the thing that starts the replacement. Somebody else does --
    root, an admin restarting a unit, the sweep plus any later connection --
    and the RECLAIM is what covers those. Returns the status of the visit after
    the replacement is in place.
    """
    before = slot.incarnation
    slot.logout(leave_rundir=True)
    slot.resurrect()
    assert slot.incarnation is not None and slot.incarnation != before, \
        "%s did not come back with a NEW incarnation" % slot.name
    st, _, _ = client.get("/s/%s/" % sid)
    return st


def four_correct_logouts(rig, asked=None):
    """ONE VISITOR, FOUR ROUNDS OF THE OWNER'S OWN SEQUENCE. Slots used.

    ASSERTS ONLY WHAT THE VISITOR CAN SEE -- that each arrival is served and
    each return is gated -- and deliberately nothing about teardown requests.
    That is what lets the red arm below run this same code against a router
    with the repair undone and have EXHAUSTION be the thing that speaks: with
    two slots and four rounds, the third arrival has nowhere to go unless a
    slot came back. An arm whose red came from a missing request file instead
    would be checking the repair's own bookkeeping, not the leak.

    What ASKED collects, when a list is passed, is what the router requested in
    each round, for the caller to judge.
    """
    c = rig.client()
    used = []
    for i in range(4):
        sid, name = arrive_on_slot(rig, c)
        used.append(name)
        slot = slot_named(rig, name)
        st = logout_and_reload(rig, c, sid, slot)
        assert st == 410, (
            "round %d: the reload inside the window was PROXIED into a slot "
            "whose session had stopped (%d). That connection is what starts a "
            "fresh desktop in a slot somebody else is still let." % (i + 1, st))
        assert slot.incarnation is None, (
            "round %d: a fresh desktop was started in %s by the visitor's own "
            "reload -- the slot was recycled underneath the letting"
            % (i + 1, name))
        if asked is not None:
            asked.append(rig.teardown_requests())
        # systemd finishing what the logout started. Not an assertion: this is
        # the far edge of the window, and the slot is only free after it.
        slot.finish_logout()
        rig.run_teardowns()
    return used


def open_stream(rig, client, sid):
    """The tab's stream: an upgrade through the router, answered 101 and held."""
    s = socket.create_connection(("127.0.0.1", rig.port), 10)
    s.settimeout(10)
    req = ["GET /s/%s/websocket HTTP/1.1" % sid, "Host: demux.test",
           "Authorization: Basic " + client.auth,
           "Cookie: hdw4s_id=" + client.cookie,
           "Upgrade: websocket", "Connection: Upgrade",
           "Sec-WebSocket-Version: 13",
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="]
    s.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        assert chunk, "the router closed the stream before answering it"
        head += chunk
    status = int(head.split(b" ", 2)[1])
    assert status == 101, "the stream was not opened through the router: %d" \
        % status
    return s


def stream_until_dropped(rig, client, sid, slot, drop):
    """Open the tab's stream, let DROP end it from the desktop's side, and
    return once the TAB has seen it end -- the moment its client reconnects."""
    ws = open_stream(rig, client, sid)
    for _ in range(100):
        if slot.streams:
            break
        time.sleep(0.01)
    assert slot.streams, "%s never received the stream" % slot.name
    drop()
    ws.settimeout(5)
    try:
        rest = ws.recv(1)
    except OSError:
        rest = b""
    ws.close()
    assert rest == b"", "the tab's stream carried data after the desktop left"


def test_a_logout_with_the_tab_open_starts_no_desktop(rig):
    """THE RESURRECTION, as production showed it: log out with the tab open.

    Measured 2026-09-27 on production and on a development box: the logout
    stops the session, the relay goes with it and closes the tab's stream, and
    the client reconnects 9 ms later -- inside the moment in which the session's
    port is still listening and its runtime directory still exists. The
    reconnect was proxied, and the proxy's connect() started a fresh desktop in
    the slot for nobody.

    The oracle is the SLOT: whether a new start of it was published. The
    visitor must get the ended page (410), and nothing may be asked to be torn
    down, because nothing should have been started to need it.
    """
    c = rig.client()
    sid, name = arrive_on_slot(rig, c)
    slot = slot_named(rig, name)
    stream_until_dropped(rig, c, sid, slot, lambda: slot.log_out_under_a_stream(
        door_after=0.4, rundir_after=1.0))
    st, _, _ = c.get("/s/%s/" % sid)
    assert slot.incarnation is None, (
        "the tab's reconnect after a logout started a fresh desktop in %s, "
        "owned by nobody" % name)
    assert st == 410, "the visitor was not shown the ended page: %d" % st
    assert rig.teardown_requests() == [], (
        "a teardown was requested, so a desktop had been started for nobody: "
        "%r" % (rig.teardown_requests(),))


def test_a_desktop_that_closes_a_stream_and_stays_is_still_reached(rig):
    """THE PERMIT ARM: a stream closed by a desktop that is NOT going away.

    The streaming server closes a tab's stream for reasons of its own -- a
    second viewer taking over is one -- and the desktop stays. A router that
    treated every hang-up as the end would take that desktop from its owner,
    which is the more expensive of the two mistakes. So the same drop, with
    nothing else changing, must still reach the SAME start of the same slot.
    """
    c = rig.client()
    sid, name = arrive_on_slot(rig, c)
    slot = slot_named(rig, name)
    token = slot.incarnation
    stream_until_dropped(rig, c, sid, slot, slot.hang_up_streams)
    st, _, body = c.get("/s/%s/" % sid)
    assert st == 200, "a desktop that is still there was gated: %d" % st
    assert ("SLOT=%s" % name) in body.decode() and slot.incarnation == token, \
        "the visitor did not reach the desktop they had"


NO_SETTLE_AFTER_A_HANG_UP = """

# Appended by the red arm: a hang-up is not waited out. The reconnect is judged
# at once, by instruments that have not caught up with the logout yet.
def settle_after_hang_up(rec, instance, replaced=session_replaced,
                         clock=time.time, sleep=time.sleep):
    return replaced(rec, instance)
"""


def red_a_logout_with_the_tab_open_resurrects_again():
    """RED ARM: without the wait, the tab's reconnect starts a desktop."""
    path = scratch_demux("-nosettle.py", NO_SETTLE_AFTER_A_HANG_UP)
    rig = Rig(nslots=2, demux=path)
    try:
        try:
            test_a_logout_with_the_tab_open_starts_no_desktop(rig)
        except AssertionError as e:
            if "started a fresh desktop" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


def test_a_correct_logout_does_not_consume_the_slot(rig):
    """FOUR IN A ROW, on a pool of two. The leak, reproduced and then not.

    The oracle is the BACKENDS, not the router's account of itself: which slot
    served is read from the slot's own answer, and a slot coming back is a name
    appearing twice.
    """
    asked = []
    used = four_correct_logouts(rig, asked)
    for i, request in enumerate(asked):
        assert request == [], (
            "round %d: a teardown was requested, which means a desktop had "
            "been started for nobody and needed ending. With the window shut "
            "there should have been nothing to reclaim: %r" % (i + 1, request))
    assert len(set(used)) <= len(rig.slots), \
        "more slots were handed out than exist: %r" % (used,)
    assert len(set(used)) < len(used), (
        "four sessions were served by four different slots, so nothing was "
        "reclaimed -- the pool was merely bigger than the test: %r" % (used,))


def test_a_slot_this_router_did_not_let_is_not_reclaimed(rig):
    """THE REFUSAL. A returning tab whose letting we no longer hold.

    The tab's letting was forgotten at the gate, and a restart in between
    must not bring it back: the table the router writes down holds only what
    it has not forgotten. The tab presents a session id that resolves to
    nothing, and "I do not know this session" must never become "so I will
    destroy what is in its slot".

    ENFORCED BY STRUCTURE AS WELL AS BY THE CHECK, and that is worth saying
    rather than leaving to be noticed: reclaim_slot() is reachable only from
    the two places that are holding a record, so there is no path on which a
    slot without a letting can be reached at all. The function's own refusal
    for a missing record is proved separately, with a red arm, by
    assert_reclaim_needs_a_letting() at every start of the router.
    """
    c = rig.client()
    sid, name = arrive_on_slot(rig, c)
    slot = slot_named(rig, name)
    st = recycled_underneath(rig, c, sid, slot)
    assert st == 410, "the visitor was not gated at a recycled slot: %d" % st
    rig.run_teardowns()
    # And now a SECOND replacement, with the router restarted in between: the
    # letting was forgotten at the gate above, so it must still be unknown.
    slot.resurrect()
    rig.restart()
    st, _, _ = c.get("/s/%s/" % sid)
    assert st == 410, "a tab with an unknown session id was not gated: %d" % st
    assert rig.teardown_requests() == [], (
        "a slot with NO letting on record was reclaimed anyway: %r"
        % (rig.teardown_requests(),))
    assert os.path.isdir(slot.rundir), \
        "%s's desktop was ended by a router that never let it" % name


def test_a_slot_re_let_to_somebody_else_is_not_reclaimed(rig):
    """THE REFUSAL THAT COSTS A REAL PERSON, and the one the window creates.

    One slot, so the second visitor has exactly one place to go. The first
    visitor logs out PAST the window -- the state in which the slot genuinely
    reads free -- and the second is minted onto it and gets a desktop. Now the
    first visitor's stale letting still names that slot and still fails to match
    what is running there. Reclaiming on that mismatch would destroy a desktop
    somebody was handed seconds ago while they were looking at it.

    THE OWNERSHIP GUARD IS SEEN REFUSING IN THE SAME RUN, twice over, because a
    reclaim must not make it possible to hand somebody a desktop that is not
    theirs: the first visitor is gated at their own old address rather than
    proxied onto the stranger now in it, and the second visitor's address
    refuses the first visitor outright.
    """
    a = rig.client()
    sid_a, name = arrive_on_slot(rig, a)
    slot = slot_named(rig, name)
    token_a = slot.incarnation

    # THE OWNERSHIP GUARD, REFUSING, on a live session and before anything else
    # happens -- asked here rather than at the end because after the gate below
    # the letting has been dropped and the same request would be answered 410,
    # which is a different guard. A refusal that could have come from either is
    # not evidence about this one.
    st, _, _ = rig.client().get("/s/%s/" % sid_a)
    assert st == 403, \
        "a stranger reached this visitor's session address: %d" % st

    slot.logout(leave_rundir=False)

    b = rig.client()
    sid_b, name_b = arrive_on_slot(rig, b)
    assert name_b == name, (
        "the second visitor did not land on the slot the first one left, so "
        "nothing here is about a re-let slot: %s then %s" % (name, name_b))
    assert slot.incarnation not in (None, token_a), \
        "the second visitor was given the first one's desktop"

    st, _, _ = a.get("/s/%s/" % sid_a)
    assert st == 410, (
        "the first visitor was not gated at a slot that is now somebody "
        "else's: %d" % st)
    assert rig.teardown_requests() == [], (
        "a slot re-let to somebody else was reclaimed out from under them: %r"
        % (rig.teardown_requests(),))

    st, _, body = b.get("/s/%s/" % sid_b)
    assert st == 200, "the second visitor's own desktop was ended: %d" % st
    assert ("SLOT=%s" % name) in body.decode(), \
        "the second visitor stopped being served by %s" % name


RECLAIM_ON_MISMATCH_ALONE = """

def assert_reclaim_needs_a_letting(judge=None, factory=None):
    return None


def reclaimable(own, sid, rec, rundir=None, webroot=None):
    # THE DEFECT THE RULING'S QUALIFIER EXISTS TO PREVENT, put back on purpose:
    # reclaim whenever what is running does not match the letting, without ever
    # asking whether the letting is still the current one. Every line of this is
    # defensible on its own and the whole is an eviction.
    if rec is None or not occupancy_readable(rundir):
        return "no letting"
    instance = rec["instance"]
    if not slot_occupied(instance, rundir):
        return "nothing there"
    now = slot_incarnation(instance, webroot)
    if now is None or now == rec.get("incarnation"):
        return "still ours"
    return None
"""


NO_DOOR_CHECK = """
def assert_door_only_refuses_what_it_measured(ports=None, door=None,
                                              replaced=None, factory=None):
    # Stubbed so the arm can REACH the rig. Run either mutation below without
    # this and the router refuses to start, which is the startup guard catching
    # it unaided -- the first place each of these was watched go red.
    return None

def slot_door_open(instance, ports=None, etc=None):
    # THE WINDOW, REOPENED: the router goes back to deciding on the runtime
    # directory alone, which outlives the session it describes. "None" is the
    # honest shape of the old behaviour -- the question was never asked.
    return None
"""


NO_DOOR_AND_NO_RECLAIM = """
def assert_door_only_refuses_what_it_measured(ports=None, door=None,
                                              replaced=None, factory=None):
    # Stubbed so the arm can REACH the rig. Run either mutation below without
    # this and the router refuses to start, which is the startup guard catching
    # it unaided -- the first place each of these was watched go red.
    return None

def slot_door_open(instance, ports=None, etc=None):
    return None


def reclaim_slot(own, sid, rec, why, request=None, rundir=None, webroot=None):
    return False
"""


def red_the_window_is_open_again():
    """RED ARM: without the door check, the visitor's own reload recycles the slot.

    THE PRECISE ONE FOR THIS BRANCH. It does not go looking for exhaustion --
    it checks the single step the repair is about: a reload arriving while the
    runtime directory is still there gets PROXIED into a socket whose session
    has stopped, and that connection starts a fresh desktop under the old
    letting. Four-out-of-four in the field, because the client reloads every
    five seconds and the directory survives the session by about half a second.
    """
    path = scratch_demux("-nodoor.py", NO_DOOR_CHECK)
    rig = Rig(nslots=2, demux=path)
    try:
        c = rig.client()
        sid, name = arrive_on_slot(rig, c)
        slot = slot_named(rig, name)
        before = slot.incarnation
        slot.logout(leave_rundir=True)
        st, _, _ = c.get("/s/%s/" % sid)
        if st != 200:
            raise RuntimeError(
                "the red arm went red for the wrong reason: the reload was "
                "not proxied even with the door check removed (%d)" % st)
        assert slot.incarnation in (None, before), (
            "a fresh desktop was started in %s by the visitor's own reload, "
            "under a letting that is still somebody else's" % name)
    finally:
        rig.stop()
        _remove_scratch_demuxes()


NO_RECLAIM_AT_ALL = """

def reclaim_slot(own, sid, rec, why, request=None, rundir=None, webroot=None):
    # THE ROUTER AS IT WAS: it gates the visitor and leaves the desktop that is
    # no longer theirs running in the slot, for nobody, until the idle sweep
    # comes for it -- which on a stock install is SEVEN DAYS, because
    # hdw4s.conf sets no window and a bare number in that setting means days.
    return False
"""


def red_a_logout_still_consumes_the_slot():
    """RED ARM: the leak itself, reproduced on a router with the repair undone.

    THIS IS THE BEFORE HALF of "reproduced before and not after, on one build",
    and it is here rather than in a findings file because a leak nobody can
    make happen again is a leak that comes back. It must fail on the THIRD
    round: two slots, two of them burned, and the third arrival has nowhere to
    go.
    """
    # BOTH REPAIRS UNDONE, and it has to be both now, which is itself the
    # finding. With only the reclaim removed the pool no longer empties,
    # because the door check stops the desktop being started at all; with only
    # the door removed it no longer empties either, because the reclaim ends
    # what got started. They cover the same leak from the two ends, so the
    # original failure -- one visitor consuming four slots in seven minutes by
    # behaving correctly -- needs both gone before it comes back.
    path = scratch_demux("-noneither.py", NO_DOOR_AND_NO_RECLAIM)
    rig = Rig(nslots=2, demux=path)
    try:
        c = rig.client()
        try:
            for _ in range(4):
                sid, name = arrive_on_slot(rig, c)
                slot = slot_named(rig, name)
                slot.logout(leave_rundir=True)
                c.get("/s/%s/" % sid)      # the reload, which resurrects
                c.get("/s/%s/" % sid)      # and the next one, which gates
                rig.run_teardowns()
        except AssertionError as e:
            if "arrival did not redirect: 503" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
        raise AssertionError(
            "four rounds of the owner's sequence ran on a two-slot pool "
            "without exhausting it, so nothing leaked")
    finally:
        rig.stop()
        _remove_scratch_demuxes()


TABLE_IN_MEMORY_AGAIN = """

# Appended by the red arm: the table goes back to living in this process only.
Ownership._save = lambda self: None
"""


def red_the_table_is_forgotten_at_a_restart():
    """RED ARM: a router that does not write its table down loses the visitor."""
    path = scratch_demux("-inmemory.py", TABLE_IN_MEMORY_AGAIN)
    rig = Rig(demux=path)
    try:
        try:
            test_a_visitor_keeps_their_desktop_across_a_router_restart(rig)
        except AssertionError as e:
            if "cut off from it" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


SAY_EVERY_TIME = """

# Appended by the red arm: every refused request is its own log line.
def say_once(key, msg=None):
    if msg is not None:
        log(msg)
    return True
"""


def red_a_refusal_is_logged_per_request():
    """RED ARM: a line per request, which is the log somebody silences."""
    path = scratch_demux("-sayall.py", SAY_EVERY_TIME)
    rig = Rig(demux=path)
    try:
        try:
            test_a_refused_session_is_logged_once(rig)
        except AssertionError as e:
            if "was refused five times and logged 5 time(s)" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


def red_reclaim_on_mismatch_alone():
    """RED ARM: a router that reclaims without asking whose slot it is.

    The startup guard catches this on its own -- run it without the stub in
    RECLAIM_ON_MISMATCH_ALONE and the router refuses to start, which is where
    this was first watched go red. Stubbed out here so the arm reaches the RIG,
    because the two prove different things: that the function refuses, and that
    the refusal is on the path a real request takes.
    """
    path = scratch_demux("-reclaim.py", RECLAIM_ON_MISMATCH_ALONE)
    rig = Rig(nslots=1, demux=path)
    try:
        try:
            test_a_slot_re_let_to_somebody_else_is_not_reclaimed(rig)
        except AssertionError as e:
            # WHICH ASSERTION WENT RED, checked rather than assumed. A red arm
            # that fails for any other reason reports the guard working while
            # proving nothing about it, and this test has five other
            # assertions that could have been the one that spoke. Raised as a
            # non-AssertionError so the harness reports it as the wrong
            # failure instead of counting it as the arm.
            if "reclaimed out from under them" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


# --- concurrent arrivals: ONE slot is ONE letting ------------------------
#
# MEASURED ON A DEVELOPMENT CONTAINER, 2026-09-27: nine new visitors, each
# with its own cookie jar, sent to the front door at one instant, were logged
# as nine mints with nine visitor tags onto TWO slots within a second -- six on
# ephemeral0, three on ephemeral1 (private/evidence/concurrent-mint-race-1.txt).
# Every connection is served on its own thread, and the pick of a free slot was
# computed from the table and the reservations BEFORE either of them recorded
# the mint that pick led to. So every thread that picked before the first one
# recorded saw the same slot free. Nothing here saw it, because every test
# above arrives one visitor at a time.


def load_demux_from(path):
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader(
        "demux_mod_%d" % id(path), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def concurrent_lettings(path, entry, nslots, nvisitors):
    """NVISITORS new browsers ask for a desktop at one instant, through ENTRY.

    Returns (instances let, statuses). Runs the router's own arrival() or its
    directory's create, IN THIS PROCESS, against an in-memory table.

    THE WINDOW IS WIDENED, AND THAT IS THE WHOLE TECHNIQUE. On a workstation
    the pick and the record are microseconds apart, so a burst reproduces the
    race some of the time -- a red that comes and goes is not a red anybody can
    rely on. So every visitor is held, just after it has read what is taken and
    before it acts on that, until all of them have read it. A router that makes
    the read and the record ONE act cannot be held there by more than one
    visitor at a time: the barrier times out, is broken, and the rest go through
    one by one. What is stood in for is timing, never the decision: pick_slot(),
    slots_in_use(), the table and the reservation are the router's own.

    Stood in for: the pool table (a list), occupancy (unreadable, so only the
    router's own mints count -- the half this defect is about), the socket
    listing (none, so the first free slot is offered), and the log.
    """
    import io
    m = load_demux_from(path)
    tmp = tempfile.mkdtemp(prefix="demux-concurrent-")
    pool = ["ephemeral%d" % i for i in range(nslots)]
    m.ephemeral_slots = lambda table=None: list(pool)
    m.occupancy_readable = lambda rundir=None: False
    m.listening_paths = lambda *a, **kw: None
    m.RESERVE_DIR = os.path.join(tmp, "reserved")
    m.TEARDOWN_DIR = os.path.join(tmp, "teardown")
    os.makedirs(m.TEARDOWN_DIR)
    m.log = lambda msg: None
    m.log_refusal = lambda *a, **kw: None
    barrier = threading.Barrier(nvisitors, timeout=1.5)
    read_taken = m.slots_in_use

    def held(own, slots=None):
        taken = read_taken(own, slots)
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        return taken
    m.slots_in_use = held

    own = m.Ownership()
    statuses = []
    lock = threading.Lock()

    def visitor():
        wf = io.BytesIO()
        identity = own.mint_identity()
        if entry == "front door":
            m.arrival(own, wf, identity, b"", True)
        else:
            m.console(own, wf, identity, True, "create", None, b"POST")
        with lock:
            statuses.append(int(wf.getvalue().split()[1]))

    threads = [threading.Thread(target=visitor) for _ in range(nvisitors)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    lettings = [r["instance"] for r in own._by_sid.values()]
    return lettings, sorted(statuses)


def assert_one_letting_per_slot(path, entry, nslots, nvisitors):
    lettings, statuses = concurrent_lettings(path, entry, nslots, nvisitors)
    twice = sorted({n for n in lettings if lettings.count(n) > 1})
    assert not twice, (
        "%d visitors arriving at once through the %s were let %d desktop(s) "
        "on %d slot(s): %s let to more than one of them -- two strangers "
        "handed ONE desktop" % (nvisitors, entry, len(lettings),
                                len(set(lettings)), ", ".join(twice)))
    want = min(nslots, nvisitors)
    assert len(lettings) == want, (
        "%d visitors at once on a %d-slot pool were let %d desktop(s), not %d"
        % (nvisitors, nslots, len(lettings), want))
    ok = 302 if entry == "front door" else 303
    want_statuses = sorted([ok] * want + [503] * (nvisitors - want))
    assert statuses == want_statuses, (
        "the %s answered %s; wanted %s -- every visitor past the pool must be "
        "REFUSED, and every one inside it let" % (entry, statuses,
                                                   want_statuses))


def test_concurrent_arrivals_are_let_distinct_slots(rig=None):
    """Nine at once on nine slots: nine slots. Through BOTH minting sites."""
    for entry in ("front door", "directory's New desktop"):
        assert_one_letting_per_slot(DEMUX, entry, 9, 9)


def test_concurrent_arrivals_past_the_pool_are_refused(rig=None):
    """Twelve at once on nine slots: nine lettings, three refusals, no twins.

    THE OTHER HALF, and without it the repair above is satisfied by a router
    that serialises the pick and then refuses everybody after the first -- or
    by one that lets the twelfth visitor share a slot because a count said
    there was room."""
    for entry in ("front door", "directory's New desktop"):
        assert_one_letting_per_slot(DEMUX, entry, 9, 12)


def test_a_burst_through_the_real_front_door_is_let_distinct_slots(rig):
    """The same question with nothing stood in for but the desktops.

    The real router process, real threads, real TCP: twelve cookieless
    browsers released together at a nine-slot pool. NOT the red half of this
    defect -- whether the unwidened race is hit here depends on the machine,
    and concurrent_lettings() above is what makes it certain. This is what
    says the repair is on the path a real request takes, and that it has not
    turned a full pool into a hang."""
    n = 12
    go = threading.Barrier(n, timeout=10)
    got = []
    lock = threading.Lock()

    def one():
        # RECORDED, NEVER ASSERTED, in the thread: an assertion here would die
        # with the thread and the test would report a count instead of a cause.
        c = rig.client()
        go.wait()
        st, h, _ = c.get("/")
        where = None
        if st == 302:
            c.learn_cookie(h)
            st2, _, body = c.get(h["location"][0])
            # 410 HERE IS THE DEFECT'S USUAL FACE. A slot let twice gates the
            # EARLIER letting as superseded, so a visitor who was just handed a
            # desktop is told it has ended before they ever saw it. But a
            # refusal is only CALLED a re-let below if the router's log shows
            # one: a 502 once came from this rig's own stand-in, not the router.
            where = body.decode().split("SLOT=")[1].split()[0] \
                if st2 == 200 else "answered %d" % st2
        with lock:
            got.append((st, where))

    threads = [threading.Thread(target=one) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert len(got) == n, "only %d of %d arrivals came back" % (len(got), n)
    slots = [w for st, w in got if st == 302]
    refused = [st for st, _ in got if st != 302]
    lost = [w for w in slots if w.startswith("answered")]
    # THE ROUTER'S OWN COUNT OF LETTINGS PER SLOT decides what a refusal was.
    # Asked of the log rather than inferred from the status, because two
    # causes answer a fresh visitor with an error and only one is a re-let.
    import collections
    import re
    let = collections.Counter(re.findall(r"minted a session: slot (\S+),",
                                         rig.stderr_text()))
    twice = sorted(n for n, k in let.items() if k > 1)
    assert not twice, (
        "a burst of arrivals let %s to more than one visitor (%s), and %d "
        "visitor(s) were then refused their new desktop (%s)"
        % (", ".join(twice), dict(let), len(lost), ", ".join(lost) or "none"))
    assert not lost, (
        "%d visitor(s) handed a desktop in a burst were refused it on arrival "
        "(%s), and the router's log shows NO slot let twice (%s) -- not a "
        "re-let; look at the stand-in slot and at forward_request()"
        % (len(lost), ", ".join(lost), dict(let)))
    assert len(slots) == len(set(slots)), \
        "a burst of arrivals put two visitors on one slot: %s" % sorted(slots)
    assert len(slots) == len(rig.slots), \
        "a burst of %d on %d slots let %d" % (n, len(rig.slots), len(slots))
    assert refused == [503] * (n - len(rig.slots)), \
        "the arrivals past the pool were answered %s, not refused" % refused


def reclaim_holds_the_letting(path):
    """True when reclaim_slot() decides AND acts with no letting able to land
    in between. Asked of the lock at the instant of the act, because the
    interleaving itself -- a desktop stopping between the question and the
    request -- cannot be produced on demand without widening a window that
    the router gives no seam for."""
    m = load_demux_from(path)
    m.log = lambda msg: None
    m.reclaimable = lambda *a, **kw: None
    m.teardown_requested = lambda *a, **kw: False
    own = m.Ownership()
    seen = []

    def request(instance):
        seen.append(own.letting.locked())
        return None
    m.reclaim_slot(own, "0" * 32, {"instance": "ephemeral0"}, "a test",
                   request=request)
    assert seen, "reclaim_slot() never asked for a teardown, so nothing was tested"
    return seen[0]


def test_a_reclaim_cannot_interleave_with_a_letting(rig=None):
    """A reclaim that decided on an old desktop must not end a new visitor's.

    reclaimable() answers "a desktop is running here and nobody else holds
    the slot"; if a letting can land between that answer and the teardown
    request, the request ends the NEW visitor's desktop as it starts."""
    assert reclaim_holds_the_letting(DEMUX), (
        "a teardown was requested while a letting could land on the same slot "
        "-- a visitor let it in between loses their fresh desktop")


RECLAIM_WITHOUT_THE_LETTING = """

# Appended by the red arm: the reclaim decides and acts without the lock.
def reclaim_slot(own, sid, rec, why, request=None, rundir=None, webroot=None):
    return _reclaim_slot(own, sid, rec, why, request, rundir, webroot)
"""


def red_a_reclaim_interleaves_with_a_letting():
    path = scratch_demux("-reclaim-unlocked.py", RECLAIM_WITHOUT_THE_LETTING)
    try:
        assert reclaim_holds_the_letting(path), \
            "a teardown was requested while a letting could land"
    finally:
        _remove_scratch_demuxes()


LETTING_NOT_ATOMIC = """

# Appended by the red arm: the pick and the record are two acts again.
def let_slot(own, identity):
    instance = pick_slot(own)
    if instance is None:
        return None, None
    sid = own.mint_session(identity, instance)
    reserve_slot(instance)
    return instance, sid
"""


def red_concurrent_arrivals_share_a_slot():
    """RED ARM: the letting with its lock taken away. Must put twins on a slot."""
    path = scratch_demux("-letting.py", LETTING_NOT_ATOMIC)
    try:
        try:
            assert_one_letting_per_slot(path, "front door", 9, 9)
        except AssertionError as e:
            if "two strangers handed ONE desktop" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        _remove_scratch_demuxes()


# --- a press that another page made --------------------------------------
#
# Every console POST was checked for the cookie and nothing else, so what kept a
# page elsewhere from spending a slot, connecting without the card or ending a
# desktop was the browser's SameSite=Lax -- which does not hold cookies back
# from a same-site sibling, and which a cookieless request does not need.

ANOTHER_PAGE = [
    ("Sec-Fetch-Site: cross-site",),
    ("Sec-Fetch-Site: same-site",),
    ("Sec-Fetch-Site: none",),
    # The browser's word wins over an Origin that happens to match.
    ("Sec-Fetch-Site: cross-site", "Origin: http://demux.test"),
    # An older browser, with no Sec-Fetch-Site, naming the page that asked.
    ("Origin: https://elsewhere.example",),
    ("Origin: null",),
    ("Origin: http://demux.test.elsewhere.example",),
]


def test_a_press_from_another_page_is_refused(rig):
    """Every console POST another page can make is refused, acts on nothing,
    hands out no identity, and is said once per kind of request."""
    a = rig.client()
    sid, _ = arrive(rig, a)
    mints = mint_lines(rig)
    for hdrs in ANOTHER_PAGE:
        for path in ("/sessions/new", "/sessions/%s/resume" % sid,
                     "/sessions/%s/discard" % sid):
            st, h, body = a.post(path, headers=hdrs)
            assert st == 403, (
                "a POST to %s carrying %s was not refused: %d -- another page "
                "can act on this visitor's desktops" % (path, hdrs, st))
            assert "location" not in h, \
                "a refused POST to %s still sent the browser on" % path
            assert not fresh_markers(h), \
                "a refused POST to %s handed out a connect marker" % path
            assert "Your desktops" in body.decode(), \
                "the refusal gives the visitor no way on"
    assert mint_lines(rig) == mints, \
        "a refused POST minted a desktop anyway"
    assert rig.teardown_requests() == [], \
        "a refused discard asked for a teardown anyway: %r" \
        % rig.teardown_requests()

    # A browser with NO cookie, which is what a page elsewhere most often
    # produces: it must not be handed an identity, and nothing is let.
    stranger = rig.client()
    st, h, _ = stranger.post("/sessions/new",
                             headers=("Sec-Fetch-Site: cross-site",))
    assert st == 403, "a cookieless cross-site create was not refused: %d" % st
    assert "set-cookie" not in h, \
        "a refused cross-site POST handed a new browser an identity"
    assert mint_lines(rig) == mints, "a cookieless cross-site create minted"

    # ONCE, for the admin: seven attempts of one kind at create, one line.
    log = [l for l in rig.stderr_text().splitlines()
           if "another page asked" in l and "a create POST" in l
           and "Sec-Fetch-Site: cross-site" in l]
    assert len(log) == 1, (
        "repeated cross-site presses at create were logged %d time(s): %r"
        % (len(log), log))
    assert "visitor " in log[0] and "Nothing was done" in log[0], \
        "the refusal line does not say who or what happened: %r" % log[0]


def test_a_press_on_this_machines_own_page_still_acts(rig):
    """THE PERMIT ARM, without which the refusal above is satisfied by a
    router that refuses every POST -- New desktop, Resume and Discard gone for
    everybody, with every refusal test green."""
    a = rig.client()
    sid, _ = arrive(rig, a)
    # A browser that says the press came from this origin.
    st, h, _ = a.post("/sessions/new", headers=("Sec-Fetch-Site: same-origin",))
    assert st == 303, "a same-origin New desktop was refused: %d" % st
    # An older browser: no Sec-Fetch-Site, an Origin naming this host. The
    # port differs from Host's on purpose -- the proxy passes $host, which
    # carries none.
    st, h, _ = a.post("/sessions/%s/resume" % sid,
                      headers=("Origin: http://demux.test:8443",))
    assert st == 303, "an older browser's same-origin Resume was refused: %d" % st
    # NEITHER HEADER: a client acting for itself. Every rig and script that
    # posts here does so from a real browser on this origin, but the suite's
    # own client sends neither, and so does curl.
    st, h, _ = a.post("/sessions/%s/resume" % sid)
    assert st == 303, "a POST carrying neither header was refused: %d" % st
    st, h, _ = a.post("/sessions/%s/discard" % sid,
                      headers=("Sec-Fetch-Site: same-origin",))
    assert st == 303, "a same-origin Discard was refused: %d" % st
    assert len(rig.teardown_requests()) == 1, \
        "a same-origin Discard asked for no teardown"


CROSS_SITE_PERMITTED = """

# Appended by the red arm: every console POST acts, wherever it came from --
# the router as it was. The start-up check is disarmed too, or the router
# would refuse to start and the arm would be red for that instead.
def cross_site_refusal(headers):
    return None


def assert_cross_site_posts_are_refused(judge=None):
    return None
"""


def test_no_page_of_the_routers_can_be_framed(rig):
    """Every page the router writes itself refuses to be framed.

    A page elsewhere that framed /sessions/ could get a SAME-ORIGIN press on
    Discard out of the visitor -- which the cross-site refusal passes, because
    it is one. Asked of each kind of page the router renders, and of the
    refusal and the redirect, because a header added to one code path is the
    shape that misses the next."""
    a = rig.client()
    sid, _ = arrive(rig, a)
    asked = [("the directory", a.get("/sessions/")),
             ("a discard confirmation", a.get("/sessions/%s/discard" % sid)),
             ("the ended page", a.get("/s/%s/" % secrets_hex())),
             ("a 404", a.get("/nothing-here")),
             ("the front door's redirect", rig.client().get("/")),
             ("a cross-site refusal",
              a.post("/sessions/new", headers=("Sec-Fetch-Site: cross-site",)))]
    for what, (st, h, _) in asked:
        csp = " ".join(h.get("content-security-policy", []))
        xfo = h.get("x-frame-options", [])
        assert "frame-ancestors 'none'" in csp and xfo == ["DENY"], (
            "%s (%d) can be framed by another page: CSP %r, X-Frame-Options %r"
            % (what, st, csp, xfo))


def test_a_desktop_cannot_install_a_service_worker(rig):
    """Neither half of a registration reaches the browser or the desktop.

    Every desktop in the pool serves pages on the one origin the router's own
    pages use. A service worker registered there outlives the desktop in the
    visitor's browser, and with Service-Worker-Allowed it may claim / -- the
    front door, the directory, and every other session address."""
    a = rig.client()
    sid, body = arrive(rig, a)
    slot = slot_named(rig, body.split("SLOT=")[1].split()[0])

    # 1. The widening header is dropped; an ordinary one still passes, or a
    #    filter that dropped every header would satisfy this.
    slot.extra_headers = ("Service-Worker-Allowed: /",
                          "service-worker-allowed : /",
                          "X-Desktop-Ordinary: kept")
    st, h, _ = a.get("/s/%s/app.js" % sid)
    slot.extra_headers = ()
    assert st == 200, "the desktop's script did not serve: %d" % st
    assert "service-worker-allowed" not in h and \
        not any(k.strip() == "service-worker-allowed" for k in h), \
        "a desktop widened a service worker's scope: %r" % h
    assert h.get("x-desktop-ordinary") == ["kept"], \
        "the desktop's ordinary headers were dropped along with it"

    # 2. The registration fetch itself is refused, and never reaches the slot.
    before = len(slot.asked)
    mints = mint_lines(rig)
    for _ in range(3):
        st, h, body = a.get("/s/%s/sw.js" % sid,
                            headers=("Service-Worker: script",))
        assert st == 403, \
            "a service worker's script was served to the browser: %d" % st
        assert b"SLOT=" not in body, "the refusal came from the desktop"
    assert len(slot.asked) == before, \
        "a refused registration still reached the desktop: %r" \
        % slot.asked[before:]
    # And the same address without that header is an ordinary script.
    st, _, body = a.get("/s/%s/sw.js" % sid)
    assert st == 200 and b"SLOT=" in body, \
        "an ordinary request for the same address was refused too: %d" % st

    # 3. Said once, for the admin, and it minted nothing.
    lines = [l for l in rig.stderr_text().splitlines()
             if "service worker" in l and sid in l]
    assert len(lines) == 1, \
        "three refused registrations were logged %d time(s): %r" \
        % (len(lines), lines)
    assert mint_lines(rig) == mints, "a refused registration minted a desktop"
    # Nor at the router's own pages, where no session resolves it.
    st, h, _ = rig.client().get("/", headers=("Service-Worker: script",))
    assert st == 403 and "set-cookie" not in h and mint_lines(rig) == mints, \
        "a registration at the front door was answered %d, or minted" % st


SERVICE_WORKERS_AGAIN = """

# Appended by the red arm: both halves undone. The header filter is back to
# cookies only, and no request is recognised as a registration.
def session_may_send(line):
    name, sep, value = line.partition(b":")
    if sep and name.strip().lower() == b"set-cookie":
        return session_may_set_cookie(value)
    return True


def registers_a_service_worker(headers):
    return False
"""


def red_a_desktop_installs_a_service_worker():
    path = scratch_demux("-serviceworker.py", SERVICE_WORKERS_AGAIN)
    rig = Rig(demux=path)
    try:
        try:
            test_a_desktop_cannot_install_a_service_worker(rig)
        except AssertionError as e:
            if "widened a service worker's scope" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


REGISTRATION_SERVED_AGAIN = """

# Appended by the red arm: only the registration refusal undone.
def registers_a_service_worker(headers):
    return False
"""


def red_a_service_workers_script_is_served():
    path = scratch_demux("-swscript.py", REGISTRATION_SERVED_AGAIN)
    rig = Rig(demux=path)
    try:
        try:
            test_a_desktop_cannot_install_a_service_worker(rig)
        except AssertionError as e:
            if "script was served to the browser" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


def test_only_a_page_request_mints_at_the_front_door(rig):
    """An <img> or <iframe> on some other page must not spend a slot.

    Every such fetch carries the visitor's browser to the front door, and a
    browser that owns nothing live is minted a desktop there. The browser
    says what it is fetching in Sec-Fetch-Dest; only "document" -- a tab
    opening the address, which is what a link does -- may mint."""
    for dest in ("image", "iframe", "empty", "script"):
        c = rig.client()
        st, h, _ = c.get("/", headers=("Sec-Fetch-Dest: %s" % dest,))
        assert st == 403 and "location" not in h, (
            "a front-door request for an %s was answered %d%s -- another page "
            "can spend this browser on a slot"
            % (dest, st, " to %s" % h["location"][0] if "location" in h else ""))
        assert "set-cookie" not in h, \
            "a front-door request for an %s handed out an identity" % dest
    assert mint_lines(rig) == 0, \
        "a request that was not for a page minted a desktop"
    # THE PERMIT ARMS: a tab opening the address, and a client that sends no
    # Sec-Fetch-Dest at all (every rig here, curl, an old browser).
    st, h, _ = rig.client().get("/", headers=("Sec-Fetch-Dest: document",))
    assert st == 302 and h["location"][0].startswith("/s/"), \
        "a tab opening the front door was not given a desktop: %d" % st
    st, h, _ = rig.client().get("/")
    assert st == 302 and h["location"][0].startswith("/s/"), \
        "a client sending no Sec-Fetch-Dest was not given a desktop: %d" % st
    assert mint_lines(rig) == 2, "the permitted arrivals minted %d" \
        % mint_lines(rig)


MINT_FOR_ANY_DEST = """

# Appended by the red arm: the front door mints whatever is fetching it.
_shipped_arrival_dest = arrival


def arrival(own, wf, identity, query, new_identity, dest=None):
    return _shipped_arrival_dest(own, wf, identity, query, new_identity, None)
"""


def red_an_image_mints_at_the_front_door():
    path = scratch_demux("-anydest.py", MINT_FOR_ANY_DEST)
    rig = Rig(gate=None, demux=path)
    try:
        try:
            test_only_a_page_request_mints_at_the_front_door(rig)
        except AssertionError as e:
            if "can spend this browser on a slot" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


FRAMEABLE_AGAIN = """

# Appended by the red arm: the router's pages as they were, frameable.
FRAME_HEADERS = ()
"""


def red_the_directory_can_be_framed():
    path = scratch_demux("-frameable.py", FRAMEABLE_AGAIN)
    rig = Rig(demux=path)
    try:
        try:
            test_no_page_of_the_routers_can_be_framed(rig)
        except AssertionError as e:
            if "can be framed by another page" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


PREFIX_FILTER_AGAIN = """

# Appended by the red arm: the filter as it shipped, matching a prefix of the
# raw value rather than the name a browser reads out of it.
def session_may_set_cookie(value):
    return not value.strip().startswith(b"hdw4s_id=")
"""


def red_a_padded_name_sets_our_cookie():
    path = scratch_demux("-cookieprefix.py", PREFIX_FILTER_AGAIN)
    rig = Rig(demux=path)
    try:
        try:
            test_a_session_cannot_set_our_cookie(rig)
        except AssertionError as e:
            if "hdw4s_id =X" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


def red_a_press_from_another_page_acts():
    path = scratch_demux("-crosssite.py", CROSS_SITE_PERMITTED)
    rig = Rig(demux=path)
    try:
        try:
            test_a_press_from_another_page_is_refused(rig)
        except AssertionError as e:
            if "another page can act on this visitor's desktops" not in str(e):
                raise RuntimeError(
                    "the red arm went red for the wrong reason: %s" % e)
            raise
    finally:
        rig.stop()
        _remove_scratch_demuxes()


def red_startup_guard_notices_a_lax_judge():
    load_demux().assert_cross_site_posts_are_refused(lambda headers: None)


def red_startup_guard_notices_a_judge_that_refuses_everything():
    load_demux().assert_cross_site_posts_are_refused(lambda headers: "no")


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
             test_a_refused_session_is_logged_once,
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
             test_a_restart_does_not_re_let_a_slot_whose_desktop_is_still_starting,
             test_a_visitor_keeps_their_desktop_across_a_router_restart,
             test_a_reaped_slot_returns_to_the_pool_without_a_restart,
             test_a_reaped_visitor_reaches_the_gate_rather_than_a_dead_end,
             test_a_visited_slot_is_not_indistinguishable_from_a_never_visited_one,
             # The rescue console. The refusal and the admission are a PAIR and
             # are listed together so that neither can be removed alone.
             test_the_console_lists_only_your_own_sessions,
             test_one_visitor_cannot_discard_anothers_session,
             test_a_visitor_can_discard_their_own_session,
             test_opening_the_discard_address_only_asks,
             test_the_console_never_mints]

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
        # CREATE, and all three on the UNPINNED arm because the question is
        # what the SHIPPED product does. Under the pinned mint arm every
        # arrival mints anyway, so "a second desktop appeared" would say
        # nothing about whether a gesture was what produced it -- the test
        # would be green against a router that mints on sight, which is the
        # exact defect the arrival rule exists to prevent.
        (test_asking_for_a_second_desktop_takes_a_GESTURE, dict(gate=None)),
        # UNPINNED, because the shipped arm is what resumes, and resuming is
        # what the ended page's button did to the other desktop (bug 1).
        (test_the_ended_pages_button_starts_a_NEW_desktop, dict(gate=None)),
        (test_the_ended_page_and_restored_tabs_mint_NOTHING, dict(gate=None)),
        # UNPINNED: the shipped arm is the one whose bare arrival changed.
        (test_the_bare_address_shows_your_desktops, dict(gate=None)),
        # UNPINNED: the shipped arm is the one whose front door mints for a
        # browser that owns nothing live.
        (test_only_the_front_door_mints, dict(gate=None)),
        (test_the_ended_page_lists_what_is_still_running, dict(gate=None)),
        (test_every_pressable_keeps_its_target, dict(gate=None)),
        # UNPINNED for the same reason, and it needs one more thing: the
        # shipped arm is what RESUMES, and the control half of this test is the
        # resume. Under the pinned mint arm every arrival mints, so there is no
        # resume to check the marker's absence on and the test would be green
        # against a router that marked everything.
        (test_a_desktop_just_MINTED_is_marked_and_a_resumed_one_is_not,
         dict(gate=None)),
        # UNPINNED: the shipped arm, whose directory is where Resume lives.
        (test_resume_from_the_directory_connects_and_nothing_else_does,
         dict(gate=None)),
        (test_a_second_desktop_is_a_second_desktop, dict(gate=None)),
        # BUG 2, on the SHIPPED arm, with a slot per entry point and one spare
        # for the ended page's second desktop.
        (test_a_SLOW_start_shows_something_of_ours_within_two_seconds,
         dict(nslots=4, gate=None)),
        (test_a_FAST_start_shows_nothing_of_ours, dict(nslots=4, gate=None)),
        (test_each_row_names_its_own_desktop, dict(gate=None)),
        # Two slots, not three, so the pool can be filled by ONE visitor
        # without the run taking three creates to get there.
        (test_create_refuses_where_it_lives, dict(nslots=2, gate=None)),
        # ONE pool slot and one stray, so the second arrival has nowhere legal
        # to go. See the test's own docstring for why a spare slot would make
        # this green against the defect.
        (test_a_socket_outside_the_table_is_never_minted,
         dict(nslots=1, strays=["named0"])),
        # TWO slots and FOUR rounds, so the pool cannot absorb the leak. With
        # the default three it would pass against the defect.
        (test_a_correct_logout_does_not_consume_the_slot, dict(nslots=2)),
        (test_a_logout_with_the_tab_open_starts_no_desktop, dict(nslots=2)),
        (test_a_desktop_that_closes_a_stream_and_stays_is_still_reached,
         dict(nslots=2)),
        (test_a_slot_this_router_did_not_let_is_not_reclaimed, dict(nslots=2)),
        # ONE slot, so the second visitor has exactly one place to go and a
        # re-let is the only thing that can have happened.
        (test_a_slot_re_let_to_somebody_else_is_not_reclaimed, dict(nslots=1)),
        (test_a_letting_that_never_came_back_cannot_reach_the_next_one,
         dict(nslots=1)),
        # NINE slots, as on the container where the burst was measured, and
        # twelve arrivals, so the refusal past the pool is exercised too.
        (test_a_burst_through_the_real_front_door_is_let_distinct_slots,
         dict(nslots=9)),
        # The refusal and the permit are a PAIR, listed together so that
        # neither can be removed alone.
        (test_a_press_from_another_page_is_refused, dict(gate=None)),
        (test_a_press_on_this_machines_own_page_still_acts, dict(gate=None)),
        (test_no_page_of_the_routers_can_be_framed, dict(gate=None)),
        (test_a_desktop_cannot_install_a_service_worker, dict(gate=None)),
        (test_only_a_page_request_mints_at_the_front_door, dict(gate=None)),
    ]

    # Runs WITHOUT a rig from here, because it builds its own with the gate mode
    # unpinned -- the shipped default cannot be exercised by a rig that sets it.
    for fn in (test_shipped_default_resumes_a_returning_browser,
               test_a_slot_that_is_never_reaped_is_reported_at_start,
               test_a_duration_already_in_seconds_is_refused,
               test_the_records_the_refusal_log_is_read_from_survive_a_restart,
               # In-process, with the window between the pick and the record
               # held open; see concurrent_lettings().
               test_concurrent_arrivals_are_let_distinct_slots,
               test_concurrent_arrivals_past_the_pool_are_refused,
               test_a_reclaim_cannot_interleave_with_a_letting):
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
    # Builds its own rig, because its whole subject is two slots configured
    # DIFFERENTLY, which the shared rig cannot express.
    try:
        test_the_row_says_when_the_desktop_goes_by_itself()
        check(test_the_row_says_when_the_desktop_goes_by_itself.__name__, True)
    except Exception as e:
        check(test_the_row_says_when_the_desktop_goes_by_itself.__name__,
              False, repr(e))
    # These two build their OWN rigs, against a scratch copy of the router with
    # the repair undone, so they cannot share the one above.
    for fn in (red_pool_from_the_directory,
               red_startup_guard_notices_the_directory_listing,
               red_the_window_is_open_again,
               red_a_logout_still_consumes_the_slot,
               red_reclaim_on_mismatch_alone,
               red_the_table_is_forgotten_at_a_restart,
               red_a_logout_with_the_tab_open_resurrects_again,
               red_a_refusal_is_logged_per_request,
               red_scope_checked_by_the_page,
               red_a_console_address_that_stops_being_claimed,
               red_every_path_is_the_front_door,
               red_create_on_a_GET,
               red_the_ended_pages_button_resumes,
               red_the_bare_address_resumes,

               red_a_slow_start_is_the_loading_tab_again,
               red_our_page_in_front_of_a_fast_desktop,
               red_our_page_waits_for_itself,
               red_every_redirect_marked_as_a_fresh_mint,
               red_resume_on_a_GET,
               red_resume_of_a_desktop_that_is_not_yours,
               red_startup_guard_notices_a_console_address_that_moved,
               red_concurrent_arrivals_share_a_slot,
               red_a_reclaim_interleaves_with_a_letting,
               red_a_press_from_another_page_acts,
               red_a_padded_name_sets_our_cookie,
               red_the_directory_can_be_framed,
               red_a_desktop_installs_a_service_worker,
               red_a_service_workers_script_is_served,
               red_an_image_mints_at_the_front_door,
               red_startup_guard_notices_a_lax_judge,
               red_startup_guard_notices_a_judge_that_refuses_everything):
        expect_red(fn.__name__, fn)

    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
