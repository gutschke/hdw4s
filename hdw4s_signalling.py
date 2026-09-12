"""Session hand-over for the Selkies signalling server.

A browser client hardcodes its signalling peer ids -- 1 for video, 3 for audio --
so two clients on one desktop both claim the same ids and the second can never
register. Upstream refuses it and raises, which escapes the connection handler
and logs a traceback per attempt; a single stuck client produced 17858 of them
in two days, because nothing tells the client that this refusal is different
from any other closed socket, so it reconnects forever.

Supporting two concurrent viewers is a much larger change. What this does
instead is let a session be *handed over*: a second device is told the desktop
is open elsewhere and offered a button to take it.

This is a subclass rather than an edit to upstream's file. Upstream source is
never mutated, so there is nothing to back up, nothing for a package upgrade to
silently revert, and nothing to poison a rollback. The cost is that the
overridden bodies still copy upstream logic, so they can drift -- but see
`upstream_state()`: drift is detected at startup and fails loudly instead of
quietly doing nothing.
"""

import asyncio
import base64
import sys
import hashlib
import inspect
import os
import json
import logging
import time

logger = logging.getLogger("hdw4s.signalling")

# Bumped by hand so a running server can be identified beyond doubt.
BUILD = "handover-10"

# Close codes, from RFC 6455's private range. A client has to tell a refusal
# apart from every other reason a socket closes: it must keep reconnecting
# through a network hiccup, and stop reconnecting into a wall. Reason strings
# are advisory and length-capped, so the code is what carries the meaning.
CLOSE_SESSION_IN_USE = 4001   # held by another client; ask before taking it
CLOSE_TAKEN_OVER = 4002       # you were taken over; do not come back on your own
CLOSE_SUPERSEDED = 4003       # superseded by your own newer socket; go quietly

# If this change is ever taken upstream, the PR carries this attribute, and its
# presence is how we notice we are no longer needed. We cannot detect a merge of
# something upstream has no reason to announce, so the announcement has to be
# part of what we offer them.
UPSTREAM_CAPABILITY = "SUPPORTS_SESSION_HANDOVER"

# Where the browser client lives, and the marker its patch leaves behind. The
# two halves have to move together: a server that refuses a duplicate with a
# private close code, in front of a client that does not understand it, is
# worse than neither -- the client treats the refusal as an ordinary close and
# reconnects several times a second, forever.
#
# Rather than trust a flag some other program remembered to write, look at the
# client that will actually be served. It is the thing being asserted.
WEBROOT = os.environ.get("HDW4S_WEBROOT", "/opt/gst-web")
CLIENT_MARKER = "HDW4S takeover"
# index.html is in this list because the button lives there and nowhere else.
# Leaving it out let the server enable hand-over for a tree whose app.js and
# signalling.js were patched but whose markup was not -- the client then reaches
# the busy state, renders no button because no branch exists for it, and
# suppresses its own reconnect. A blank overlay over a session with no way back,
# which is worse than the behaviour being fixed.
CLIENT_FILES = ("app.js", "signalling.js", "index.html")

# The peer ids a browser claims. The client hardcodes these; the desktop's own
# app uses the even ones. Only these may ever be handed over -- letting a client
# take peer 0 or 2 would kick the desktop off its own signalling.
CLIENT_PEER_IDS = ("1", "3")

# Backpressure on a client that keeps being refused. A client that understands
# the refusal shows a button and stops; one that does not understand it
# reconnects several times a second forever, and the only lever the server has
# is to answer it more slowly. The first refusal is almost immediate so the
# button appears promptly.
REFUSAL_DELAY_STEP = 0.25
REFUSAL_DELAY_MAX = 2.0

# A client that takes the same session over again and again within a couple of
# seconds is a loop, not a person. Scoped to one client reclaiming the same peer
# repeatedly, so that two *different* devices trading a session are not slowed
# down by each other. Note the limit still applies to one device taking the same
# session twice inside the interval, which a determined pair of users clicking
# at each other can reach; they see a refusal and clicking again works.
TAKEOVER_MIN_INTERVAL = 2.0

# Refusals are logged once per peer, then summarised, because an unpatched or
# cached client loops several times a second and a healthy session already
# emits tens of thousands of lines a day.
REFUSAL_SUMMARY_INTERVAL = 60.0

# How often to look again at whether the served client can ask for a hand-over.
# The answer is taken once at startup to decide whether to install at all, and
# that decision cannot be revisited without restarting -- but the webroot can
# change underneath a running session, in both directions, and an operator who
# has just rolled the client back has no way to tell from the server that the
# two halves no longer agree. Looking again costs two small reads.
CLIENT_RECHECK_INTERVAL = 60.0

# sha256 of the upstream method bodies this subclass was written against. Used
# to tell "upstream moved" from "upstream is what we expect".
# The three methods this replaces, and the two it calls and depends on the
# behaviour of: run() is where the (None, None) sentinel gets unpacked, where a
# raise would become a traceback, and where remove_peer is called as a session
# unwinds; cleanup_session is relied on for its side effect of closing the
# session partner. Watching only what we override would leave the contract we
# depend on unguarded.
KNOWN_UPSTREAM = {
    # selkies-gstreamer 1.6.2
    "run": {
        "729f4c181df0891b4252564129bdf72e4a0067bdbb2edcb448d73d104ea1eeb6",
    },
    "cleanup_session": {
        "9ddd792b8572e2985d5b2f8f1982a3e3999f931656a87460d9f2515d6e47d139",
    },
    "hello_peer": {
        "19417020687a2b73ecf16f3d8de837332778286be7d6202e4448a70137aea50f",
    },
    "connection_handler": {
        "bde653ca0d1d5e19b08c63cb2f8ce6d0ba6389d4ebee40b7c521da7ee0729c29",
    },
    "remove_peer": {
        "2dc53de199f4b9cef51cf6b89d58a30da903193ef0e0a3cd9462db4acc41c323",
    },
}


def client_supports_handover(webroot=None):
    """Can the client that will be served actually ask for a hand-over?"""
    root = WEBROOT if webroot is None else webroot
    for name in CLIENT_FILES:
        path = os.path.join(root, name)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                if CLIENT_MARKER not in fh.read():
                    return False
        except OSError:
            return False
    return True


def _method_hash(base, name):
    try:
        src = inspect.getsource(getattr(base, name))
    except (OSError, TypeError, AttributeError):
        return None
    return hashlib.sha256(src.encode("utf-8")).hexdigest()


def current_hashes(base):
    """What the installed upstream looks like. Used to record a new version."""
    return {name: _method_hash(base, name) for name in KNOWN_UPSTREAM}


def upstream_state(base):
    """One of 'upstream-has-it', 'recognised', or 'drifted'.

    'upstream-has-it'  the change was taken upstream; stand down entirely.
    'recognised'       upstream is a version this subclass was written against.
    'drifted'          upstream changed and did not announce a hand-over
                       capability. Do NOT drop an override onto code that has
                       moved underneath: fall back to stock behaviour, which is
                       a known quantity, and say so loudly.
    """
    if getattr(base, UPSTREAM_CAPABILITY, False):
        return "upstream-has-it"
    have = current_hashes(base)
    for name, known in KNOWN_UPSTREAM.items():
        if not known:
            continue                      # no baseline recorded yet
        if have.get(name) not in known:
            return "drifted"
    return "recognised"


class HandoverMixin:
    """Upstream, plus the ability to hand a session to another device.

    A mixin rather than a subclass of a named class, because the class to
    extend is not knowable at import time. The application binds
    WebRTCSimpleServer by value, and does so from a *different* module object
    than `selkies_gstreamer.signalling_web` -- the package puts its own
    directory on sys.path, so `signalling_web` and
    `selkies_gstreamer.signalling_web` are two distinct modules holding two
    distinct classes. Subclassing the wrong copy would silently do nothing.
    So the base is whatever the module we are installing into actually holds.
    """

    SUPPORTS_SESSION_HANDOVER = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Which asyncio task currently owns each peer id. Every connection runs
        # in its own task, so this is what lets a cleanup know whether the entry
        # it is about to delete is still its own -- without changing any method
        # signature that upstream's connection handler calls.
        self._owner_task = {}
        self._refusal_count = {}
        self._refusal_logged_at = {}
        self._refusal_streak = {}
        self._last_takeover = {}
        # ensure_future returns a task nothing else holds a reference to, and
        # an unreferenced task can be collected before it has run. Keeping them
        # here until they finish is free and removes the hazard.
        self._evictions = set()
        self._client_ok = None
        self._client_checked = 0.0

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _identity(meta):
        if isinstance(meta, dict):
            value = meta.get("client")
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _wants_takeover(meta):
        return bool(isinstance(meta, dict) and meta.get("takeover"))

    def _client_can_ask(self):
        """Can the client being served still ask for a hand-over?

        Cached briefly, because it is asked on a path a misbehaving client can
        drive several times a second.
        """
        now = time.monotonic()
        if self._client_ok is None or now - self._client_checked > CLIENT_RECHECK_INTERVAL:
            ok = client_supports_handover()
            if self._client_ok is not None and ok != self._client_ok:
                if ok:
                    logger.warning(
                        "the client in %s now supports session hand-over; "
                        "sessions started before it was updated are still "
                        "serving the old behaviour and need restarting", WEBROOT)
                else:
                    logger.warning(
                        "the client in %s no longer supports session hand-over, "
                        "so a second device is being refused in a way it cannot "
                        "recognise and will retry. Restart this session, or put "
                        "the patched client back", WEBROOT)
            self._client_ok = ok
            self._client_checked = now
        return self._client_ok

    def _note_refusal(self, uid, raddr, incoming):
        """Log the first refusal per peer, then one summary a minute.

        The bit worth having in the log is whether the client sent an identity
        at all. Without one, this is not a second device politely waiting for
        someone to press a button -- it is a client that does not understand the
        protocol, looping, which means a deployment went wrong.
        """
        now = time.monotonic()
        self._refusal_count[uid] = self._refusal_count.get(uid, 0) + 1
        last = self._refusal_logged_at.get(uid)
        if last is None or now - last >= REFUSAL_SUMMARY_INTERVAL:
            logger.warning(
                "Refusing peer %r from %r: session in use "
                "(client_identified=%s, client_can_ask=%s, "
                "refusals=%d since last report)",
                uid, raddr, incoming is not None, self._client_can_ask(),
                self._refusal_count[uid])
            self._refusal_logged_at[uid] = now
            self._refusal_count[uid] = 0

    def _other_leg_held_elsewhere(self, uid, incoming):
        """Is the client's other leg already held by somebody else?

        A page opens its video and audio legs a few hundred milliseconds apart,
        so without this a second device is refused the picture and handed the
        sound -- one device showing the desktop, another playing it, while the
        second is being told it is open somewhere else.

        Asked as a question about what is held right now rather than remembered
        from an earlier refusal, so it stops applying the instant the other
        device goes away.
        """
        for other in CLIENT_PEER_IDS:
            if other == uid:
                continue
            entry = self.peers.get(other)
            if entry is None:
                continue
            held = self._identity(entry[3])
            if held is not None and held != incoming:
                return True
        return False

    async def _refuse(self, ws, uid, raddr, incoming):
        """Say no, and say it a little more slowly to whoever keeps asking.

        Counted per client rather than per peer id, so a client that does not
        understand the refusal and spins on it slows itself down without making
        a real second device wait for its button.
        """
        who = (uid, incoming or (raddr[0] if raddr else "?"))
        streak = self._refusal_streak.get(who, 0) + 1
        self._refusal_streak[who] = streak
        self._note_refusal(uid, raddr, incoming)
        delay = min(REFUSAL_DELAY_MAX, REFUSAL_DELAY_STEP * streak)
        try:
            await asyncio.sleep(delay)
            await ws.close(code=CLOSE_SESSION_IN_USE, reason="session in use")
        except Exception:
            pass

    def _evict(self, entry, code, reason):
        """Close a displaced socket without waiting for it.

        Awaiting this costs the close handshake timeout twice when the peer is
        a sleeping laptop -- twenty seconds, in exactly the situation the
        feature exists for. The socket is already out of self.peers, so nothing
        depends on the close having finished.
        """
        task = asyncio.ensure_future(entry[0].close(code=code, reason=reason))
        self._evictions.add(task)

        def _done(finished, addr=entry[1]):
            self._evictions.discard(finished)
            # Retrieve the exception even though there is nothing to do with
            # it. Left unread, asyncio reports it at collection time as an
            # unhandled error -- log noise from the change written to remove
            # log noise. A socket we are throwing away failing to close is not
            # interesting; that it happened at all is, once.
            if not finished.cancelled() and finished.exception() is not None:
                logger.debug("displaced socket for %r did not close cleanly: %s",
                             addr, finished.exception())

        task.add_done_callback(_done)

    # -- overrides -------------------------------------------------------

    async def hello_peer(self, ws):
        """Register a peer, handing the session over when asked to.

        Returns (None, None) for a refusal. Upstream's connection handler
        unpacks the pair and passes it on; both overrides below recognise the
        sentinel and stop. That keeps a refusal from raising out through the
        websockets handler, which is what turned one stuck client into 17858
        tracebacks.
        """
        raddr = ws.remote_address

        # Everything from here to the end of the parse is hostile input, the
        # receive included -- and that is the case a browser reaches most
        # often: a tab closed while connecting, a connection reset, or a frame
        # larger than the server will accept all raise here. An earlier version
        # of this guard began one line too late and let all three through.
        #
        # A connection we turn away must not raise out through the websockets
        # handler. That is what logged a traceback per attempt and let one
        # stuck client write 17858 of them in two days: the client sees the
        # resulting close as an ordinary failure and comes straight back.
        # Upstream raises for a malformed HELLO and unpacks the token list
        # without checking its length, so a one-word HELLO, a truncated base64
        # blob, or a payload that is not JSON each end the same way. Refusing
        # all of them as we refuse a duplicate closes the loop for every input,
        # not only the one we set out to fix.
        try:
            hello = await ws.recv()
            toks = hello.split(maxsplit=2)
            metab64str = None
            if len(toks) > 2:
                hello, uid, metab64str = toks
            elif len(toks) == 2:
                hello, uid = toks
            else:
                raise ValueError("HELLO needs a peer id")
            if hello != "HELLO":
                raise ValueError("not a HELLO")
            if not uid or uid.split() != [uid]:
                raise ValueError("peer id may not contain whitespace")
            meta = None
            if metab64str:
                meta = json.loads(base64.b64decode(metab64str))
                # A client that sends metadata must send an object. JSON null
                # decodes to None, which is indistinguishable from having sent
                # no metadata at all -- and "sent no metadata" is precisely how
                # the desktop's own peers are recognised below, the peers that
                # may never be handed over. Without this, one line of input
                # claims a peer id that no take-over can then reclaim, and the
                # session is wedged for good.
                if not isinstance(meta, dict):
                    raise ValueError("metadata is not an object")
        except Exception as exc:
            logger.info("Malformed HELLO from %r: %s", raddr, exc)
            try:
                await ws.close(code=1002, reason="invalid protocol")
            except Exception:
                pass
            return (None, None)

        incoming = self._identity(meta)
        takeover = self._wants_takeover(meta)

        # Taking over is a deliberate act from a client that can identify
        # itself. A client with no identity cannot be given the session: it
        # would have no way to reclaim its own connection afterwards, and the
        # only clients without one are those that do not understand hand-over
        # and so never offered the button in the first place.
        if takeover and (incoming is None or uid not in CLIENT_PEER_IDS):
            takeover = False

        if not takeover and uid in CLIENT_PEER_IDS \
                and self._other_leg_held_elsewhere(uid, incoming):
            await self._refuse(ws, uid, raddr, incoming)
            return (None, None)

        displaced = None
        if uid in self.peers:
            held_entry = self.peers[uid]
            held_meta = held_entry[3]
            held = self._identity(held_meta)

            if incoming is not None and incoming == held:
                # Our own earlier connection, still registered because the
                # server has not noticed it died. This is the case that must not
                # be mistaken for a second device: it is an ordinary reconnect.
                displaced, code, reason = held_entry, CLOSE_SUPERSEDED, "superseded"
                logger.info("Peer %r reconnecting as the same client", uid)
            elif takeover and held_meta is not None \
                    and (time.monotonic()
                         - self._last_takeover.get((uid, incoming),
                                                   float("-inf"))
                         > TAKEOVER_MIN_INTERVAL):
                # held_meta is None only for the peers the desktop's own app
                # registers (it says a bare HELLO). Those are not a device
                # anyone is sitting at, and letting a client evict them would
                # kick the desktop off its own signalling.
                displaced, code, reason = held_entry, CLOSE_TAKEN_OVER, "taken over"
                logger.info("Peer %r taken over by %r", uid, raddr)
            else:
                await self._refuse(ws, uid, raddr, incoming)
                return (None, None)

        # Claim the slot before yielding anywhere. Upstream registers the peer
        # only after hello_peer returns, leaving several await points between
        # deciding the id is free and taking it -- long enough for two clients
        # to both be told HELLO, after which the loser can still read the
        # winner's routing state and inject into its session.
        self.peers[uid] = [ws, raddr, None, meta]
        self._owner_task[uid] = asyncio.current_task()

        if displaced is not None:
            if code == CLOSE_TAKEN_OVER:
                now = time.monotonic()
                # Identities are minted per page load, so without pruning this
                # gains an entry for every hand-over for the life of the
                # session -- weeks. Anything older than the interval can no
                # longer affect a decision.
                for key, when in list(self._last_takeover.items()):
                    if now - when > TAKEOVER_MIN_INTERVAL:
                        del self._last_takeover[key]
                self._last_takeover[(uid, incoming)] = now
            await self.cleanup_session(uid)
            # cleanup_session may have removed the entry we just claimed --
            # but only restore it if nobody has taken the slot in the meantime.
            # Restoring unconditionally is how two concurrent hand-overs both
            # ended up believing they had won.
            if self._owner_task.get(uid) is asyncio.current_task():
                self.peers[uid] = [ws, raddr, None, meta]
            self._evict(displaced, code, reason)

        if self._owner_task.get(uid) is not asyncio.current_task():
            # Superseded while we were tidying up. We are the loser of that
            # race, and the winner is already registered.
            await ws.close(code=CLOSE_TAKEN_OVER, reason="taken over")
            return (None, None)

        self._refusal_streak.pop((uid, incoming or "?"), None)

        try:
            await ws.send("HELLO")
        except Exception:
            # The client vanished mid-handshake; do not leave the slot claimed.
            if self._owner_task.get(uid) is asyncio.current_task():
                self.peers.pop(uid, None)
                self._owner_task.pop(uid, None)
            raise
        return uid, meta

    async def connection_handler(self, ws, uid, meta=None):
        if uid is None:
            return                      # refused in hello_peer; nothing to run
        # hello_peer already claimed the slot, so re-registering here would
        # overwrite a newer owner if one arrived in between.
        if self._owner_task.get(uid) is not asyncio.current_task():
            return
        return await super().connection_handler(ws, uid, meta)

    async def remove_peer(self, uid):
        if uid is None:
            return
        owner = self._owner_task.get(uid)
        if owner is not None and owner is not asyncio.current_task():
            # A displaced connection unwinding. The id belongs to whoever took
            # it; deleting it here would throw out the client that just
            # arrived.
            logger.info("Not removing peer %r: superseded by a newer connection", uid)
            return
        self._owner_task.pop(uid, None)
        return await super().remove_peer(uid)


def make_server_class(base):
    """Build the hand-over server on top of whichever class was handed to us."""
    return type("HDW4SServer", (HandoverMixin, base), {})


def install_into(module):
    """Replace the name `module` will construct, if we are still needed.

    Rebinding one module attribute is the whole of our footprint. Nothing on
    disk changes, so there is no backup to keep, nothing for a package upgrade
    to silently revert, and undoing it is simply not calling this.
    """
    base = getattr(module, "WebRTCSimpleServer", None)
    if base is None:
        logger.error("%s has no WebRTCSimpleServer to extend; hand-over DISABLED",
                     getattr(module, "__name__", module))
        return "missing"
    if not client_supports_handover():
        logger.warning(
            "the browser client in %s does not support session hand-over, so "
            "the server will not offer it. This is the right way round: a "
            "client that cannot ask would reconnect into the refusal forever. "
            "A second device sees the old behaviour until the client is "
            "updated.", WEBROOT)
        return "client-cannot-ask"
    state = upstream_state(base)
    if state == "upstream-has-it":
        logger.info("upstream provides session hand-over; using it unchanged")
        return state
    if state == "drifted":
        logger.error(
            "the signalling server has changed and does not announce session "
            "hand-over, so it is running unmodified. Hand-over is DISABLED, "
            "and the behaviour it replaced comes back with it: a second client "
            "is refused in a way it cannot recognise, so it reconnects several "
            "times a second and each attempt logs a traceback. Re-check the "
            "overrides against the installed version.")
        return state
    module.WebRTCSimpleServer = make_server_class(base)
    logger.info("session hand-over enabled")
    return state


def install():
    """Install into the application, which is the only place that matters."""
    from selkies_gstreamer import __main__ as selkies_main
    return install_into(selkies_main)


def main():
    install()
    from selkies_gstreamer import __main__ as selkies_main
    return selkies_main.main()


if __name__ == "__main__":
    sys.exit(main() or 0)
