# Security

## Reporting a vulnerability

Report privately through GitHub's ["Report a vulnerability"][advisory] button
on the Security tab. Please do not open a public issue for something
exploitable.

Expect an acknowledgement within a week. This is a small project maintained in
spare time; there is no embargo policy and no bounty.

[advisory]: https://github.com/gutschke/hdw4s/security/advisories/new

## What this program assumes

Four things are true by design rather than by oversight. A report that one of
them is the case is not a vulnerability; a report that one of them can be
subverted is.

**The session authenticates nobody.** Anything that completes a connection to a
session's port gets a full desktop as that account, with no login screen. That
is the point -- the desktop is meant to appear when the page loads -- and it is
why the port must never be reachable by anything untrusted.

**The reverse proxy is the security boundary.** It terminates TLS and decides
who may reach a session, and it is the only thing in the design that identifies
a user. `hdw4s auth` adds a credential the proxy presents on every request, so
that reaching the port is not by itself enough; the user never sees it, and it
is not a substitute for authenticating people at the proxy.

**The firewall restricts, it does not grant.** `HDW4S_PROXIES` narrows who may
reach a session to a set of addresses. An address is a weak thing to rely on by
itself: it can be spoofed unless the network prevents it, and on a shared
network anything on that network can present it. Treat it as a second lock,
never the first. The nftables rules also close the ephemeral range a WebRTC
media path would scatter sockets across -- which, since dual mode is locked
off, is now a second line rather than the first. See the note on the media
chain below for how, and for what it does and does not cover.

**The updater installs an unsigned upstream package as root.** `hdw4s-update`
fetches the streaming server's `.deb` from its upstream GitHub releases over TLS
and installs it with `dpkg`. What is downloaded is checked against a sha256 --
the one recorded in `hdw4s-update` for the release and platform the maintainer
tested, otherwise the digest GitHub publishes for that asset -- and the download
is refused outright if neither is available, so no install happens with nothing
checked. That pins the bytes to what somebody saw; it is not a signature, and it
says nothing about whether upstream's release was honest when it was made.
Upstream publishes no signatures. So whoever can serve those URLs *and* choose
what the release contains gets root on every machine running the updater. Pin a
version, or turn the timer off, if that trade is not acceptable.

## Known weaknesses not yet fixed

The streaming server logs its **parsed configuration** at startup, including
the values it took from the environment, and that includes the credential
`hdw4s auth` generated. This is worth stating precisely: the credential is
deliberately passed in the environment rather than on a command line, so that
it does not appear in `/proc`, and it is the logging that undoes that -- not
anything about how it is passed.

Anything that can read the journal for a session's unit can therefore read that
session's proxy credential. The journal is not world-readable, but on Debian and
Ubuntu its access list includes `adm` as well as `systemd-journal`, which is
usually a wider set than expected. Two further consequences: the credential
stays in the journal for its retention period, so `hdw4s auth` does not retract
one that has already been logged; and rotating a credential does not shorten
that window.

The nftables `media` chain closes the sockets a WebRTC media path would open.
Under 2.0 there are none to close: the session serves one WebSocket, dual mode
is locked off so the WebRTC stack never starts, and the streaming server's
process owns one TCP listener on loopback and no UDP socket at all -- checked,
not assumed. The chain stays because what it constrains is broader than that
one program, as the rest of this note explains, and because a future release
that reached for a media path should find the door already shut.

Where the kernel allows it, it matches the cgroup that owns each
socket, which means it constrains sockets **by what created them, not by which
port they use**. Where it does not -- an older kernel, older nftables, or a
container below kernel 6.11, where matching a cgroup by level silently never
matches -- it falls back to dropping new inbound connections to the ephemeral
port range instead, and says so when it applies the rules. The two have
opposite blind spots, so which one is in force matters: `hdw4s firewall
--check` reports it. Two consequences
follow. A session cannot escape it by choosing a different port. But equally, it
constrains nothing the account creates by another route — a cron job, an `at`
job, an ssh login — because those are outside the session's slice. Anything that
opens a listener there and forwards to the session's loopback port exposes a
desktop that authenticates nobody. The chain is a limit on the streaming server,
not on the account. Under the port-range fallback both of those invert: a
session escapes by binding outside the range, and an unrelated program of the
same account inside it is caught.

The cgroup form has a narrow timing window that the port-range form does not.
It drops a packet only when a socket in the slice already exists to match, so a
packet arriving before the streaming server binds that port finds no socket and
is recorded by conntrack instead. That recorded flow only becomes `established`
-- and so only passes above the drop -- if something later answers on that port,
which for a candidate socket means answering with credentials from the
authenticated signalling channel. So this is a narrowing of the guarantee rather
than a way in, and provoking it means spraying a large port range noisily. It is
stated because the guarantee is narrower than "the candidate sockets are
closed", not because it is known to be reachable.

## Reports that are in scope

Anything that lets one account reach another account's session or display;
anything that lets a session escape the restrictions its unit places on it;
anything that makes a session reachable that the firewall was configured to
exclude; and anything in the packaging that runs attacker-controlled input as
root.

## Supported versions

The most recent release. This project does not backport fixes.
