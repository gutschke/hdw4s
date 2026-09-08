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
never the first. The nftables rules also drop new inbound connections to the
ephemeral range, where the streaming server scatters its media sockets across
every address the machine has.

**The updater installs an unsigned upstream wheel as root.** `hdw4s-update`
fetches the streaming server from its upstream GitHub releases over TLS and
installs it into a system-wide virtual environment. There is no signature and no
recorded hash to verify, so whoever can serve those URLs gets root on every
machine running the updater -- a Python wheel can ship a `.pth` file that runs
on every interpreter start. Pin a version, or turn the timer off, if
that trade is not acceptable.

## Reports that are in scope

Anything that lets one account reach another account's session or display;
anything that lets a session escape the restrictions its unit places on it;
anything that makes a session reachable that the firewall was configured to
exclude; and anything in the packaging that runs attacker-controlled input as
root.

## Supported versions

The most recent release. This project does not backport fixes.
