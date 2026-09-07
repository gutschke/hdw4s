# hdw4s

**hdw4s** gives an existing account on an existing machine a full GNOME desktop
that is reachable from a web browser.

It is not a container image and it does not want to be. Containers are a fine
way to run a disposable desktop, but they are the wrong shape entirely when the
desktop you want is the one belonging to a machine and an account that already
exist -- with that machine's files, that account's home directory, and the
software already installed there. hdw4s streams that desktop instead of
building a new one.

The streaming itself is done by
[Selkies](https://github.com/selkies-project/selkies), which is not this
project's work. hdw4s is the part that makes it a thing you can install:
session lifecycle, display and port allocation, a firewall table, and a way to
share a home directory with another desktop without the two corrupting each
other's settings.

## Core concepts

### 1. One session, one systemd unit

A session is `hdw4s@<user>.service`. It runs, as that user, an X server on the
`dummy` driver, a GNOME session, and the streaming server. No graphics card is
involved and no virtual terminal is claimed, which is what lets an ordinary
account start a desktop from a service that has no seat and no login.

Systemd owns the cleanup. The runtime directory and the session's private `/tmp`
go away when the unit stops, however it stops, so there are no stale locks or
sockets to sweep up afterwards.

### 2. Ports are allocated; displays are not

Each session gets a slot, recorded once and never moved, that fixes its TCP
port. A reverse proxy and a firewall can both be configured against that and
stay valid as accounts come and go.

The X display number is left to the X server, which claims the first free one
without a race and reports back when it is ready to serve. Nothing outside the
machine ever sees it, so it does not need to be predictable.

### 3. A shared home directory does not have to mean a shared desktop

A GNOME session assumes it owns its home directory. When the same home is
mounted on several machines, or another desktop is already logged in against
it, two sessions end up writing the same settings database, keyring and
metadata stores -- none of which are safe to share, and several of which use
memory-mapped or journalled files that do not work over NFS at all.

`HDW4S_ISOLATION=profile` keeps the shared home for the user's *files* and moves
the session's settings, state and cache to local disk. Documents, Desktop and
Downloads still point at the real shared directories. Desktop appearance, saved
passwords and the browser profile become per-session.

That trade is not tunable: those components conflict *because* they are shared,
so the only way to stop the conflict is to stop sharing them.

## Features

* **Works with the accounts you have.** No new users, no container images, no
  separate home directory. Point it at a username and that user gets a desktop.
* **Seamless in the browser.** No login screen and no connect dialog -- the
  proxy in front has already identified the user. The desktop follows the
  browser window, and audio comes with it.
* **Ordinary reverse proxying.** One TCP port per session, plain HTTP and
  WebSocket, no UDP and no second channel. The proxy can live on another
  machine.
* **Coexists with a desktop that is already running**, on this machine or on
  another one sharing the same home directory over the network.
* **Firewalled by construction.** The package owns one nftables table covering
  the whole port block, written once, so a rule cannot fall behind which
  sessions happen to be running.
* **Updates itself carefully.** A daily timer follows upstream, verifies what it
  downloaded before replacing anything, checks that sessions came back, and
  rolls back if they did not. It refuses outright to install a release whose
  layout it does not recognise.

## Installation

Either install the package:

```bash
sudo apt install ./hdw4s_1.0_all.deb
```

or install from a checkout:

```bash
git clone https://github.com/gutschke/hdw4s
cd hdw4s
sudo ./install.sh
```

## Configuration

Before starting anything, say which reverse proxy is allowed to reach these
desktops:

```bash
sudo editor /etc/hdw4s/hdw4s.conf     # set HDW4S_PROXIES
sudo hdw4s firewall --apply
```

Then give an account a desktop and see what it was assigned:

```bash
sudo hdw4s enable alice
sudo hdw4s list
```

```
INSTANCE             USER       PORT   STATE      LISTENING DISPLAY
alice                alice      7300   active     yes       3
```

Point the proxy at that port. To share a home directory with another desktop,
add to `/etc/hdw4s/alice.conf`:

```ini
HDW4S_ISOLATION=profile
```

That session then has its own keyring rather than sharing the account's. Give
it one that unlocks without a prompt:

```bash
sudo hdw4s keyring alice
sudo systemctl restart hdw4s@alice
```

## Security

**A session performs no authentication of its own.** That is deliberate -- it
exists to sit behind a proxy that has already identified the user, so that
reaching the desktop takes no second login. It also means anything that can open
a connection to a session port gets that user's desktop.

So `HDW4S_PROXIES` is not a convenience setting. It is the only thing between a
session and everything that can route to the machine. Terminate TLS at the
proxy, authenticate there, and do not expose a session port by any other route.

Note that the package's firewall table can reliably *close* the port block but
cannot guarantee it is *open*: an nftables drop overrides another table's
accept, but not the reverse. If something else filters this machine, the proxy
may also need a rule there.

Run `hdw4s firewall --check` to confirm every session is actually covered.

## Requirements

Ubuntu 24.04 or a Debian of comparable vintage, GNOME, and no graphics card
required.

Running a second desktop for an account **on the same machine** relies on
gnome-session falling back to its own service manager, which GNOME 49 removes
and GNOME 50 replaces with a hard refusal; GNOME 50 also drops the X11 session
that the current Selkies release needs. Sessions on *different* machines sharing
one home directory are unaffected, because those checks are local to a machine.

## Documentation

`man hdw4s`, mirrored as [hdw4s.8.md](hdw4s.8.md).

## Uninstalling

```bash
sudo apt remove hdw4s          # or, from a checkout install:
sudo /usr/local/lib/hdw4s/uninstall.sh
```

Session profiles under `/var/lib/hdw4s` are left behind on purpose. Remove them
by hand if those desktops are not wanted again.
