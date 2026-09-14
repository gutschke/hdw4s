hdw4s(8) -- headless GNOME desktop streamed to a web browser
============================================================

## SYNOPSIS

`hdw4s` `list`<br>
`hdw4s` `show` <instance><br>
`hdw4s` `enable` <instance><br>
`hdw4s` `disable` <instance><br>
`hdw4s` `release` <instance><br>
`hdw4s` `transport` <instance> `tcp`|`unix`<br>
`hdw4s` `auth` <instance><br>
`hdw4s` `noauth` <instance><br>
`hdw4s` `proxy` <instance><br>
`hdw4s` `set` [<instance>] <KEY>=<VALUE>...<br>
`hdw4s` `unset` [<instance>] <KEY><br>
`hdw4s` `seed` <instance> [`--only` <path>]...<br>
`hdw4s` `keyring` <instance><br>
`hdw4s` `reap`<br>
`hdw4s` `firewall` `--apply`|`--check`|`--print`|`--restore`<br>
`hdw4s` `--version`

## DESCRIPTION

**hdw4s** gives an existing account on an existing machine a full GNOME desktop
that is reachable from a web browser. It needs no graphics card and no
container: the point is to reach the machine and the account that are already
there.

Each session is a systemd unit that runs, as that user, an X server on the
`dummy` driver, a GNOME session, and the Selkies streaming server. The X server
never touches a virtual terminal, a DRM device or an input device, which is what
lets an ordinary account start one from a service with no seat and no login.

Sessions are expected to sit behind a reverse proxy that terminates TLS and
identifies the user. The streaming server itself runs with authentication
switched off, so that a user who is already known to the proxy lands on their
desktop without a second login. See **REVERSE PROXY AND SECURITY**.

## COMMANDS

  * `list`:
    Print every configured session with its user, port, whether it has a
    credential of its own, whether it keeps its settings apart from the home
    directory, its transport, its unit state and its current display.

  * `show` <instance>:
    Print one session's settings and, for each of them, which file it came from.

  * `enable` <instance>:
    Allocate a slot for a session and open its front door. The desktop is not
    started here and is not started at boot: the socket listens, and the first
    connection to arrive starts the session behind it. Safe to re-run.

  * `disable` <instance>:
    Stop a session and close its front door, so nothing starts it again. The
    slot stays reserved, so the port does not change if it is enabled later.

  * `noauth` <instance>:
    Remove the credential `auth` added, and explain when running without one is
    a reasonable choice. Editing the file by hand is the same decision made
    quietly; this is the supported way to make it.

  * `reap` :
    Stop sessions nobody has connected to for `HDW4S_IDLE_DAYS`. Run from a
    timer; there is no need to invoke it by hand.

  * `release` <instance>:
    Stop a session and give up its slot, so another session may take the port.
    The session's profile directory is left in place.

  * `transport` <instance> `tcp`|`unix`:
    Choose how the reverse proxy reaches this session. See **TRANSPORTS**.

  * `auth` <instance>:
    Require the proxy to present a secret as well as an acceptable address.
    Generated here, sealed to this machine, and never shown to the user, so
    there is still no login screen.

  * `proxy` <instance>:
    Print an nginx configuration for this session, matching whichever
    transport and authentication it is set up for.

  * `set` [<instance>] <KEY>=<VALUE>...:
    Change a setting without opening an editor. With an instance, writes to
    that session's file; without one, to the defaults. The edit is deliberately
    conservative: an existing assignment is changed where it stands, keeping
    its indentation and any note written after it on the same line; otherwise
    the documented default is uncommented in place, so the explanation above it
    still applies; otherwise the setting is appended. Nothing else in the file
    is touched, and anything not offered here can still be edited by hand.

  * `unset` [<instance>] <KEY>:
    Comment a setting out so the default applies again. The line is commented
    rather than deleted, so the value that was there stays visible.

  * `seed` <instance> [`--only` <path>]...:
    Copy an account's existing desktop settings from its home directory into an
    isolated session's profile, once. Only ever in that direction, only when
    asked, and only into a profile that is still empty -- a profile with
    anything in it is one somebody has used, and there is no way to tell which
    of two copies of a setting is the newer. Re-running is refused rather than
    overwriting; remove the profile first if starting over is really meant.

    This is a snapshot and not a link. The two diverge from that moment on.

    `--only` limits the copy to the named paths, relative to the home
    directory, and may be given more than once. An account that has been in
    use for years accumulates settings for programs that will never run in
    this session; copying all of it forward only carries the accumulation
    into a second place. Naming what matters -- the settings database, the
    browser profile, the handful of applications actually used -- is usually
    a great deal less than what is there. Paths that do not exist are
    reported and skipped, and the exclusions above still apply inside the
    paths that do.

        hdw4s seed alice --only .config/dconf --only .config/google-chrome

    Caches are skipped, including the ones browsers keep inside their profile
    directories rather than under `~/.cache`; they are regenerable and are
    usually almost all of the size. So are downloaded models and component
    data: a current Chrome fetches an on-device language model of nearly three
    gigabytes, per profile, which dwarfs everything worth carrying across. Saved passwords are skipped too, since the
    session has its own keyring with its own password.

    The session must be stopped, or the copy captures half-written state.

  * `keyring` <instance>:
    Give a session its own keyring with a generated password, sealed to this
    machine with systemd-creds and handed to the session at start time, so it
    is unlocked without anyone typing anything. The session's keyring is
    separate from the account's login keyring: passwords saved in one are not
    visible in the other. Requires root and a restart of the session.

  * `firewall --apply`:
    Rewrite the package's nftables table and the kernel's reserved-port list
    from the current configuration. Run this after changing `HDW4S_PROXIES`,
    `HDW4S_BASE_PORT` or `HDW4S_BLOCK_SIZE`.

  * `firewall --check`:
    Report whether the table is loaded and whether every session listens on a
    port the table actually covers. Exits non-zero if not.

  * `firewall --restore`:
    Put the table back if it has gone missing, and do nothing if it has not.
    Run periodically by `hdw4s-firewall.timer`; see **REVERSE PROXY AND
    SECURITY**.

  * `firewall --print`:
    Write the ruleset to standard output without loading it.

## INSTANCES

An instance is a user name. An account has one desktop:

    hdw4s enable alice

Versions up to 1.1 also accepted `alice:2`, a second concurrent desktop for the
same account on the same machine. That form is no longer created.

It was withdrawn because it was not worth what it cost to reason about, not
because it stopped working. A second desktop doubled the states every part of
the package had to account for -- two instances against one home directory, one
keyring, one set of application single-instance locks -- to deliver something
that can be had instead by giving the account a desktop on a second machine,
which is a case this package already supports properly.

**An instance created by an earlier version keeps working**, and keeps its slot
and its port. `hdw4s list` reports it with the state `legacy`. No command will
accept the name except `hdw4s release`, which stops the session first, so
retiring one takes a single command:

    hdw4s release alice:2

An account wanting desktops on *several machines* at once is a different thing
and is supported; see `HDW4S_ISOLATION`.

## CONFIGURATION

Two files are read in order, the second overriding the first:

    /etc/hdw4s/hdw4s.conf         defaults for every session
    /etc/hdw4s/<instance>.conf    settings for one session

`hdw4s show` <instance> prints the settings that apply to one session.

Most settings work per session for free, because a session reads the shared file
and then its own. Six do not, and `hdw4s set` refuses to write them to a
session's file rather than accepting something that would have no effect:
`HDW4S_PROXIES`, `HDW4S_BASE_PORT`, `HDW4S_BLOCK_SIZE` and `HDW4S_MEDIA_PORTS`
are read when the firewall is applied, which happens once for the machine;
`HDW4S_ALLOW_SYSTEM_USER` is read before a session exists; and `SELKIES_VERSION`
belongs to the copy of the streaming server, of which there is one.

  * `HDW4S_PROXIES`:
    Addresses allowed to reach a session, separated by spaces; IPv4 and IPv6
    addresses and prefixes are both accepted. Empty means this machine only.

  * `HDW4S_ISOLATION`:
    `none` or `profile`. See **SHARED HOME DIRECTORIES**. Defaults to `none`.

  * `HDW4S_PROFILE_DIR`:
    Where an isolated session keeps its private profile. Defaults to
    `/var/lib/hdw4s`.

  * `HDW4S_BASE_PORT`, `HDW4S_BLOCK_SIZE`:
    The block of TCP ports sessions are allocated from. Defaults to 7300 and
    64. Two consecutive blocks are actually reserved: the first is what the
    reverse proxy connects to, and the second, immediately above it, is where
    each session's streaming server listens on loopback behind its relay. So
    the defaults reserve 7300-7427, and only 7300-7363 are ever reachable from
    off the machine.

  * `HDW4S_ADDR`:
    The address the streaming server binds. Defaults to `127.0.0.1`. Leave it
    alone unless you know why you are changing it: the socket unit in front is
    the only way in, and the firewall decides who may reach that. Binding
    anything wider publishes the streaming server directly, at a port in the
    second block, which the firewall does not cover and nothing authenticates.

  * `HDW4S_ALLOW_SYSTEM_USER`:
    Set to `yes` to permit a session for an account below UID 1000.

  * `HDW4S_TRANSPORT`:
    `tcp` or `unix`. Set with `hdw4s transport`, which also arranges the units
    that go with it, rather than by hand.

  * `HDW4S_PROXY_GROUP`:
    The group allowed to open a session's Unix socket, i.e. the group the
    reverse proxy runs as. Defaults to `www-data`.

  * `HDW4S_AUTH`:
    `none` or `basic`. Set with `hdw4s auth`, which also generates the secret.
    `hdw4s enable` turns it on for a session it creates, because the firewall
    filters what arrives from other machines and nothing stands between the
    session and the other accounts on this one: the streaming server listens on
    loopback, and any local account can open a loopback port. The reverse proxy
    presents the secret and the user never sees it, so there is no login
    screen either way. Re-running `hdw4s enable` on a session that already
    exists leaves the setting alone. Set `none` to turn it off.

  * `HDW4S_SESSION`:
    The desktop to start; defaults to `gnome-session`. Anything that runs on
    X11 works, and nothing else in a session depends on the choice. GNOME 50,
    which Ubuntu 26.04 ships, removes the X11 session that the current Selkies
    release needs, whereas Xorg and the lighter desktops have no such plan, so
    changing this is the whole migration when that matters.

  * `HDW4S_IDLE_DAYS`:
    How long a session may go with nobody connected before `reap` stops it.
    Defaults to 7. Measured by connections rather than by typing, so work left
    running is not mistaken for an idle desktop. Connections are looked for
    every few minutes rather than once a day, because a desktop used only
    during working hours has nobody connected to it at any moment a nightly
    check would happen to look. Set it to 0 to never reap.

  * `HDW4S_MEDIA_PORTS`:
    Either `proxied`, the default, or `direct`. The streaming server scatters
    connection candidates across the ephemeral port range on every address the
    machine has. `proxied` drops new inbound connections to that range, which
    closes them; `direct` leaves them reachable, which is needed only when a
    browser reaches the streaming server without a proxy in between.

  * `HDW4S_RESIZE`:
    Whether the desktop follows the size of the browser window. Defaults to
    true.

  * `HDW4S_LANG`:
    The locale the session runs in. Unset, the machine's own `LANG` from
    `/etc/default/locale` is used, and `C.UTF-8` only if that is absent. It has
    to be a UTF-8 locale: some terminals refuse to start otherwise.

  * `HDW4S_FRAMERATE`, `HDW4S_ENCODER`:
    Passed through to the streaming server. Leave them alone unless the picture
    is visibly wrong; the defaults suit a machine with no graphics card.

  * `HDW4S_DPI`:
    Whether the desktop's display density follows the browser's, which is what
    makes text the right size on a HiDPI screen or in a zoomed window. Defaults
    to `follow`. Set a number to pin it, which makes the server refuse the
    density a client asks for and so stops it rewriting `~/.Xresources` and
    `~/.xsettingsd` again and again; see SHARED HOME DIRECTORIES. A pinned
    number other than 96 is still applied once when the session starts, so
    both files are written that once. Pinning 96 writes neither, ever.

  * `HDW4S_INDEXING`:
    Whether the desktop's file indexer runs. Defaults to `off`, and takes
    effect only with `HDW4S_ISOLATION=profile`; without that the indexer is the
    account's rather than the session's and is left alone, with a warning. See
    SHARED HOME DIRECTORIES for why, and for what turning it off costs.

  * `HDW4S_THUMBNAILS`:
    Whether the file manager draws image thumbnails. Defaults to `off`, and
    like `HDW4S_INDEXING` takes effect only with `HDW4S_ISOLATION=profile`. The
    file manager's own `local-only` setting does not protect a network home,
    because the kernel calls NFS native; see SHARED HOME DIRECTORIES.

  * `HDW4S_HIDPI`:
    How a high-density client is handled: `scale` (the default) asks for the
    size of the browser window and lets the browser stretch the result, which
    is correct size and slightly soft; `native` asks for the client's full
    device resolution, which is pixel-exact and, on GNOME, half size. See
    SHARED HOME DIRECTORIES for why the desktop does not scale itself.

  * `SELKIES_VERSION`:
    Pin a Selkies release and stop following upstream.

## RUNNING SOMETHING AS ROOT

`sudo` works the way it does everywhere else. `sudoers` and PAM decide who may
use it, a password is asked for and a wrong one is refused, and this package
adds no rule, wrapper or exception of its own.

It did not always, and the reason is worth keeping because it looked
deliberate. Until 1.2 the session unit's capability bounding set held
`CAP_NET_RAW` and nothing else. A setuid-root program without `CAP_SETGID`
cannot change group, so `sudo` failed at `unable to change to root gid` --
before `sudoers` was consulted, before anyone was asked for a password, and
with nothing said about why. An administrator's own desktop refused them root
while `sudoers` said they could have it.

That read as a security control and was not one. A setuid-root program reaches
uid 0 whatever the bounding set says, because the kernel grants the uid at
`execve`; and a process with uid 0 owns every root-owned file through the
ordinary permission bits, needing no capability to do it. Run under exactly
that bounding set, a setuid-root test binary reported:

    euid=0  caps=cap_net_raw=ep
    /etc/shadow                       r : OK
    /etc/sudoers                      r : OK
    /root/canary                      w : OK
    /etc/systemd/system/probe.service w : OK

The missing capability stopped the *group* change, which only programs on the
legitimate path -- `sudo`, `su`, `login` -- ever ask for. It could not deny
root to anybody `sudoers` denies it to. It could only deny it to the
administrators `sudoers` allows.

What does constrain a root process inside a session is the unit's sandbox, not
its capabilities. `ProtectSystem=strict` makes the file system read-only apart
from the session's own directories, so the writes above fail there; devices are
hidden and kernel tunables are not writable. `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`
and `CAP_NET_ADMIN` are still out of the bounding set, so mounting, loading a
module and reconfiguring the network stay impossible for uid 0 in a session.

    sudo systemd-run --pty --collect --uid=0 -- bash

is the way out to a root shell without those restrictions. systemd does not
consult polkit for a caller that is already root, and the shell it starts is a
transient unit outside the session's control group -- which also means it is
named in the journal, rather than being an unremarked setuid transition.

**A desktop whose account can `sudo` is a desktop whose compromise is root.**
That is true of any Linux machine. What is particular here is that the desktop
is reachable through a reverse proxy, so more people are in a position to try.
If an account should not administer the machine from a browser, say so in
`sudoers`: that is where an administrator looks for the answer, and it is the
only place that decides it.

## SHARED HOME DIRECTORIES

A GNOME session assumes it is the only one using its home directory. That
assumption breaks when the same home is mounted on more than one machine and a
desktop runs against it on each -- the case this section exists for, and the
one way an account gets more than one desktop. Those sessions then write
the same settings database, the same keyring and the same metadata stores. None
of those are safe to share, and the settings database and the metadata stores
use memory-mapped and journalled files that are documented not to work over NFS
at all.

Setting `HDW4S_ISOLATION=profile` keeps the shared home for the user's files but
moves most of the session's settings, state and cache to a private directory on
local disk -- most, because the streaming server writes three paths it builds
from the home directory itself, which no XDG variable reaches. Concretely, the session gets its own `XDG_DATA_HOME`, `XDG_STATE_HOME`,
`XDG_CACHE_HOME` and dconf profile, its own X authority cookie, its own audio
server socket, and wrappers that give Firefox and Thunderbird their own
profiles.

All four XDG base directories move together: config, data, state and cache.
Leaving the config home shared and redirecting dconf on its own was tried and
abandoned, because it needs a service that has to answer before any setting can
be read, and it leaves a lock beside its database that a killed session does not
clean up. What this does not cover is a path a program builds from
the home directory rather than from these variables. Some input-method
configuration hardcodes `~/.config` that way, and so does the streaming
server.

What stays shared:

    Documents, Desktop, Downloads, Pictures, Music, Videos
    everything else in the home directory, including ~/.ssh

That last line covers files the software writes as well as the user's own, and
three of them come from the streaming server rather than from the desktop:

    ~/.Xresources   written when a client reports its display density.
                    The user's own lines survive; their Xft.dpi is replaced.
    ~/.xsettingsd   written on the same trigger, and rewritten whole, so
                    anything already in it is lost. Nothing on a GNOME
                    system reads it, and the daemon that would is not part
                    of this package.
    ~/Desktop       would be created at startup as the destination for file
                    transfers, which this package does not enable. Pointed
                    at the session's runtime directory instead, so it is
                    not created here at all.

A high-density client is a related trap. The desktop does not scale itself:
GNOME works its scale out from the monitor's physical size, a virtual monitor
reports none, and GNOME therefore stops at 1. Asking the streaming server for a
higher DPI does not help either, because on GNOME that reaches only the X
resource database, which the settings daemon owns. So a client on a 2x screen
asking for its full device resolution gets a desktop at half size. `HDW4S_HIDPI`
defaults to `scale` for that reason.

The indexer is a separate matter, and is off by default -- see
`HDW4S_INDEXING`. On a home shared between machines it is work without an
answer: every machine crawls the same tree over the network, each keeps its own
copy of the result on local disk, and none of them sees a change made from
another machine, because the only change notification it has is inotify and
inotify does not cross NFS. It is not removed and not masked: the package is a
hard dependency of the file manager, and masking it would reach the account's
real login session on the same machine. The session sets the keys that
Settings -> Search -> Search Locations writes, so a user can turn it back on for
their own session where they would think to look. The cost is that searching
inside documents stops working; searching by name still works, but walks the
tree instead of consulting an index.

Thumbnails go the same way and on weaker grounds, which is worth stating.
The file manager's own setting is `local-only`, which sounds like the
protection a network home wants and is not: `local` there means the kernel
calls the filesystem native, and it calls NFS native. So the default reads
every image in a browsed directory in full, over the network. Against that:
the result is cached in the profile and the profile persists, so it is a cost
per machine rather than per session; the file manager skips anything over its
own size limit; and this is something a user can see and probably wants. What
tips it is that a desktop delivered as a video stream pays for a wall of
thumbnails twice, once over the network and again in the encoder.
`HDW4S_THUMBNAILS=on` gives them back.

The first two are what `HDW4S_DPI` set to a number stops -- `96` stops them
outright, another number still applies itself once at startup and writes them
that once -- at the cost of a desktop that no longer scales to a HiDPI or
zoomed browser. It is left following by default
because that cost falls on everyone who opens a session, while these two files
matter only to an account that keeps something in them.

Existing settings can be carried across once with `hdw4s seed`, which is the
only supported way to populate a profile from a home directory and does not run
by itself.

What becomes per-session:

    desktop appearance, extensions, keyboard shortcuts
    saved passwords and online accounts (a separate keyring; see `keyring`)
    browser profile, history and open tabs
    recently-used files

One consequence is worth planning for: browsers download some data per
profile, and an isolated session is a new profile. A current Chrome fetches an
on-device language model of nearly three gigabytes that way, so a machine
running several isolated sessions holds several copies of it on local disk and
fetches each one over the network. Where that matters, it can be turned off
for every session at once with a browser policy, which is a decision for the
administrator rather than something this package should make.

That split is not a compromise that can be tuned away. Those components conflict
precisely because they are shared, so the only way to stop the conflict is to
stop sharing them.

## DISPLAY AND PORT ALLOCATION

A session's TCP port comes from a slot recorded in `/etc/hdw4s/instances`. The
slot is assigned when the session is first enabled and never moves, so a reverse
proxy and a firewall can both be configured against it and stay valid when
accounts are added or removed.

The X display number is *not* allocated. The X server picks the first free one
itself and reports it back, which is the only way to claim one without a race.
Nothing outside the machine ever sees the display number, so it does not need to
be predictable.

## TRANSPORTS

How the reverse proxy reaches a session, in decreasing order of how much the
machine itself can guarantee.

  * **Unix socket** (`hdw4s transport` <instance> `unix`):
    The session listens only on loopback, and systemd exposes it at
    `/run/hdw4s-proxy/<instance>.sock`, owned by the group named in
    `HDW4S_PROXY_GROUP`. Who may connect is then a question of file
    permissions: a process that cannot open the socket cannot reach the
    session at all, whatever address it comes from and whatever it claims to
    be. There is no shared secret to leak and no address to spoof.

    This is the right answer whenever it is available. It requires the proxy
    to be on the same machine, or to be able to see the same filesystem.

    Two containers on one host can share a socket if the same directory is
    bind-mounted into both and they use the same user-id mapping, which is the
    usual default. It then behaves exactly as it would locally: file
    permissions decide who may connect, and `SO_PEERCRED` reports the peer's
    identity translated correctly into the reading side's namespace. Containers
    with *different* id mappings see different ownership on the same file, and
    that is where the arrangement stops working.

  * **TCP with a proxy credential** (`tcp` plus `hdw4s auth`):
    For a proxy on another machine. The firewall restricts which addresses may
    connect, and the session additionally requires a secret that only the proxy
    knows, injected by it as a header. An attacker who defeats the address
    check -- by spoofing, or simply by being on the same network -- still does
    not have the secret.

    The secret crosses the network in the clear on each request, so it is
    worth pairing with something that makes the path itself private, such as a
    point-to-point encrypted tunnel between the proxy and the session's host.

    It is also worth making the address check mean something. Where the
    network can pin each host to the addresses it was assigned, a neighbour can
    no longer claim to be the proxy, which is otherwise the easy way past an
    address list. Most hypervisors and many switches offer some form of this;
    consult their documentation, and check afterwards that a dynamically
    assigned address has not been left out.

  * **TCP alone** (`tcp`, the default):
    The firewall's address list is the only control. Adequate on a network
    where nothing untrusted can route to the machine, and the weakest of the
    three otherwise.

## REVERSE PROXY AND SECURITY

**A session performs no authentication of its own.** It is built to sit behind a
reverse proxy that has already identified the user, so that reaching the desktop
takes no second login. Anything that can open a TCP connection to a session port
gets that user's desktop.

Two things follow, and both matter:

  * `HDW4S_PROXIES` must list the proxy, and nothing else. It is the only thing
    standing between a session and everything that can route to the machine.

  * The proxy must be the only path. Terminate TLS there, authenticate there,
    and do not expose a session port by any other route.

Two things sharpen the second point.

The newest connection wins. A client that opens a desktop somebody else is using
takes it, and the identity a client presents is its own claim rather than
something the session checks. So where an unauthenticated reach at a session
port once meant a connection that was refused, it now means one that can take a
running desktop away from the person at it.

And the streaming server offers more than a desktop unless it is told not to.
Its own defaults serve a file manager over the user's `Desktop` directory,
accept uploads into it, let any caller restart the media stack in WebRTC mode,
and admit extra viewers and gamepad players to a live session. hdw4s turns each
of those off at the server, by name rather than by relying on a default, because
they share a URL prefix with the stream and a proxy cannot separate them. Two
endpoints, `/api/status` and `/api/health`, answer before any authentication
runs and always will.

The remedy for all of it is the same as it has always been, and it is why
`HDW4S_PROXIES` exists; this only raises what is lost by getting it wrong.

The package owns one nftables table, `inet hdw4s`. It restricts and does not
grant. A drop in this table overrides any other table's accept, so the port
block can be closed reliably. An accept in it is only advisory: if another
firewall on the machine drops the packet first, nothing here brings it back, so
opening the block to the proxy may need a rule wherever that firewall is
configured.

The rules cover the whole port block rather than the ports currently in use. A
rule written per session goes stale the moment a session moves, which is how a
firewall ends up guarding a port nothing listens on while live sessions sit
unprotected beside it.

The table is also checked periodically, not just applied once at session start.
`nft flush ruleset` removes every table on the machine, including this one, and
several common tools issue it -- `ufw reload` and `netfilter-persistent` among
them. Without a check, the table would vanish while every session carried on
serving, and nothing would say so. `hdw4s-firewall.timer` notices and puts it
back.

`hdw4s enable` refuses an account below UID 1000 unless
`HDW4S_ALLOW_SYSTEM_USER=yes` is set, since a browser-reachable desktop with no
authentication of its own is rarely what is wanted for a system account.

Each session's X server is given its own authority cookie in its runtime
directory. Without one, every account on the machine could read the session's
screen and type into it.

`HDW4S_PORT` appears in an instance's file but is not a setting: `enable`
writes it, and the relay in front of the session is configured from the same
allocation at the same moment. Changing it moves where the session listens
without moving where the relay connects, so the desktop starts and is
unreachable, and nothing reports it.

## FILES

  * `/etc/hdw4s/hdw4s.conf`:
    Defaults for every session.

  * `/etc/hdw4s/<instance>.conf`:
    Settings for one session.

  * `/etc/hdw4s/instances`:
    Slot table mapping instances to ports. Edit with `hdw4s release`, not by
    hand while a session is running.

  * `/etc/hdw4s/<instance>.auth.cred`:
    The credential the reverse proxy has to present, encrypted to this
    machine. Created by `hdw4s auth` and by `hdw4s enable` for a session it
    creates; removed by `hdw4s noauth` and by `hdw4s release`.

  * `/etc/hdw4s/<instance>.keyring.cred`:
    The session keyring's password, encrypted to this machine. Created by
    `hdw4s keyring`, removed by `hdw4s release`.

  * `/etc/hdw4s/nftables.conf`:
    Generated ruleset. Regenerated by `hdw4s firewall --apply`.

  * `/etc/sysctl.d/60-hdw4s.conf`:
    Reserves the session port block so that the kernel never hands one of
    those ports to an outgoing connection from something else, which would
    otherwise stop a session binding, intermittently. Written by
    `hdw4s firewall --apply`.

  * `/etc/systemd/system/hdw4s@<instance>.service.d/`:
    Drop-ins written by `hdw4s enable`: the account the session runs as, the
    home directory it may write to and is ordered after, a profile directory
    outside the default, and the credentials to load. Written by the tool,
    not by hand -- `hdw4s enable` is safe to re-run and rewrites them.

  * `/etc/systemd/system/hdw4s-proxy@<instance>.socket.d/`:
    The address the front door listens on, written by `hdw4s transport`.

  * `/usr/lib/hdw4s/hdw4s.xorg.conf`:
    X server configuration for the `dummy` driver. Deliberately not
    `/etc/X11/xorg.conf`, which belongs to the machine's own display.

  * `/var/lib/hdw4s/<instance>/`:
    An isolated session's profile.

  * `/run/hdw4s/<instance>/`:
    Runtime directory: X authority cookie, X server log, current display.

  * `/run/hdw4s-proxy/<instance>.sock`:
    The filesystem socket a session is reached through, where
    `hdw4s transport` has been told to use one.

## UPDATES

A timer follows upstream daily, installing the distribution package upstream
publishes. What it downloads is checked against a sha256 -- the one recorded in
`hdw4s-update` for the release and platform the maintainer tested, otherwise the
digest GitHub publishes for that asset -- and the download is refused if neither
is available, so nothing is ever installed unchecked. It also reads the
package's own control fields back and checks its declared dependencies against
the machine before installing, rather than unpacking something that then cannot
be configured. That pins the bytes to what somebody saw; it is not a signature,
and upstream publishes none. See SECURITY.md.

It restarts only sessions nobody is connected to. A session in use keeps the
version it started with until it next stops on its own, which is when picking
up a new one costs nothing. An updater that reboots a desktop somebody is
working in, at an hour chosen by a timer, is an updater that gets switched off.

## DIAGNOSTICS

    hdw4s list                       what exists and whether it is running
    hdw4s show <instance>            effective settings and their source
    hdw4s firewall --check           whether the table is loaded and what it covers
    hdw4s --version                  which version this is
    systemctl status hdw4s@<i>       includes the display and port when running
    journalctl -xeu hdw4s@<i>        session output, including the X server

The X server's log is kept in the session's runtime directory rather than the
home directory, so it disappears with the session instead of accumulating.

## LIMITATIONS

There is no way to configure STUN or TURN, and nothing left for one to
configure. A session serves a single WebSocket: dual mode is locked off, so the
WebRTC stack never starts, no UDP socket is opened, no connection candidates
are gathered and no STUN server is contacted. Checked rather than assumed --
the streaming server's process owns one TCP listener on loopback and no UDP
socket at all.

Under 1.6 this was not true, and the reasons it mattered are worth keeping: the
server appended its own default STUN server unless one was named exactly, so a
setting could only ever add a second and never replace the first, and every
session told a third party the machine's address and when it started. TURN was
disabled outright because the server otherwise used a relay belonging to a
third party with a shared secret published in its own source, which would have
carried the desktop's video, keystrokes and clipboard.
Enabling a relay you run yourself needs somewhere to keep its credentials that
a session cannot read, which does not exist yet: the configuration files are
read by the session as the desktop user, so a secret in them is readable by
every account with a desktop on that machine.


An account gets one desktop per machine. The same account having desktops on
*different* machines, against one home directory, is a supported case and is
what `HDW4S_ISOLATION=profile` exists for.

`sendmail` does not work inside a session; SMTP to `localhost` does. The two
differ because the local `sendmail` command does not talk to the mail system
over the network -- it writes into the queue directory through `postdrop` --
and `ProtectSystem=strict` makes that directory read-only. It fails with
`Read-only file system` and the message is lost, leaving only a warning in the
journal.

The mail system itself is outside the session and perfectly reachable. A
session shares the machine's network namespace, so submitting to `127.0.0.1:25`
works and is the supported route. Measured from inside a running session, as
the session's own account: the banner answers, the message is accepted, and the
local mail system relays it onward -- `status=sent`, a real delivery to the
smarthost.

So a program that must send mail from a desktop should speak SMTP to
`localhost`, which is what every mail client already does. The gap only affects
programs that shell out to `sendmail`, and the one that does so here is
convenient to lose: `sudo`'s `mail_badpass` cannot raise a message from a
session, so a mistyped password in a desktop generates no mail at all.

This package is for machines with no screen. A session for an account that is
also logged in at a physical console on the same machine is not supported and
not tested. It is not prevented either, and no reason is known why it could not
work -- the conflict it would cause is the one `HDW4S_ISOLATION=profile`
addresses -- but nothing here detects it or warns about it, and two desktops
writing one account's settings corrupt them rather than reporting anything.

A session gives GNOME a private D-Bus, so gnome-session cannot reach a systemd
user manager and falls back to its own service manager. Two things follow, and
both are load-bearing rather than incidental. The desktop's components stay
inside the session's control group, which is what lets `KillMode=control-group`
reap the whole desktop when the unit stops -- as user units they would belong to
the account's `user@.service` and survive it. And the package depends on that
fallback existing at all: **GNOME 49 removes it and GNOME 50 replaces it with a
hard refusal, and GNOME 50 also removes the X11 session** the current Selkies
release needs. Neither version works here, and the limit is on the package
rather than on any optional part of it.

That limit does not reach the rest of the design. The X server, the streaming,
the audio and the isolation are all indifferent to which desktop is started, so
setting `HDW4S_SESSION` to one that is not being withdrawn from X11 -- Xfce,
MATE, LXQt -- avoids both halves of it. That is a smaller change than it sounds,
and a much smaller one than bridging a Wayland session back onto an X11 display,
which is possible but visibly a workaround.

Snap and Flatpak applications ignore the wrappers and some of the environment
used to isolate a session, so they may still share state between desktops.

A session runs with `CAP_NET_RAW` in its capability bounding set and nothing
else, which is what lets `ping(8)` work. Nothing is granted by that: a program
still needs the capability on its own file, and marking a file needs
`CAP_SETFCAP`, which the session does not have. Tools that capture packets are
a different matter and do not work in a session at all, whatever capabilities
they carry, because `AF_PACKET` is not among the address families the unit
permits. Run those over `ssh(1)` instead, where none of these restrictions
apply. An empty bounding set was tried first and is a trap worth naming: the
distribution ships `ping` with the effective bit set, the kernel refuses to
execute a binary whose effective capabilities cannot be granted, and the result
is `Operation not permitted` from `exec` with nothing said about sockets or
capabilities.

## EXIT STATUS

  * `0`:
    The command did what it was asked to.

  * `1`:
    It failed, and said why on standard error. `hdw4s firewall --check` also
    exits 1 when the check itself was fine but what it found was not -- a
    missing table, a session outside the loaded port range, a `proxies` set
    that no longer matches the configuration. That is a result, not a fault,
    which is why the check is worth running from a timer.

  * `2`:
    The command line was wrong: an unknown command, or the wrong number of
    arguments. Nothing was changed.

## ENVIRONMENT

  * `HDW4S_ETCDIR`:
    The configuration directory, `/etc/hdw4s` by default. It exists so that
    the test suite can run against a disposable copy; changing it on a real
    machine points the tool at one set of files while the units and the
    firewall go on reading another.

  * `PYTHON`:
    The interpreter `hdw4s firewall --check` uses to read nftables' JSON
    output. Defaults to `python3`.

## SEE ALSO

`systemd.unit`(5), `systemd.exec`(5), `nft`(8), `Xorg`(1), `Xserver`(1),
`xauth`(1), `dbus-run-session`(1), `dconf`(7)
