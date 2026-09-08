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
`hdw4s` `proxy` <instance><br>
`hdw4s` `set` [<instance>] <KEY>=<VALUE>...<br>
`hdw4s` `unset` [<instance>] <KEY><br>
`hdw4s` `seed` <instance> [`--only` <path>]...<br>
`hdw4s` `keyring` <instance><br>
`hdw4s` `firewall` `--apply`|`--check`|`--print`

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

An instance is a user name, optionally followed by a colon and a session number:

    hdw4s enable alice
    hdw4s enable alice:2

The second form gives one account a second concurrent desktop on the same
machine. A colon is used because systemd leaves it untouched when it escapes an
instance name, and because it cannot occur in a user name, so splitting on it
can never cut a name in half.

## CONFIGURATION

Two files are read in order, the second overriding the first:

    /etc/hdw4s/hdw4s.conf         defaults for every session
    /etc/hdw4s/<instance>.conf    settings for one session

`hdw4s show` <instance> prints the settings that apply to one session.

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

  * `HDW4S_SESSION`:
    The desktop to start; defaults to `gnome-session`. Anything that runs on
    X11 works, and nothing else in a session depends on the choice. GNOME 50,
    which Ubuntu 26.04 ships, removes the X11 session that the current Selkies
    release needs, whereas Xorg and the lighter desktops have no such plan, so
    changing this is the whole migration when that matters.

  * `HDW4S_IDLE_DAYS`:
    How long a session may go with nobody connected before `reap` stops it.
    Defaults to 7. Measured by connections rather than by typing, so work left
    running is not mistaken for an idle desktop. Set it to 0 to never reap.

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

  * `SELKIES_VERSION`:
    Pin a Selkies release and stop following upstream.

## SHARED HOME DIRECTORIES

A GNOME session assumes it is the only one using its home directory. That
assumption breaks when the same home is mounted on more than one machine, or
when another desktop is already logged in against it. Two sessions then write
the same settings database, the same keyring and the same metadata stores. None
of those are safe to share, and the settings database and the metadata stores
use memory-mapped and journalled files that are documented not to work over NFS
at all.

Setting `HDW4S_ISOLATION=profile` keeps the shared home for the user's files but
moves the session's settings, state and cache to a private directory on local
disk. Concretely, the session gets its own `XDG_DATA_HOME`, `XDG_STATE_HOME`,
`XDG_CACHE_HOME` and dconf profile, its own X authority cookie, its own audio
server socket, and wrappers that give Firefox and Thunderbird their own
profiles.

All four XDG base directories move together: config, data, state and cache.
Leaving the config home shared and redirecting dconf on its own was tried and
abandoned, because it needs a service that has to answer before any setting can
be read, and it leaves a lock beside its database that a killed session does not
clean up. What this does not cover is a program that hardcodes `~/.config`
regardless of the variable, which in practice means some input-method
configuration.

What stays shared:

    Documents, Desktop, Downloads, Pictures, Music, Videos
    everything else in the home directory, including ~/.ssh

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

  * `/etc/hdw4s/<instance>.keyring.cred`:
    The session keyring's password, encrypted to this machine. Created by
    `hdw4s keyring`, removed by `hdw4s release`.

  * `/etc/hdw4s/nftables.conf`:
    Generated ruleset. Regenerated by `hdw4s firewall --apply`.

  * `/usr/lib/hdw4s/hdw4s.xorg.conf`:
    X server configuration for the `dummy` driver. Deliberately not
    `/etc/X11/xorg.conf`, which belongs to the machine's own display.

  * `/var/lib/hdw4s/<instance>/`:
    An isolated session's profile.

  * `/run/hdw4s/<instance>/`:
    Runtime directory: X authority cookie, X server log, current display.

## UPDATES

A timer follows upstream daily. It checks that what it downloaded is a
well-formed archive before replacing anything, and refuses outright to install a
release whose layout it does not recognise, rather than half-upgrading a working
machine. It does not verify authenticity: there is no signature and no recorded
hash, so a well-formed archive from the right URL is all it can establish. See
SECURITY.md.

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

There is no way to configure STUN or TURN. The streaming server appends its own
default STUN server unless it is named exactly, so a setting could only add a
second and never replace the first; a session therefore always contacts that
server at startup, which is a third party learning the machine's address and
when sessions begin. TURN is disabled outright, because the server otherwise
uses a relay belonging to a third party with a shared secret published in its
own source -- which would carry the desktop's video, keystrokes and clipboard.
Enabling a relay you run yourself needs somewhere to keep its credentials that
a session cannot read, which does not exist yet: the configuration files are
read by the session as the desktop user, so a secret in them is readable by
every account with a desktop on that machine.


A second desktop for an account that is already logged in on the same machine
works only because gnome-session falls back to its own service manager when it
cannot reach a systemd user manager, and there is only ever one of those per
account. GNOME 49 removes that fallback and GNOME 50 removes the X11 session
altogether, so that arrangement does not survive an upgrade past Ubuntu 24.04.

Sessions on *different* machines sharing one home directory are not affected:
the checks involved are local to a machine.

Neither limit reaches the rest of the design. The X server, the streaming, the
audio and the isolation are all indifferent to which desktop is started, so
setting `HDW4S_SESSION` to one that is not being withdrawn from X11 -- Xfce,
MATE, LXQt -- avoids both. That is a smaller change than it sounds, and a much
smaller one than bridging a Wayland session back onto an X11 display, which is
possible but visibly a workaround.

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

## SEE ALSO

`systemd.unit`(5), `systemd.exec`(5), `nft`(8), `Xorg`(1), `Xserver`(1),
`xauth`(1), `dbus-run-session`(1), `dconf`(7)
