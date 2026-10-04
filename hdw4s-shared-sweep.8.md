hdw4s-shared-sweep(8) -- guard, sweep and relay for the hdw4s /shared drop area
============================================================================

## SYNOPSIS

`hdw4s-shared-sweep` `--dir` <tabledir> `--idle` <duration> `--max-age` <duration><br>
`hdw4s-shared-sweep` `--watch` `--dir` <tabledir><br>
`hdw4s-shared-sweep` `--guard` <directory> [`--form` `any`|`i`|`ii`]<br>
`hdw4s-shared-sweep` `--harden` <store><br>
`hdw4s-shared-sweep` `--check` `--dir` <directory> `--idle` <duration> [`--interval` <duration>] [`--verbose`]<br>
`hdw4s-shared-sweep` `--relay-server` `--dir` <tabledir> [`--group` <group>] [`--interface` <names>] [`--allow` <host>[,<host>...]] [`--listen` <addr>] [`--port` <port>] [`--silence` <duration>] [`--heartbeat` <duration>]<br>
`hdw4s-shared-sweep` `--relay-client` `--store` <store> `--idle` <duration> [`--group` <group>] [`--ttl` <n>] [`--interface` <name>] [`--to` <addr>] [`--port` <port>] [`--heartbeat` <duration>]<br>
`hdw4s-shared-sweep` `--probe-sandbox` `--dir` <tabledir> [`--probe-path` `r`|`w`:<path>]...<br>
`hdw4s-shared-sweep` `--version`

## DESCRIPTION

`/shared` is a drop area that every hdw4s desktop on a machine, and the
machine's administrator, can read and write: anybody may leave, take, replace
or change anything there, and nothing about an item is promised. This tool
keeps it from becoming a route to anything else, and keeps it tidy.

It does three jobs, each from its own unit:

  * The **sweep** (`hdw4s-shared-sweep@.timer`, every two minutes) removes
    anything that is not a regular file or a directory, makes every file
    readable and writable by everybody (`(mode & 0777) | 0666`, which also
    clears set-id bits) and every directory `0777`, and removes what nobody
    has used for the idle time or what is older than the maximum age.
  * The **watcher** (`hdw4s-shared-watch@.service`) does the first two at
    once, when an item appears, wherever the kernel allows it.
  * The optional **relay** carries "this file was read" from an NFS client to
    the store's server, where the sweep runs; see [THE RELAY][].

On a machine running hdw4s, hdw4s starts the sweep and the watcher for the
store it owns; see hdw4s(8). This package exists on its own for the machine
that owns a store shared with others, such as a storage node or a hypervisor
that binds the store into containers.

## THE STORE RULE

A **store** is a whole filesystem dedicated to `/shared`. Its root is owned by
root and is not group- or other-writable, and it holds one directory, `table`
(mode `0777`, not sticky), and nothing else except `lost+found` and `.zfs`.
Only `table` is ever exposed to desktops or swept.

Every view of it must be mounted `nosymfollow`, `nodev`, `noexec` and
`nosuid`, and, unless the filesystem is NFS, `strictatime`. These flags are
what make it safe for root to walk a tree anybody can change: no path through
it follows a symbolic link, nothing in it runs or acts as a device by being
opened, and a separate filesystem means nothing in it is a hard link to a file
anywhere else. On NFS, access times are the server's: mount the store there
with access times recorded on every read (on ZFS: `atime=on relatime=off`).
This tool cannot verify that from a client.

## THE GUARD

Every mode starts by judging the directory it was given, and refuses to touch
anything if the judgement fails. A directory is accepted in exactly one of two
forms:

  * **(i)** it is the root of a bind of a store's table, which is how
    desktops see it. Two things prove it, and both are required: another
    mount of the same filesystem, visible on the same machine, is a store that
    passes form (ii), and this mount's root is that store's `table` itself
    (the same device and inode); AND, on a local filesystem, the mount's root
    within its filesystem is `/table`, while over NFS -- where a bind of a
    subdirectory records its root as `/` -- the mount's source is the store's
    source followed by `/table`. Anything else, a `table` directory of another
    filesystem included, is refused (`no-sibling`);
  * **(ii)** it is the directory `table` directly beneath the root of a mount
    whose root is `/`, and that mount satisfies the store rule.

The sweep, the watcher and the relay server change things, and accept form
(ii) only: they are always given a store's own table. Form (i) is for
`--check` and `--guard`, which only look.

The mount is found from the directory's own mount id (statx), never by
matching paths, and must carry the flags above. `--guard` prints one line and
exits 0 when it accepts, and prints the clause that failed and exits 1 when it
refuses: `open`, `path` (the path resolves somewhere else, through a
symbolic link), `mount`, `flags`, `form-i`, `stacked`, `not-mount-child`,
`not-table`, `no-sibling`, `fs-root`, `store-owner`, `store-extra`, `moved` (a running
watcher or relay finds the store unmounted or remounted under it) or, for
`--harden`, `remount`.

Independently of the guard, every removal and every change of mode is made
relative to an open directory, on a single name, and only after checking,
immediately before the call, that the directory is still on the table's mount
and still beneath the table, that the entry is on the same mount and is the
one that was judged, and, for a change of mode, that the file has no other
link.

Inside an unprivileged container the store root, owned by the host's root,
appears owned by the overflow uid (65534); that is accepted there, and only
there.

A stat on an NFS store whose server is down blocks; run the guard under
timeout(1) where that matters.

## OPTIONS

  * `--dir` <tabledir>:
    The directory to sweep, watch, serve or check. A store's `table`, or a
    bind of it.
  * `--idle` <duration>:
    Remove an item once none of its access, modification and change times is
    newer than this (`30m` by default in the units). A directory is judged by
    its modification and change times only, because listing it moves its
    access time, and only once it is empty. A time more than five minutes in
    the future is ignored.
  * `--max-age` <duration>:
    Remove an item this long after it was created, however much it is used
    (`7d` by default). Needs the filesystem to report a birth time; where it
    does not, the maximum age is not enforced, and the sweep and `--check` say
    so.
  * `--harden` <store>:
    Check the store rule, then add any missing flag to <store> by remounting
    it in place, then guard its `table`. A path that is not a store is refused
    before anything is remounted.
  * `--check`:
    Print what `hdw4s check` reports about /shared, one `red:` or `warn:` line
    each: the guard refusing; nobody sweeping (an item unused for longer than
    the idle time plus two intervals is still there); over 90% full; an NFS
    store mounted `hard`; no birth time. Reads only.
  * `--interval` <duration>:
    The sweep's period, for `--check` (default `2m`).
  * `--max-depth` <levels>:
    How deep below the table the sweep, the watcher and `--check` go (default
    8192, and never more than the open files the process may hold). A
    directory deeper than that is not entered, so nothing below it is widened
    or expired; the sweep counts them and `--check` warns while there are
    any.
  * `--dry-run`[`=1`|`=0`]:
    For the sweep and the watcher: every removal and every widening that
    passes the checks is NOT made, and is logged instead as one line, `would
    expire`, `would remove-non-file`, `would rmdir` or `would widen`, with the
    item's name relative to the table -- the only time this tool logs a name.
    The pass summary says what would have been done. A nest of empty
    directories shows only its deepest level, since nothing beneath is really
    removed. In the units, `HDW4S_SHARED_DRYRUN=1` in a drop-in turns it on.
  * `--unsandboxed`:
    The sweep and the watcher refuse to run as root on the host with a
    writable root filesystem, which is what running them outside their units'
    `ProtectSystem=strict` looks like. This says it is meant.
  * `--probe-sandbox`:
    Try to open a few files outside the table (write: `/proc/sys`, `/sys`;
    read: `/etc/shadow`, and each `--probe-path`), and to touch
    <tabledir>`/canary`; print only whether each open succeeded. Run it in place
    of a unit's command, with a drop-in that replaces `ExecStart=`, to see
    what that unit's sandbox actually allows.

Durations are a number with one of systemd's unit letters, `s` `m` `h` `d`
`w` `M` `y` (`m` is minutes, `M` months), or a bare number of days. The
shortest is `2m`, and `0` is refused: expiry is not optional.

## UNITS

Every unit is a template whose instance is the escaped path of the store's
**root**: `systemd-escape --path /srv/shared-store` gives
`srv-shared\x2dstore`. Each is bound to that path's mount unit, so it stops
when the store is unmounted and is never left holding it busy.

  * `hdw4s-shared-harden@.service`: on the machine that mounts the store from
    its device, enable it so that every mount is given its flags before it is
    exported or bound anywhere.
  * `hdw4s-shared-sweep@.timer`, `hdw4s-shared-watch@.service`: enable them on
    exactly one machine per store, the one that owns its storage. Change the
    idle time and maximum age with a drop-in setting `HDW4S_SHARED_IDLE=` and
    `HDW4S_SHARED_MAX_AGE=` in the `.service`.
  * `hdw4s-shared-relay-server@.service`, `hdw4s-shared-relay-client@.service`:
    off unless enabled; see below.

The sweep and the watcher run as root with only `CAP_FOWNER`,
`CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`, under `ProtectSystem=strict`
plus `ReadOnlyPaths=/run` (strict alone leaves `/run` writable), with only
the store writable. The watcher also has `CAP_SYS_ADMIN` for its one
fanotify mark and drops it immediately after. `ProtectHome=` covers `/home`,
`/root` and `/run/user` only: a machine whose home directories are elsewhere
should add `InaccessiblePaths=` for them in a drop-in.

The sandbox is fixed when a unit starts. A filesystem the host mounts
later -- a homes dataset brought up at runtime, an NFS remount -- appears
inside an already running watcher or relay server writable, whatever
`ProtectSystem=` says. `InaccessiblePaths=` on its PARENT directory does
cover mounts made under it later, so name the parent of any homes tree that
may be mounted at runtime, not the tree itself. The watcher and the relay
server are restarted once a day (`RuntimeMaxSec=1d`) so that their view is
renewed; the sweep starts afresh at every run.

For example, on a storage node whose store is mounted at `/srv/shared-store`:

    systemctl enable --now 'hdw4s-shared-harden@srv-shared\x2dstore.service'
    systemctl enable --now 'hdw4s-shared-sweep@srv-shared\x2dstore.timer'
    systemctl enable --now 'hdw4s-shared-watch@srv-shared\x2dstore.service'

## SHARING ONE STORE BETWEEN MACHINES

Mount the store on the **host**, with the flags, and bind it into each
container, carrying the flags on the bind. If the store is remote, the host
mounts it over NFS (`soft`, a short `timeo`, and the four flags). Run the
sweep and the watcher only on the machine that owns the storage: access times
are truthful there, and fanotify is refused on NFS and on a host's filesystem
seen from inside a container. On every desktop machine set
`HDW4S_SHARED=source` and `HDW4S_SHARED_SWEEP=external`; see hdw4s(8).

  * **LXC, Proxmox VE:** in the container's configuration,
    `lxc.mount.entry: /srv/shared-store srv/shared none bind,create=dir,optional,nosymfollow,nodev,noexec,nosuid,strictatime 0 0`.
    `optional` lets the container start when the store is missing; the guard
    then refuses the empty directory. Proxmox's `mpN:` also works, but takes
    part in snapshots, backups and migration.
  * **Incus, LXD:** a disk device from the host's flagged mount.
  * **A virtual machine:** an NFS mount carrying the flags.

For high availability, present the store at one path on every node (locally
where it lives, over NFS elsewhere), so the container's entry is valid
wherever it runs.

On ZFS, the mount helper refuses `nosymfollow`: mount the dataset plainly
(`mountpoint=legacy`, from fstab) and let `hdw4s-shared-harden@` add the
flags. Exclude the dataset from automatic snapshots and replication, and set
`quota` as well as `refquota`: snapshots of a busy drop area are not bounded
by `refquota`.

## THE RELAY

Reads served from an NFS client's page cache never reach the server, so an
item read only through an NFS client can expire up to the idle time after it
was last written or first read there. The relay closes that gap. It is
optional and off by default; without it, nothing else changes. Once enabled
it needs no configuration.

It is meant for HOSTS: the server on the machine that owns the store, the
client on each machine that mounts it over NFS, neither in a container. A
tmpfs store, or any store whose sweep runs on the machine its readers use,
never needs it.

**Multicast, by default.** The client sends to the group 239.255.47.48 on UDP
port 4748 (IPv4 local scope), out of the interface of its route to the
store's NFS server, so it follows the store wherever it moves. The server
joins that group on every interface that is up, multicast-capable, not
loopback and has an IPv4 address, and logs which at start. Whichever nodes
are up, on one network segment, this just works.

  * **TTL 1: one segment.** Nodes on different subnets: raise the TTL
    (`--ttl`, `HDW4S_SHARED_RELAY_TTL=`) where multicast is routed, or
    configure unicast.
  * **IGMP snooping.** A switch that snoops IGMP but has no querier forgets a
    group after a few minutes. The server re-issues its membership every
    minute (an unsolicited report), which keeps such a switch forwarding.
  * **Firewall.** On the storage host, allow UDP to 239.255.47.48 port 4748
    from the client hosts on the interface that faces them.
  * **What is on the wire, and who can read it.** Announcements carry the
    table-relative name and fileid of each file opened through an NFS
    client, as it is used, so they also say WHEN it was used. They are not
    encrypted, and any host on the segment can read them: it need only join
    the group, and with TTL 1 and no IGMP querier they flood the segment
    anyway, including any guest network bridged onto it. Nothing else is
    sent -- never contents, and never which user opened a file, only which
    client host's announcement it was. Under the default threat
    model this is harmless: the names are already visible in every desktop's
    `/shared`, to everyone who can use it. If it is not acceptable that other
    hosts on the segment can see which files are used and when, configure
    unicast instead (below); the cost is upkeep, because then the server's
    address and the list of client hosts are kept by hand.
  * **The port.** The server does not set `SO_REUSEPORT`. A local process on
    the storage host could still bind the port first and receive or squat the
    announcements; only an administrator there can.

**Unicast, if configured:** the client's `--to` (`HDW4S_SHARED_RELAY_TO=`)
names the server; the server's `--listen` (`HDW4S_SHARED_RELAY_LISTEN=`)
names the one address it binds -- never a wildcard -- and `--allow` is then
required. Announcements then go only to that address. Nothing is discovered:
every client host must be added to `--allow`, and every client's `--to`
changed whenever the server's address does (a store that moves between
hosts takes its server with it), or that client's reads silently stop
keeping anything alive until somebody notices the server's warning about
its silence.

The **client** watches every directory of the table with inotify and sends
"this file was used" for each open it sees, at most once per file per quarter
of the idle time, plus a heartbeat every ten minutes (`--heartbeat`). It
never reads file contents and never listens.

It does not see an open in a directory it is not yet watching: one created
on its own host an instant before the open (the open can race the new
watch), or one created anywhere else -- on the storage host or through
another NFS client -- because inotify reports only what happens on its own
host; such a directory is watched from the client's next rescan, every
quarter of the idle time. What it misses is therefore new, and the sweep
covers it another way: it counts a file's ctime, which nobody can set back,
so a file is kept at least the idle time after it was created or moved in,
longer than it takes the client to start watching its directory.

The **server** runs beside the sweep. The only thing any datagram can make it
do is move the access time of an existing regular file inside the table,
which keeps it from expiring early: never beyond the maximum age, and nothing
is ever created, removed, re-moded or written. It runs as its own system
user, `hdw4s-shared-relay`, with only `CAP_FOWNER`, and never sends a packet.
In multicast mode it binds the wildcard -- a group arrives addressed to the
group -- and three checks decide what it reads: only the group it joined
reaches the socket; a datagram must be addressed to that group and have
arrived on an interface it joined on; and its source must be on a subnet
connected to that interface. `--allow` (single hosts) narrows the sources
further, and `--interface` the interfaces. In an unprivileged container
systemd's `IPAddressAllow=` and `IPAddressDeny=` are silently inert, so the
server's own checks are the layer there.

    # /etc/systemd/system/hdw4s-shared-relay-server@srv-shared\x2dstore.service.d/narrow.conf
    [Service]
    Environment=HDW4S_SHARED_RELAY_INTERFACES=br0
    Environment=HDW4S_SHARED_RELAY_ALLOW=192.0.2.10
    IPAddressAllow=192.0.2.10
    IPAddressDeny=any

The server's user must be able to traverse the store's root (the store rule's
0755): a store root of 0700 makes it drop every announcement, correctly.

**When multicast fails, the journal says so**, briefly: at start, one line
naming the joined interfaces; a client named in `--allow` that sends no
heartbeat for `--silence` (thirty minutes), one warning, and one line when it
is heard again; nothing received from anybody for two heartbeat intervals
after somebody was heard, one warning and one recovery line; nothing ever
received an hour after start, one line saying to check the firewall and IGMP.
A client that cannot send says so once, with the error, then counts hourly,
then says once when it works again. A join refused because the host has more
interfaces than `net.ipv4.igmp_max_memberships` allows is logged once. The
counters are logged on `systemctl kill -s USR1`, and hourly when they changed;
the client's also once when it stops, including every open it did not
announce, by reason (`discard-...`, `coalesced`), and how many were still
pending. A spoofed source can keep an existing file alive up to its maximum
age, and nothing more.

**A burst of opens is paced.** The client sends at most five times a second,
packing what is due into full datagrams: at most 100 announcements a second,
1000 at once, and never more than 16 datagrams at once or 20 a second. The
server grows its receive buffer to hold that burst, 278528 bytes as the kernel
counts them, and never shrinks a larger one. Its start line says the size it
got, in the same bytes; if that is less, it warns, and `net.core.rmem_max`
must be at least 139264, half of it, because the kernel doubles what it is
asked for (a stock rmem_max is enough). The datagrams the kernel dropped for
the socket -- a full buffer, mostly -- are `drop-kernel-datagrams` in its
counts line: datagrams, not announcements, of which one can carry dozens.
Opening many thousands of files at once therefore announces them over
minutes, at 100 a second.

## LOGGING

Counts only. No file name from the table and no name or payload from the
network is ever logged: they are whatever somebody chose, and a journal may be
persistent.

## EXIT STATUS

`0` done, or accepted; `1` refused by the guard, or `--check` found a red row;
`2` a usage error, a bad value, or the tool itself failed (never a verdict
about the store); `3` `--check` found warnings only.

## CAVEATS

**Trees too deep to reach.** A directory renamed into the bottom of another
deep tree can end up deeper than the sweep's depth budget, or deeper than the
kernel will resolve a path at all (under AppArmor, about 8 KiB of path).
Nothing below it is widened or expired; the sweep counts it and
`hdw4s check` warns. The remedy is the administrator's: on a tmpfs store,
reboot, or turn `/shared` off and on again; on a dataset, move the top
ancestor of the deep subtree up by hand (`mv` within the table), or remove it
from a root shell that is not confined by AppArmor.

The relay client's unit restarts with a growing delay (`RestartSteps=`,
`RestartMaxDelaySec=`), which needs systemd 254 or later. An older systemd
ignores those two lines with a warning and restarts every `RestartSec=`
instead, which is enough.

`nosymfollow` inside a container holds against its users, not against its
root: container root can remount without it. The guard runs at every pass and
the expose service unbinds `/shared` when a flag goes, so the result is an
empty `/shared`, not an unsafe one. A program that resolves links itself could
follow one planted in the table until the watcher removes it. A file renamed
between the sweep's look at it and its removal can be removed while new.
Anything taken from the table is as untrusted as everything else on it; copy
it out with a plain `cp`.

## SEE ALSO

hdw4s(8), systemd.exec(5), fanotify(7), inotify(7), nfs(5)
