# Running a Colophon home on a Mac

This page is for running a home on a Mac that stays on, such as a Mac mini, without Docker:
the reference relay (`relay/`, Bun) and the Rust home module run directly under macOS, as a
background service started by `launchd`. It assumes you are comfortable pasting commands into
Terminal and have an administrator account on the Mac, but not that you have run a server
before.

For what a home is and does, read [`relay/README.md`](../../relay/README.md); every setting is
listed there. For a container instead, read [`docker.md`](docker.md): much of what it says about
the key, backups and proxies applies here too.

What has been tested, and what has not, is marked as you go. In short: the key, token and
member ID commands and the configuration on this page were run, and the relay started with that
configuration on a loopback port, answered, provisioned a slot and stopped cleanly. The parts
that need an administrator (the user account, the `launchd` job, the power settings) and the
tunnel were **not** run while writing this page. They follow a setup that has been used in
practice, but check each step as you go.

## What you end up with

```
/opt/colophon-home/                      the home's folder, owned by the service user (0700)
  releases/colophon-home-<version>/      one unpacked home bundle per version (read-only)
  current -> releases/colophon-home-<version>
  config.json                            the relay config (0600)
  secrets/home-key.jwk                   the home's private P-256 key (0600): its identity
  data/                                  the relay's data directory: every slot, provisioned.json
/Library/LaunchDaemons/local.colophon-home.plist   the service (root:wheel, 0644)
/Library/Logs/ColophonHome/home.log      the relay's output
```

The relay listens on `127.0.0.1` only. Nothing on the Mac is reachable from the network; a
tunnel or a reverse proxy (see "Reaching it from the internet") carries `https://` traffic to
it.

The examples use the user name `colophonhome`, port `8787` and the public origin
`https://home.example.org`. Replace them with your own everywhere.

## 1. A user of its own

Run the home as a **standard (not administrator) macOS user that exists only for it**. Then:

- the home's key and data are readable by that user alone, not by your everyday account, the
  apps you run in it, or anything that account downloads;
- a fault in the relay, Bun or the module can reach only that user's files: it cannot install
  software, read your documents or change system settings;
- it is clear what belongs to the home when you back it up, move it or remove it.

Do not run it as your own user, and never as root.

Create the user from an administrator account. In System Settings, Users & Groups, "Add
User…", choose **Standard**, name it `colophonhome`, and give it a long random password that
you store in your password manager (you will not need to log in as it). Or in Terminal:

```sh
sudo sysadminctl -addUser colophonhome -fullName "Colophon home" -password -   # asks for the password
sudo dscl . -create /Users/colophonhome IsHidden 1    # optional: keep it off the login window
dscl . -read /Groups/admin GroupMembership            # colophonhome must NOT be listed
```

*Untested here.* Do not turn on Remote Login (SSH) for this user and do not log in to it; the
commands below act as it with `sudo -u colophonhome`.

Each command below that starts with `sudo -u colophonhome` runs as that user, so the files it
makes belong to it. The home lives in a folder of its own, `/opt/colophon-home`, rather than in
the user's home folder, so the backup is one folder and nothing else of the account's (its
settings, caches) is mixed in. Make it:

```sh
sudo install -d -o colophonhome -g staff -m 0700 /opt/colophon-home
sudo -u colophonhome sh -c 'umask 077 && cd /opt/colophon-home && mkdir -p releases secrets data'
```

## 2. Bun

The relay needs [Bun](https://bun.sh) 1.3 or newer (`relay/package.json`); it is tested with
1.4.4 and the container uses 1.4.5. Install it once, from your administrator account, with
Homebrew:

```sh
brew install oven-sh/bun/bun
/opt/homebrew/bin/bun --version
```

On an Intel Mac, Homebrew's prefix is `/usr/local`, so Bun is `/usr/local/bin/bun`; use that
path wherever this page says `/opt/homebrew/bin/bun`. The service user only runs Bun, so it
does not need Homebrew of its own. When you upgrade Bun (`brew upgrade bun`), restart the home
(step 6).

## 3. The home bundle

A home bundle is `colophon-home-<version>.tar.gz`: one folder, `colophon-home-<version>/`,
holding the relay's `.js` files and `package.json` (from `relay/` in the repository) and the
module `colophon_home_wasm.wasm`, side by side. Nothing needs installing: the relay has no
dependencies to fetch.

**What exists today.** The only published bundle is `colophon-home-0.5.0.tar.gz`, attached to
the [v0.5.0 release](https://github.com/luff-llc/colophon/releases/tag/v0.5.0) with
`SHA256SUMS`. It predates some settings on this page (the metrics endpoint and the module memory
bound, for example), though it reads the same config fields used below (*not tested with this page*); the patch releases after it are
tags with no release assets, and this page describes the relay on `main`. Until a later release
carries a bundle, you can use 0.5.0 or build one.

To use the published one, from your administrator account:

```sh
mkdir -p ~/Downloads/colophon-0.5.0 && cd ~/Downloads/colophon-0.5.0
curl -fLO https://github.com/luff-llc/colophon/releases/download/v0.5.0/colophon-home-0.5.0.tar.gz
curl -fLO https://github.com/luff-llc/colophon/releases/download/v0.5.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing     # must print: colophon-home-0.5.0.tar.gz: OK
```

To build one from a tag (or `main`) instead, you need Git and the Rust toolchain the repository
pins (1.99.1, with the `wasm32-unknown-unknown` target):

```sh
git clone https://github.com/luff-llc/colophon.git && cd colophon
git checkout v0.5.0                               # or the tag you want
bash scripts/package-release.sh --only home       # dist/release/<version>/colophon-home-<version>.tar.gz
```

`package-release.sh` builds in a clean environment of its own and writes `SHA256SUMS` beside
the bundle; [`docs/release-packaging.md`](../release-packaging.md) describes it. (*Not run while
writing this page*; the bundle tested here was made from the same files.)

Unpack it as the service user, read-only:

```sh
sudo -u colophonhome tar -xzf colophon-home-0.5.0.tar.gz -C /opt/colophon-home/releases
sudo -u colophonhome chmod -R a-w /opt/colophon-home/releases/colophon-home-0.5.0
sudo -u colophonhome ln -sfn releases/colophon-home-0.5.0 /opt/colophon-home/current
```

(The tar file must be somewhere the service user can read; copy it to `/tmp` first if
`~/Downloads` is not.)

## 4. The key

The home's key is its identity: every account that appoints this home names the key's member
ID. Make it once, as the service user, with the relay's own command:

```sh
sudo -u colophonhome sh -c 'umask 077 && cd /opt/colophon-home &&
  /opt/homebrew/bin/bun current/server.js home-key > secrets/home-key.jwk.new &&
  mv -n secrets/home-key.jwk.new secrets/home-key.jwk && rm -f secrets/home-key.jwk.new'
```

`mv -n` never replaces a key that is already there. Check that it loads, and note its member
ID. This loads the key with the relay's own code, the way the relay does at start-up, and prints
only the ID:

```sh
sudo -u colophonhome sh -c 'cd /opt/colophon-home/current && KEY=/opt/colophon-home/secrets/home-key.jwk \
  /opt/homebrew/bin/bun -e "const { HomeKey, HomeModule } = await import(\"./home.js\");
    const m = await HomeModule.load(\"colophon_home_wasm.wasm\");
    const k = await HomeKey.fromJwk(JSON.parse(await Bun.file(process.env.KEY).text()), m);
    console.log(JSON.stringify({ member: k.memberId }));"'
# {"member":"<32 hex>"}
```

(Bundles built from `main` also have `container-entry.js identity <key file>`, which prints the
same.)

Write the member ID down somewhere other than this Mac. After any restore, move or update, the
home must report the same one (step 9); a different ID is a different home.

The key is never printed by the relay and never written to the data directory. Do not copy it
anywhere except into a backup (step 10), and never run it in two places at once.

## 5. The config file

The relay reads one JSON file, named with `--config`. **Use absolute paths in it.** The relay
resolves relative paths against the folder it is started in, not against the config file.

Make a provisioning token first (the gate below admits it; anyone holding it can create slots):

```sh
sudo -u colophonhome sh -c 'cd /opt/colophon-home/current && /opt/homebrew/bin/bun server.js token'
# {"token": "...", "tokenSha256": "..."}
```

Keep `token` in your password manager for the app or tool that creates slots. Only
`tokenSha256` goes into the config. Then write `/opt/colophon-home/config.json` as the service
user (for example with `sudo -u colophonhome nano /opt/colophon-home/config.json`):

```json
{
  "host": "127.0.0.1",
  "port": 8787,
  "dataDir": "/opt/colophon-home/data",
  "home": {
    "keyFile": "/opt/colophon-home/secrets/home-key.jwk",
    "wasm": "/opt/colophon-home/current/colophon_home_wasm.wasm"
  },
  "limits": {
    "slotBytes": 268435456
  },
  "provision": {
    "enabled": true,
    "prefix": "https://home.example.org/v1/libraries/",
    "gate": "token",
    "tokenSha256": "<the tokenSha256 printed above>",
    "maxSlots": 20,
    "perAddressPerHour": 10,
    "unclaimedHours": 24
  },
  "clientAddress": {
    "header": "CF-Connecting-IP",
    "trustedPeers": ["127.0.0.1", "::1"]
  }
}
```

```sh
sudo -u colophonhome chmod 600 /opt/colophon-home/config.json
```

What each part does (the relay README has every field):

- `host`, `port`: loopback only. The tunnel or proxy on this Mac connects to it there.
- `dataDir`: where the slots live. It must belong to the service user and be on this Mac's own
  disk, not a network share or a synced folder (iCloud Drive, Dropbox).
- `home.keyFile`, `home.wasm`: the key from step 4, and the module of the release `current`
  points to.
- `limits.slotBytes`: the most bytes one slot may hold (here 256 MiB; `0` is no limit).
  `limits.requestsPerMinute` (per client address, default 1200) can be set here too.
- `provision`: the door at `POST /v1/provision` that creates a slot for an account. `prefix`
  is your public origin followed by `/v1/libraries/`, exactly. `gate` `"token"` admits only the
  token above; `maxSlots`, `perAddressPerHour` and `unclaimedHours` bound it. Gate `"open"`
  admits anyone within those bounds, which the README says is fine for a test home, not a
  production one; gate `"grant"` lets keys your own Colophon account delegates create slots
  (README, "Provisioning by a grant"). To create slots only by hand, leave `provision` out and
  list them under `libraries` instead.
- `clientAddress`: see "Reaching it from the internet". Leave it out if nothing sits in front of
  the relay.

Two more settings you may want: `home.moduleMemoryMB` (default 128; see
[docker.md, "Memory"](docker.md#memory)) and `metrics.tokenSha256` (see
[docker.md, "Metrics"](docker.md#metrics)).

Check the file before you install the service, by starting the relay once by hand. It prints one
line saying where it listens, or a message naming the setting it refuses:

```sh
sudo -u colophonhome sh -c 'cd /opt/colophon-home/current && /opt/homebrew/bin/bun server.js --config /opt/colophon-home/config.json'
# {"listening":{"host":"127.0.0.1","port":8787,"tls":false}}
```

In another Terminal window, `curl http://127.0.0.1:8787/healthz` answers `{"ok":true}`. Stop
the relay with Control-C. (*Tested*: this config, with a temporary data directory, parsed and
the relay answered `/healthz`, the provisioning door and a provisioned slot.)

## 6. The service

A LaunchDaemon starts the home when the Mac starts, before anyone logs in, runs it as the
service user, and starts it again if it exits. Save this as `local.colophon-home.plist` (any
folder), changing the user name, paths and Bun's path if yours differ:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>local.colophon-home</string>
  <key>UserName</key><string>colophonhome</string>
  <key>GroupName</key><string>staff</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/bun</string>
    <string>/opt/colophon-home/current/server.js</string>
    <string>--config</string>
    <string>/opt/colophon-home/config.json</string>
  </array>
  <key>WorkingDirectory</key><string>/opt/colophon-home/current</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>/opt/colophon-home</string>
    <key>PATH</key><string>/usr/bin:/bin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ExitTimeOut</key><integer>30</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardInPath</key><string>/dev/null</string>
  <key>StandardOutPath</key><string>/Library/Logs/ColophonHome/home.log</string>
  <key>StandardErrorPath</key><string>/Library/Logs/ColophonHome/home.log</string>
</dict>
</plist>
```

- `KeepAlive` restarts the relay whenever it exits, and `ThrottleInterval` waits 10 seconds
  between attempts, so a bad config shows up as the same message in the log every 10 seconds.
- `ExitTimeOut` is how long `launchd` waits after asking the relay to stop (SIGTERM) before it
  kills it. The relay stops taking requests and waits up to 8 seconds for those in flight, so
  give it more than that.
- `Umask` 63 is octal 077: what the relay creates is private to the service user.
- The log goes to a folder that belongs to root, so the service user cannot replace the log
  file with a link to some other file `launchd` would then write to.

Install it from your administrator account:

```sh
sudo install -d -o root -g wheel -m 0755 /Library/Logs/ColophonHome
sudo install -o colophonhome -g staff -m 0600 /dev/null /Library/Logs/ColophonHome/home.log
plutil -lint local.colophon-home.plist
sudo install -o root -g wheel -m 0644 local.colophon-home.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/local.colophon-home.plist
curl http://127.0.0.1:8787/healthz                     # {"ok":true}
```

Day to day:

```sh
sudo launchctl print system/local.colophon-home | grep -E 'state|pid|last exit'   # is it running
sudo launchctl kickstart -k system/local.colophon-home                          # restart
sudo launchctl bootout system/local.colophon-home                               # stop (until bootstrap)
sudo tail -n 50 /Library/Logs/ColophonHome/home.log                             # what it said
```

`bootout` stops the relay and unloads the job; nothing starts it again until the next
`bootstrap` (or the next start of the Mac, while the plist is in `/Library/LaunchDaemons`).

The log is not rotated by the relay. It is small for a personal home; to rotate it, add a file
to `/etc/newsyslog.d/` (`man newsyslog.conf`). *The plist above passes `plutil -lint`; installing
and running it was not tested in this exact form.*

## 7. Reaching it from the internet

Clients need `https://` at the origin you put in `provision.prefix`, and the relay speaks plain
HTTP on loopback. Put one of these in front of it, on the same Mac:

- **A Cloudflare tunnel** (`cloudflared`): no open port on your router. Its ingress rule sends
  your host name to `http://127.0.0.1:8787`. Cloudflare sets `CF-Connecting-IP` to the client's
  address, which is what the config above reads.
- **A reverse proxy** such as Caddy or nginx, with a port forwarded to it. Have it overwrite a
  header with the client's single address and read that one: in Caddy,
  `reverse_proxy 127.0.0.1:8787 { header_up X-Real-IP {remote_host} }`, and `"header":
  "X-Real-IP"` in the config.
- **Tailscale** (Serve for your own devices, Funnel for the internet) also terminates TLS and
  forwards to a local port.

Run the tunnel or proxy as its own service too, not in a logged-in Terminal window.
*None of these was set up while writing this page*; a Cloudflare tunnel in front of a home on
macOS has worked in practice.

Whichever you use:

- It must pass `Authorization`, `If-Match`, `If-None-Match` and `Content-Length`, and must not
  buffer or rechunk bodies: a request without `Content-Length` is refused with 411.
- **Client addresses.** Every request then comes from `127.0.0.1`, so without `clientAddress`
  every client shares one rate-limit bucket. With it, the relay reads `header` only from peers in
  `trustedPeers` (here the loopback addresses, where the tunnel or proxy connects from) and
  ignores it from anyone else. The header must hold one address: a list such as
  `X-Forwarded-For: a, b` counts against one shared bucket. The address is used for limits only,
  never for access.
- Check from outside: `curl https://home.example.org/healthz` answers `{"ok":true}`.

## 8. Keep the Mac on, and its clock right

The home signs times and judges other devices' times, so the Mac's clock must be right, and it
must be awake to answer.

- **Clock.** System Settings, General, Date & Time: turn on "Set time and date automatically".
  Check with `sntp time.apple.com` (the offset should be well under a second).
- **Sleep.** For a Mac mini, System Settings, Energy: turn on "Prevent automatic sleeping when
  the display is off" and "Start up automatically after a power failure". In Terminal:

  ```sh
  sudo pmset -a sleep 0 disksleep 0 autorestart 1
  pmset -g | grep -E ' sleep|disksleep|autorestart'
  ```

  A laptop is a poor home: it sleeps when closed and on battery.
- **Restarts.** macOS updates restart the Mac. The LaunchDaemon starts the home again at boot,
  before anyone logs in. With **FileVault** on, though, the disk stays locked after a restart
  until someone enters a password at the Mac, and the home does not start until then. For a
  restart you plan, `sudo fdesetup authrestart` unlocks once on the way back; after a power cut
  someone has to unlock it. Decide which you want: FileVault protects the key if the Mac is
  stolen.

*Untested while writing this page.*

## 9. Check it

After setup, and after every restore, move or update:

```sh
curl -s http://127.0.0.1:8787/healthz                  # {"ok":true}
curl -s https://home.example.org/healthz               # the same, from outside
# and the member ID check from step 4
```

The member ID must be the one you wrote down. Once a slot exists, `curl -s
https://home.example.org/v1/libraries/<slot>` shows it as `home.member` too. To list the slots
the door created:

```sh
sudo -u colophonhome sh -c 'cd /opt/colophon-home/current && /opt/homebrew/bin/bun server.js provisioned /opt/colophon-home/config.json'
```

## 10. Back up

**Copying files out of a running home is not a backup.** A change touches several files in
turn, and a copy made file by file takes each at a different moment; restored, it can make
clients start over, forget calls the home already took, or stop a slot from opening (see
[docker.md, "Back up, restore, update"](docker.md#back-up-restore-update)). Copy the home
while it is stopped, and copy all of it: the key, the config and the whole data directory, never
part of the data directory. Time Machine copies files while the home runs; do not count on it
as the home's backup.

```sh
sudo launchctl bootout system/local.colophon-home
sudo tar -czf ~/colophon-home-$(date +%Y%m%d%H%M%S).tar.gz -C /opt/colophon-home config.json secrets data
sudo launchctl bootstrap system /Library/LaunchDaemons/local.colophon-home.plist
curl -s http://127.0.0.1:8787/healthz
```

`sudo tar` keeps each file's owner and mode in the archive. The archive itself belongs to root;
`sudo chmod 600` it, or `sudo chown` it to your own user, before you move it. *Untested in this
form*; the same stop, copy, start order is what [docker.md](docker.md) describes.

The archive holds the private key. Encrypt it before it leaves the Mac (for example in an
encrypted disk image, or with `gpg --encrypt`), and keep more than one copy.

**Never run the same key in two places.** Two copies of a home with one key each sign heads
and receipts as that one home, from data that has drifted apart: the accounts that use it then
hold conflicting statements from their home. Do not
start a restored copy while the original still runs, and when you move a home to another
machine, stop the old one first and never start it again. A restored home is the home as it was
when the copy was made: what it took since is not in it.

To restore, with the service stopped, move the current `config.json`, `secrets` and `data`
aside, extract the archive into `/opt/colophon-home` keeping owners and modes (`sudo tar -xzpf
… -C /opt/colophon-home`), and make sure everything belongs to `colophonhome` (`sudo chown -R
colophonhome:staff …` on what you extracted). Remove `data/.relay.lock` and
`data/.relay.lock.reclaim` if they are in the copy, then start the service and check the member
ID (step 9).

## 11. Update and roll back

Read the release notes first. A home's state belongs to the format its module writes, and a
newer module may write state an older one cannot read.

1. Unpack the new bundle beside the old one, as in step 3 (do not change `current` yet).
2. Stop the home and take a backup (step 10), and keep that archive until you are happy with
   the new version.
3. Point `current` at the new release and start it:

   ```sh
   sudo -u colophonhome ln -sfn releases/colophon-home-<new version> /opt/colophon-home/current
   sudo launchctl bootstrap system /Library/LaunchDaemons/local.colophon-home.plist
   ```

4. Check it (step 9), and read the log. If the relay refuses to start, the log says why, and
   `KeepAlive` repeats the attempt every 10 seconds until you stop it.

**To roll back**, stop the home and point `current` at the previous release again. If the new
version had started and taken requests, also restore the backup from step 2, since its data may
already be in the new format; what happened since that backup is then lost. Never edit files in
the data directory by hand to make a version start.

## 12. If it does not start

- `sudo tail -n 50 /Library/Logs/ColophonHome/home.log` shows the relay's message: a setting it
  refuses names the setting.
- `Relay dataDir is locked (…/data/.relay.lock)`: another relay holds the data directory, or one
  stopped without removing its lock and its process ID now belongs to another process (it can
  happen after a power cut). Make sure no relay runs on it (`pgrep -lu colophonhome bun`); only
  then remove `data/.relay.lock` (and `.relay.lock.reclaim`) and start again.
- A slot that refuses to open (for example, a damaged line in its replay log) is not something to
  repair by hand. Restore the last good backup, and report it.

## 13. Uninstall

First take a final backup (step 10) if there is any chance you will want this home again. Then:

```sh
sudo launchctl bootout system/local.colophon-home
sudo rm /Library/LaunchDaemons/local.colophon-home.plist
sudo rm -r /Library/Logs/ColophonHome
```

Removing the folder deletes the key and every slot; then delete the user:

```sh
sudo rm -r /opt/colophon-home
sudo sysadminctl -deleteUser colophonhome
```

Accounts that appointed this home must appoint another before you delete its key: without the
key, nobody can sign as this home again. Remove the tunnel or proxy route for its host name as
well.

## What the operator can and cannot see

The same as in a container ([docker.md](docker.md#what-the-operator-can-and-cannot-see)): an
administrator of this Mac, or anyone who can act as the service user, sees slot names, sizes,
paths, timestamps, request patterns and the accounts' public authority history, and holds the
home's key. They cannot read records or forge an account's entries.
