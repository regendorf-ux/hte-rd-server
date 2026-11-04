# HTE Remote server

A self-hosted remote-desktop server and console for [RustDesk](https://rustdesk.com) clients: the ID server (`hbbs`),
the relay (`hbbr`) and a web console (`hte-console`), shipped as **one container image**, `ghcr.io/regendorf-ux/hte-rd-server`.

It is built on the ID/relay server of [RustDesk Server](https://github.com/rustdesk/rustdesk-server) by way of
[CortenDesk Server](https://github.com/marcpope/cortendesk-server), and its console reproduces, in Rust, the console of
[CortenDesk](https://github.com/marcpope/cortendesk), on the same database. Credits and licences: [`NOTICE`](NOTICE),
[`hte-console/NOTICE`](hte-console/NOTICE) and Settings > About in the console. The statement of modifications is
[`HTE.md`](HTE.md). Licence: GNU AGPL-3.0.

"HTE Remote" is the product's name on screen. Clients are stock RustDesk clients (or a custom build of one).

## What it does

**Access control**
- **Per-person reach.** Each console user sees and may *reach* only their own devices and the device groups granted to them
  or their user groups; administrators reach everything. The rule is enforced by `hbbs` where sessions start, not only shown
  in the console. A refused attempt raises an alarm (type 102); a device removed from someone's reach raises another (103).
- **Relay gate.** `hbbr` pairs only sessions `hbbs` admitted (upstream pairs anyone presenting the public key).
- **Per-computer passwords.** The console issues a password per device, rotates it on schedule and on demand, and hands it
  only to people who may reach that device (address book, web client).
- **Pending devices.** New devices wait for approval; signing in to a client approves and owns its device.

**Console**
- Devices, users, groups, user groups, strategies (client settings pushed to devices), roles, address books, logs
  (connections, file transfers, sign-ins, alarms, console audit), API tokens, diagnostics.
- **Shared address book / accessible devices** for signed-in clients: the "Accessible devices" tab and group tab.
- **Web client** in the browser, signed in with the console session, with the same reach rule and the device's password
  supplied without a prompt.
- **Sign-in**: OpenID Connect (Microsoft Entra ID, Okta, Keycloak, Google Workspace, …) and a local break-glass password,
  for the console and the RustDesk client. **Two-factor** (TOTP, recovery codes) and **e-mailed sign-in codes**, invitations
  and password reset over SMTP.
- **Admin API** (`/api/v1/*`, token-guarded) and `--assign` from the client command line.

**Operations**
- **Backups**: daily archives with retention tiers, restore from Settings, off-site copies to FTP(S) or S3.
- **Scheduled jobs**: reach and password sweeps, stale-session cleanup, log and invitation pruning, a diagnostics heartbeat.
- **Release check**: the sidebar says when a newer `hte-rd-server-v*` tag exists in this repository (once a day, public
  GitHub API, no token; switch off with `HTE_REMOTE_UPDATE_CHECK=0`).

### Differences from upstream

- From **CortenDesk Server** (inherited): signed-in RustDesk clients (1.4.1+) can connect (the server side of the secure
  signalling channel), and `hbbs` enforces a device policy pulled from the console.
- From **CortenDesk Server 1.2.0** (inherited, off here unless `HTE_REMOTE_WEBRTC=1`): WebRTC signalling for RustDesk 1.5 clients.
- Added here: per-person reach in `hbbs` (`src/hte_scope.rs`), the relay gate (`src/hte_relay_gate.rs`), and the console in
  Rust (`hte-console/`) in place of CortenDesk's console, all in one non-root container.
- Not carried over from CortenDesk's console: Apprise notifications, live page updates, the client downloads page.

## Requirements

- Docker with compose, amd64.
- A reverse proxy with TLS in front of the console (any; a Caddy example is below).
- Ports reachable by clients: `21115/tcp`, `21116/tcp+udp`, `21117/tcp`.
- **A database created by CortenDesk 1.15.** This image checks the schema at start and does not create a new one: run
  CortenDesk's image once on the data directory (or restore a backup made by CortenDesk or by this console), then switch the
  image. An existing CortenDesk installation moves over as is (same data directory, key pair and secret).

## Quick start (docker compose)

```yaml
# compose.yml
services:
  hte-remote:
    image: ghcr.io/regendorf-ux/hte-rd-server:2.0.0   # pin a digest in production
    container_name: hte-remote
    restart: unless-stopped
    user: "82:82"
    env_file: .env
    ports:
      - "21115:21115"
      - "21116:21116"
      - "21116:21116/udp"
      - "21117:21117"
    expose: ["8080", "21118", "21119"]   # console and WebSocket ports, for the reverse proxy only
    volumes:
      - ./data:/data                     # owned by 82:82; holds the database, .app_key, .server_secret, backups
      - ./rustdesk:/data/rustdesk        # hbbs's key pair and peer database
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    stop_grace_period: 45s
```

```dotenv
# .env
APP_URL=https://remote.example.com           # the public address; the relay address clients get derives from it
HTE_CONSOLE_PUBLIC_URL=https://remote.example.com
APP_NAME=HTE Remote
HTE_SIGNIN_DOMAIN=example.com                # optional: the e-mail domain the sign-in page names
TRUSTED_PROXIES=172.16.0.0/12                # the reverse proxy's address or network, as the container sees it (required for the web client, see below)
```

Reverse proxy (Caddy) — the console, and the web client's WebSocket bridge to `hbbs`/`hbbr`. Overwrite the forwarding headers
so a browser cannot choose the address `hbbs` sees:

```caddyfile
remote.example.com {
	handle /ws/id {
		reverse_proxy hte-remote:21118 {
			header_up X-Real-IP {client_ip}
			header_up X-Forwarded-For {client_ip}
		}
	}
	handle /ws/relay {
		reverse_proxy hte-remote:21119 {
			header_up X-Real-IP {client_ip}
			header_up X-Forwarded-For {client_ip}
		}
	}
	reverse_proxy hte-remote:8080
}
```

Then point clients at `remote.example.com` with the server's public key (Settings > Server shows it).

`docker exec hte-remote hte-console status` prints the state as `name=value` lines (schema, devices, scheduler, the ID server's
last policy pull, old setting names in use, the release check). Other commands: `hte-console version | migrate [--check] |
backup [--no-copy] | restore … | release-locks | db-copy <dest>`.

## Configuration

Settings live in the console (Settings) and in the database. The environment covers what must be known before the database is
read. The most used variables:

| Variable | Default | Meaning |
|---|---|---|
| `APP_URL` | (required) | Public address of the console; the ID and relay addresses given to clients derive from its host |
| `HTE_CONSOLE_PUBLIC_URL` | `APP_URL` | Origin for links and the OIDC redirect URI (never taken from the Host header) |
| `APP_NAME` | `HTE Remote` | Page titles, mail From name and subjects |
| `HTE_SIGNIN_DOMAIN` | empty | E-mail domain named on the sign-in page |
| `TRUSTED_PROXIES` | none for `hbbs`/`hbbr` (the console: private ranges) | Proxies whose `X-Forwarded-For` is believed (`hbbs`/`hbbr`: on the WebSocket ports only; `X-Real-IP` is not read). Set it to the reverse proxy's address, or every web-client user shows the proxy's address and shares its rate limits and block lists |
| `HTE_REMOTE_ID_SERVER` | `<APP_URL host>:21116` | ID server address given to clients |
| `HTE_REMOTE_RELAY_SERVER` | `<APP_URL host>:21117` | Relay address `hbbs` hands out |
| `HTE_REMOTE_SERVER_SECRET` | `/data/.server_secret` | Secret `hbbs` and the console share (generated once when missing) |
| `HTE_REMOTE_LOG_LEVEL` | `info` | `hbbs`/`hbbr` log level (`debug`, `info`, `warning`, `error`) |
| `HTE_CONSOLE_LOG` | `info` | The console's log filter (`RUST_LOG` syntax) |
| `HTE_REMOTE_OIDC_DISABLED` | off | Kill switch for single sign-on |
| `HTE_REMOTE_UPDATE_CHECK` | on | The sidebar's release check (`HTE_REMOTE_UPDATE_REPO` points it at another `owner/name`) |
| `HTE_REMOTE_ONLINE_WINDOW` | `60` | Seconds a device stays "online" after its last heartbeat (a setting overrides it) |
| `HTE_REMOTE_LOG_RETENTION_DAYS` | `365` | Log retention default (a setting overrides it) |
| `HTE_CONSOLE_SWEEPS` | all four (image) | Scheduled sweeps run here: `reach,passwords,stale,diagnostics` |
| `HTE_CONSOLE_JOBS` | all three (image) | Daily jobs run here: `backup,prune-logs,prune-invitations` |
| `HTE_CONSOLE_CACHE_PREFIX` | from `APP_NAME` | Cache key prefix in the database (keep it stable: scheduler locks use it) |
| `HTE_REMOTE_WEBRTC` | off | `1` passes RustDesk 1.5 WebRTC signalling; sessions it sets up bypass the relay (see `HTE.md`) |
| `HTE_RELAY_GATE_PORT` | `21120` (image) | Loopback port of the relay gate; unset turns the gate off |

Every `HTE_REMOTE_<X>` was `CORTENDESK_<X>` in CortenDesk. The old names are still read when the new one is unset, with a
warning per name; `hte-console status` lists any in use (`env_old_names=`). The full list, including tuning and test
variables: [`hte-console/README.md`](hte-console/README.md) and, for `hbbs`/`hbbr`, [`docs/environment-variables.md`](docs/environment-variables.md).

### Upgrading from the CortenDesk image

Same data directory, same key pair and secret, same ports. Stop CortenDesk, rename `CORTENDESK_*` to `HTE_REMOTE_*` in the
environment (optional: the old names keep working), start this image on the same `data/` and `rustdesk/` directories, and add the
`/ws/*` routes to the proxy. hte-console checks the 41 CortenDesk migrations at start and only adds tables of its own, so the
CortenDesk image can be started on the same data again. Backups made here are named `hte-remote-backup-<stamp>.tar` in
CortenDesk's format; rename one to `cortendesk-backup-<stamp>.tar` to restore it there.

## Building

```sh
cargo test --workspace
cross build --release --target x86_64-unknown-linux-musl            # hbbs, hbbr, cortendesk-utils
cross build --release -p hte-console --target x86_64-unknown-linux-musl
```

The image is built by `.github/workflows/hte-rd-server.yml` from `Dockerfile.hte`: push a git tag `hte-rd-server-v<x.y.z>`
equal to `hte-console/Cargo.toml`'s version (the job refuses anything else) and it publishes `hte-rd-server:<x.y.z>`, with the
upstream versions as image labels. Tags are never reused. `hte-console/` has its own tests and a replay harness that compares
its answers with the golden fixtures recorded from CortenDesk's console (`hte-console/fixtures/`).

## Licence

GNU Affero General Public License v3.0 ([`LICENSE`](LICENSE)), as for RustDesk Server, CortenDesk Server and CortenDesk. If you
run a modified version for others, offer them its source. Third-party assets in `hte-console/assets/vendor/` keep their own
licences (see `hte-console/NOTICE`). RustDesk is a trademark of its owners; this project is not affiliated with or endorsed by
the RustDesk project or CortenDesk.
