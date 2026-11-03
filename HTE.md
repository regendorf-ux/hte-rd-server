# HTE Remote server: statement of modifications

This repository is a modified version of [CortenDesk Server](https://github.com/marcpope/cortendesk-server), itself a modified
[rustdesk-server](https://github.com/rustdesk/rustdesk-server) (Purslane Ltd. and contributors). It adds `hte-console/`, a console
written in Rust that reproduces [CortenDesk](https://github.com/marcpope/cortendesk)'s previous console on the same database. All of it
is licensed under the GNU AGPL-3.0. This file lists the modifications and their dates, as section 5(a) of the licence asks;
upstream's own record stays in `CHANGES.md`, and the credits are in `NOTICE` and `hte-console/NOTICE`. Branch `hte` is upstream's
release tag plus the commits described here; changes to upstream files are small hooks marked `// HTE`.

## HTE Remote 2.0.0 (2026-10-25 / 2026-10-26): one image, its own name

- `Dockerfile.hte` (new) builds `ghcr.io/regendorf-ux/hte-rd-server:<x.y.z>`: `hbbs`, `hbbr` and `hte-console` under `supervisord`,
  uid 82, read-only root; nothing of the previous console's runtime is in it. `docker/hte/` (new): `supervisord.conf`, `entrypoint.sh`. `.github/workflows/hte-rd-server.yml`
  (new) builds it on the git tag `hte-rd-server-v<x.y.z>`, which must equal `hte-console/Cargo.toml`'s version; upstream versions
  are image labels.
- The name on screen is "HTE Remote" (`src/main.rs`, `src/common.rs`, `src/hbbr.rs`: `--help` texts); upstream is credited in
  Settings > About and the NOTICE files.
- Settings are `HTE_REMOTE_<X>` (were `CORTENDESK_<X>`); the old names are still read, with a warning (`src/policy.rs`,
  `hte-console/src/envvar.rs`, `docker/hte/entrypoint.sh`). hbbs's policy pull identifies as `hte-rd-server/<version>`.
- hte-console 2.0.0: serves the static files, checks the schema at start (`migrate.rs`), runs every scheduled job, its own
  release check (`update_check.rs`), backups named `hte-remote-backup-*`. Details: `hte-console/CHANGES.md`.
- 2026-10-26: the repository is `regendorf-ux/hte-rd-server` (was `hte-cortendesk-server`; GitHub redirects the old name).
- 2.0.1 (2026-10-26): public documentation rewritten without deployment details; the scripts and the separate image that ran
  beside the previous console removed; `hte-console/tests/naming.rs` guards both.

## hte-console 0.0.1 to 0.8.3 (2026-10-24 to 2026-10-25): the console in Rust, beside the previous console

## HTE Remote 2.2.0 (2026-11-02), the web client of CortenDesk 1.18

`hte-console/rdclient/` is now the web client build of CortenDesk 1.18.0 (AGPL-3.0, [marcpope/cortendesk](https://github.com/marcpope/cortendesk)), with the
same serve-time branding. New in the console: a Terminal action in the device list, `ice-servers` in strategies, and the web client's WebRTC
settings (off by default). The details are in `hte-console/CHANGES.md` (2.2.0). The image gets a new label, `com.hte.remote.upstream.cortendesk-webclient` 1.18.0; `...cortendesk` stays 1.15.0 (the console's pages and endpoints are CortenDesk 1.15's).

## HTE Remote 2.0.0 (2026-10-25), phase 9: one image, no PHP, its own name

`hte-console/` is new code, not a change to upstream files. It began as a shadow proxy in front of CortenDesk's console that recorded
sanitised fixtures (`hte-console/SANITISER.md`), then answered one group of routes after another on CortenDesk's console's SQLite file,
with no schema change: the device endpoints (0.1), the client's sign-in (0.2), the link with `hbbs` and the scheduled sweeps (0.3),
the signed-in client's endpoints and the web client (0.4), the admin API (0.5), backups and pruning (0.6), the console's pages
(0.7), and its own sign-in, session, two-factor, mail, invitations and password reset (0.8). Each step was compared with the previous console
console (replay tools since removed; the golden fixtures in `hte-console/fixtures/` remain as tests). Release by release: `hte-console/CHANGES.md`.

Upstream files touched for it: `Cargo.toml` (workspace member), `Cargo.lock` (the crate's dependencies; hbbs and hbbr are
unchanged by it), `.github/workflows/hte-console.yml` (new, the console's own image `ghcr.io/regendorf-ux/hte-console`, superseded
by `hte-rd-server`).

## 1.1.1-hte.3 (2026-10-25) on upstream 1.1.1

**The in-browser client's sessions pass the relay gate again.** The browser sends only a
`PunchHoleRequest`; the target picks the relay uuid and answers hbbs with a `RelayResponse` that
names itself (`id`), so that `RelayResponse` is the only place hbbs can admit the session. In
`src/rendezvous_server.rs` the `RelayResponse` arm replaces that `id` with the server-signed `pk`
(they are one protobuf oneof) before the gate asked who answered, so `target_answers` always saw an
empty id and never admitted the uuid; hbbr then refused the browser ("Relay gate: refused ...
not admitted by hbbs") and the client said "relay connection lost". The arm now keeps the id before
`set_pk` and asks about that. Desktop sessions were unaffected (they admit at `RequestRelay`). Test:
`tests/hte_webclient_relay.rs` (browser over WebSocket with a person's ticket, a fake target, real
hbbs and hbbr): an in-reach session pairs; out of reach, signed out, a made-up uuid, a refused uuid
and a forged `RelayResponse` do not. One line changed in `src/rendezvous_server.rs`, `Cargo.toml`
version.

## 1.1.1-hte.2 (2026-10-16) on upstream 1.1.1

**The relay pairs only sessions the ID server let through** (`src/hte_relay_gate.rs`, new). Upstream
hbbr pairs any two connections presenting the same uuid and the server key, and the key is public.
With `HTE_RELAY_GATE_PORT` set on both servers (same host), hbbs sends each uuid it hands out for an
admitted session to hbbr as a loopback datagram (`hte1 <uuid>`), and hbbr pairs a uuid only when
hbbs named it in the last two minutes (the second side waits up to 3 s for that word). hbbs names a
uuid on a `RequestRelay` it admitted, and on a `RelayResponse` from a registered, approved target
coming from the address that target registered from (`hte_scope::target_answers`). Off without the
variable. Hooks marked `// HTE`: `src/relay_server.rs` (listener start, the check at pairing),
`src/rendezvous_server.rs` (two `admit` calls), `src/hbbr.rs` and `src/lib.rs` (`mod`). Test:
`tests/hte_relay_gate.rs` (unknown, refused and admitted uuids against real hbbs and hbbr). The
address check assumes clients reach the server over one address family (the server's name has no
AAAA record).

`examples/hte_probe.rs`: asks a live hbbs whether a session may start, as a client would.

## 1.1.1-hte.1 (2026-10-16) on upstream 1.1.1

**Per-person reach, enforced where sessions start** (`src/hte_scope.rs`, new):

- The policy pulled from the console may carry a `scope` block: per console user, whether they
  are an administrator (`all`) or the device ids they may reach (`devices`), plus `token_users`
  (sha256 of a client access token -> user id). While `scope.enforce` is true, `check_initiator`
  refuses a punch-hole or relay request whose target is outside the sender's set. The sender is the
  person `policy.rs` already identifies: the web-client ticket's subject (`web-<user id>`), the
  access token, or nobody (found by IP only, which is refused under enforcement).
- Refusal texts: "You are not given access to this device. Ask your administrator to add it to
  your scope." and, for nobody signed in, "Sign in to the console with your account to start
  sessions…".
- Refusals are posted to the console as `POST /api/server/refusals` (`{refusals: [{user_id,
  user_name, from, to, ip, reason, at}]}`), one per person, origin device and target per minute,
  kept for the next round when the console does not answer.
- The `policy` admin command's line ends with ` scope=on|off people=N`.

Hooks in upstream files, each marked `// HTE`: `src/policy.rs` (the `scope` field of `Snapshot`,
four calls in `check_initiator`, the summary in `install`/`describe`, one report call in the loop),
`src/lib.rs` (`mod hte_scope`), `Cargo.toml` (version `1.1.1-hte.1`).

Tests: unit tests in `src/hte_scope.rs`; end to end in `tests/hte_scope.rs` (real hbbs, fake
console). Everything upstream ships still passes.

Build: `.github/workflows/hte-image.yml` (push a tag `v<upstream>-hte.<n>` or run it by hand)
published the plain hbbs/hbbr image `ghcr.io/regendorf-ux/hte-cortendesk-server:<upstream>-hte.<n>`, amd64 (superseded by `hte-rd-server`).

## Rebuilding on a new upstream release

```
git fetch upstream --tags                # upstream = marcpope/cortendesk-server
git checkout hte && git rebase v<new>    # resolve: the hooks above are small and marked // HTE
# bump Cargo.toml (hbbs) to <new>-hte.<n> and hte-console/Cargo.toml to the next HTE Remote version; add a section here
cargo test --workspace
git push --force-with-lease <remote> hte && git tag hte-rd-server-v<x.y.z> && git push <remote> hte-rd-server-v<x.y.z>
```
