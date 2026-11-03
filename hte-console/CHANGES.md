# hte-console changes

New HTE code (AGPL-3.0), not a change to upstream. The fork-level statement is `../HTE.md`.

## 2.2.0 (2026-11-02): the web client of CortenDesk 1.18 (Terminal, 30 fps, keyboards, 2FA, WebRTC)
Ports what CortenDesk 1.16.0 to 1.18.0 changed in the browser client and its console side; the bundle in `rdclient/` is the upstream 1.18.0 build
(AGPL-3.0, notices kept), served with the same listed branding substitutions as before (one more: the terminal window's title).
- Terminal: a Terminal action beside Connect in the device list (table and compact list) and on the device page, for every computer except
  Android and iOS. It opens `/webclient?id=<id>&mode=terminal`, the bundle's terminal page, in its own window with its own sign-in. It is the same
  page, so the same rules apply as for Connect: the list of computers is the person's reach, `POST /webclient/credential` hands over a computer's
  password only for a computer in reach and the password box starts collapsed. Needs RustDesk 1.4.1 or later on the computer.
- Web client fixes (bundle): up to 30 frames per second (was about 10); non-US keyboard layouts (one æøå, € or £, map mode on Windows and Linux
  computers, Keyboard menu entry to go back to translated characters); file transfer, terminal and camera windows on RustDesk 1.5 no longer fail with
  "Wrong password" once the computer's one-time password rotated; a 2FA code is asked for in desktop and terminal sessions. The password
  box's toggle hides while the 2FA code is asked for.
- WebRTC in the web client: to a RustDesk 1.5 computer the page offers WebRTC beside the relay and the relay stays the fallback; Session > Details
  shows the transport. Settings > Server: "Web client uses WebRTC" (**off by default**, unlike CortenDesk) and "Web client ICE servers"
  (`stun:host:3478, turn://user:password@host:3478`; `src/ice.rs`, the same rules as CortenDesk's: an entry the client would silently skip, such as a
  TURN server without credentials, is refused). Strategies: new Network group with the `ice-servers` option, stored in canonical form.
  A direct WebRTC session does not pass the relay, so the relay's own check never sees it; the ID server still judges the offer against per-person
  reach and needs its own switch (`HTE_REMOTE_WEBRTC=1`), and the page only gets a computer's password for a computer in reach.
  Without a STUN server of its own the browser uses public ones (Cloudflare, Google); everyone who opens the web client receives the TURN password.
- No migration, no change to the 41 migrations or the schema. Not ported (not asked): the eleven languages, the ID whitelist, "new devices are
  incoming only", SSO callback notes.

## 2.0.1 (2026-10-26): the repository's new name, public docs, nothing of the previous console's runtime
- The repository is `regendorf-ux/hte-rd-server`: the release check, the About link and the image labels use it (GitHub redirects the old name,
  so 2.0.0's check keeps working).
- Screens and messages: the sign-in card and footer name the product only; the "not offered" page, a strategy hint, log and error texts say
  "the previous console" where they explained behaviour by the PHP console.
- Removed: the replay scripts that started the previous console's image, the fixture generators, the asset and migration sync scripts,
  the separate hte-console image (`Dockerfile`, `.github/workflows/hte-console.yml`). The golden fixtures and every test stay.
- `pagereplay.rs` no longer talks to the previous console: no update calls, no capture or saved answers; it compares two hte-console instances
  (pages, dialogs, downloads) and posts forms to the candidate. `webreplay.rs` stays a two-instance comparison.
- Comments, templates, CSS/JS and SQL headers describe formats inherited from the previous console instead of PHP; the compatibility
  modules (`php.rs`, `laravel.rs`) and the scheduler's lock-name format are unchanged.
- `tests/naming.rs`: no company, person, private host, e-mail address or tenant id in the repository (private names checked by digest),
  and no mention of the previous console's runtime outside the compatibility code. `tests/phpfree.rs` is `tests/standalone.rs`.

## 2.0.0 (2026-10-25): phase 9, HTE Remote's own console in the PHP-free image
Version 2.0.0 is HTE Remote's version from now on: the version of the image `ghcr.io/regendorf-ux/hte-rd-server` (git tag `hte-rd-server-v2.0.0`).
(0.9.0 was this release before the rename and was never tagged.) Includes 0.8.2/0.8.3 (two-factor, e-mailed codes, mail, invitations, password
reset), with the authenticator issuer "HTE Remote" (was CortenDesk; existing codes unaffected) and the recovery codes file `hte-remote-recovery-codes.txt`.
`tests/naming.rs` fails on any old name a person could read, a `CORTENDESK_` setting read around `envvar`, or a page showing `api_version` as its version.
- One image with hbbs, hbbr and hte-console (`Dockerfile.hte`); hte-console serves `/assets/*`, `/rdclient/*`, `/robots.txt` and `/favicon.ico`
  itself (`tests/phpfree.rs`: every embedded asset, health, sign-in and 404s with no upstream).
- `migrate.rs`: `HTE_CONSOLE_MIGRATE=1` (set in the image) checks that the 41 migrations of the archived PHP console are recorded in `migrations`
  and refuses an empty or older database; applies its own additive idempotent migrations (first: `hte_console_sessions`), batch = max+1.
- `maintenance.rs`: `HTE_CONSOLE_SNOOZE_PRUNE=1` prunes expired presence snoozes every minute; `status` (now with `env_old_names`, `update_check`,
  `update_latest`) and `release-locks` helpers.
- Subcommands: `version`, `migrate [--check]`, `status`, `release-locks`, `db-copy <dest>` (online copy, refuses to overwrite).
- The name: "HTE Remote" wherever a person reads it (the `APP_NAME` fallback, backup and FTP messages, Diagnostics, the web client's fallback name,
  Settings' link and Apprise notes); Settings > About shows HTE Remote's version, the client API level and the "Based on CortenDesk and RustDesk
  Server" credit. `assets/css/hte-remote.css` and `assets/js/hte-remote.js` (were `cortendesk.*`), the web client window `hte-remote-webclient`,
  the diagnostics download `hte-remote-diagnostics.json`. New `NOTICE`.
- `update_check.rs`: once a day, the newest `hte-rd-server-v<x.y.z>` tag of `regendorf-ux/hte-rd-server` (public GitHub API, no token),
  cached as `hte_remote.latest_version`; the sidebar line is "HTE Remote console", plus "update available: x.y.z" when newer. PHP's
  `cortendesk.latest_version` is no longer read. `HTE_REMOTE_UPDATE_CHECK` (old: `CORTENDESK_UPDATE_CHECK`), `HTE_REMOTE_UPDATE_REPO`.
- `envvar.rs`: every `CORTENDESK_<X>` setting is read as `HTE_REMOTE_<X>`, falling back to the old name (unset or empty new name) with one
  warning per old name.
- Backups: new archives are `hte-remote-backup-<stamp>.tar` (format and manifest unchanged); list, remote copy, retention and restore accept
  `cortendesk-backup-*` too.
- The image defaults: SIGNIN=1, LARAVEL_SESSIONS=0, PHP_SESSION_BRIDGE=0, SWEEPS=reach,passwords,stale,diagnostics, JOBS=backup,prune-logs,prune-invitations.
  `HTE_CONSOLE_UPSTREAM` is not set: nothing is forwarded to PHP any more.

## 0.8.3 (2026-10-25): 0.8.2 as it should have been tagged
- The test e-mail's template was named `templates/mail/test.html`, which the repository's `.gitignore` (`test.*`) left out of the commit:
  0.8.2's CI failed (Send test email had no template) and no 0.8.2 image exists. Renamed `test-message.html`. Nothing else changed.

## 0.8.2 (2026-10-25): no console page left on PHP: two-factor, invitations, password reset, e-mailed codes, mail
- **Mail** (`mail.rs`): PHP's `MailSettings` and Symfony's SMTP transport: TLS from the start (`ssl`) or STARTTLS whenever offered,
  the certificate checked against the public roots (webpki-roots), AUTH LOGIN/PLAIN, 10-second timeouts, text/html quoted-printable;
  the health record (`smtp_ok_at`, `smtp_failed_at`, `smtp_last_error`). Mail templates `templates/mail/` (PHP's). Settings → Email's
  **Send test email** works (`/settings/mail-test`, `settings.mail-test` audit row).
- **Two-factor** (`pages/twofactor.rs`, `pages/challenge.rs`): Account → Two-Factor Authentication (enrol with a QR code via qrcodegen,
  recovery codes shown once, regenerate, disable; refused while required) and the sign-in challenge `/login/2fa` (TOTP with the replay
  guard, recovery codes burnt atomically, 5 tries a minute + alarm). Required-but-not-enrolled people are sent to enrol (the gate's
  `RequireTwoFactor`), as PHP. Deliberate difference: the candidate secret travels in an encrypted, account-bound form field, not the session.
- **E-mailed sign-in codes**: `/login/email` (+ resend), trusted browsers (`cd_device`, `trusted_devices`), a broken relay lets only
  someone who can repair it in (`mail_repair` → Settings → Email until it works), `RequireEmailAddress`. The RustDesk client's code step
  (phase 2) now mails its code too.
- **Password reset**: `/forgot-password`, `/reset-password/{token}` (only with mail on), neutral answers, one live link, the link burnt
  before the change, every session and client token revoked, `login_logs` note `password reset`; "Forgot password?" on the sign-in page.
- **Invitations**: the card at the end of Users (invite, resend, revoke, the link shown once and mailed when mail is on; delegated
  managers clamped) and `/invite/{token}` (the account created from the row, signed in, `login_logs` note `invitation`, audit rows).
  `/invitations` goes to Users. The page replay now compares the whole Users page (the card was "by design" before).
- The gate answers `RequireTwoFactor` / `RequireEmailAddress` / `RequireMailHealthy` itself (no forwarding to PHP).
- hte-console's own `hte-*` CSS/JS are revalidated on every load (a cached older copy hid the row-action button styles).
- Sign-in replay: the two-factor challenge (password step, page, wrong code, right code) is compared with PHP too.
- Independent review: one high, fixed: the unauthenticated "Forgot password?" post sent its mail while holding the
  database lock (a dead relay could stall the device API); the reset mail now goes after the answer, outside the lock (which also
  hides whether the account exists by timing). Medium, fixed (hardened beyond PHP): "starttls" now requires TLS; a relay that does not
  offer it gets nothing ("none" stays opportunistic). Lows fixed: no username in the stored SMTP error, a 4 KiB bound on a relay reply
  line, the enrolment blob expires after 15 minutes. Left (need a valid password or an administrator): the e-mailed code steps and the
  test mail still send under the lock, bounded by the 10 s timeouts.
- Tests: `tests/console_steps.rs` (6, with a fake SMTP relay), `mail` and `challenge`/`twofactor` unit tests.

## 0.8.1 (2026-10-25): what the 0.8.0 replay against PHP showed
- Pages (7a/7b/7c): 164 requests, 0 differences. Sign-in: 100 steps, one difference: a POST /logout with no session and no token
  was answered 302 (to the sign-in page); PHP's CSRF check runs before `auth` and answers 419. Now the same order.
- The sign-in replay leaves out the two token kinds phase 2 hardened (no `exp`, several audiences without `azp`): PHP signs those
  in, so their `login_logs` rows could never match; tests cover them. `replay-pages.sh` leaves `hte_console_sessions` out of its
  database comparison (only hte-console creates it).

## 0.8.0 (2026-10-25): phase 8, the console's own sign-in and session cookie (and all of 0.7.19, phase 7c)
- One image for 7c and 8: phase 7c's branch is merged in (Diagnostics, Roles, health routes, below). Phase 7c's scripts accept 0.8.x.
- New modules `pages/websession.rs` (hte-console's own session: cookie `__Host-hte-remote` over https, a random 40-character id,
  only its sha256 in the new table `hte_console_sessions`, idle 60 min / absolute 12 h, rotated at sign-in, revoked when the
  account's `remember_token` rotates or the account is disabled) and `pages/login.rs` (`/login` with the break-glass password,
  `/login/oidc` and its callback for Microsoft sign-in, `/logout`; the 2FA/e-mail steps redirect to `/login`, password reset and
  invitations say "not available"). Templates `auth/guest.html`, `auth/login.html`, `auth/unavailable.html` (PHP's HTE views).
- Switched by `HTE_CONSOLE_SIGNIN=1` (off by default: an upgrade alone changes nothing). The bridge
  (`HTE_CONSOLE_PHP_SESSION_BRIDGE`, on) mints PHP's session beside ours so PHP's remaining pages keep working;
  `HTE_CONSOLE_LARAVEL_SESSIONS` (on) keeps accepting sessions PHP signed in until phase 9.
- The page gate reads our session first; without one it sends the person to our sign-in page (remembering the page) when the
  switch is on. `finish()` re-sends PHP's bridged cookie with ours.
- `hte_console_sessions` is skipped by backups and restores like `sessions`.
- Replay: `replay/replay-signin-web.sh` and `hte-console web-signin-replay` / `web-signin-seed` (the scenario against PHP, rows
  compared, mutation check). Never run against PHP yet.
- Independent review: no critical or high finding. Fixed: with `SESSION_SECURE_COOKIE=true` no sign-in completes
  over plain http (medium); guest rows only for GET, 600 a minute per address (was 60, a NAT could lock itself out); `?code[]=` is a
  refusal, not a 500; a first remember token no longer ends the account's other sessions. Left: unthrottled failed-callback log rows
  (as PHP), `X-Forwarded-Proto: https` trusted from any peer (phase 2's `request_root`; setting `HTE_CONSOLE_PUBLIC_URL` overrides it).
- Tests: `tests/console_signin.rs` (20), `websession` unit tests (5).
- The fake identity provider advertises an `end_session_endpoint` (logout through the provider).
- CI: docker/setup-buildx-action v4, docker/login-action v4, docker/build-push-action v7 (Node 24; checked by the next tag's run only).

## 0.7.19 (2026-10-25): phase 7c, the console pages that still ran on PHP
- **Fleet diagnostics** (`/diagnostics`, `/diagnostics/export`): PHP's `FleetDiagnostics` report and page, the same queries, text and
  classes; the sanitised JSON download with PHP's pretty print. The scheduler card reads the heartbeat hte-console's own
  `diagnostics` sweep writes; the ID server link card reads the pull marker hte-console's policy endpoint leaves; the ID and
  relay TCP probes (one second each) run side by side, so the page holds the database lock for at most about a second.
- **Roles** (`/roles`, `/roles/save`, `/roles/delete`): list, create, edit, delete as `RoleList`: super-admin only (a redirect
  with "That section is restricted to administrators." for the page, 403 for a write), the same validation and messages, the
  matrix normalised and stored as Eloquent's `array` cast stores it, `role.create`/`role.update`/`role.delete` audit rows with
  PHP's summaries; a deleted role's holders fall back to the standard-user baseline. The pages 7b ported already read the
  same column the same way (`Ctx::allows`). The dialog's desktop radios and phone selects send only the set on screen.
- **Health**: `/health/live`, `/health/ready` (database, ID server, every relay; 503 when not ready), `/up` (Laravel's page
  without its external font and script).
- Not ported: `/downloads`, `/downloads/{id}`, `/storage/*` answer 404; `/client-downloads` and `/setup`
  keep the "not available yet" page. PHP's own backup link `/settings/backups/{name}` leads to `/settings/backups/download?name=`.
- Replay: Diagnostics, its JSON (clock and probe latency masked), Roles and the health JSON for every person; the New/Edit
  Role dialogs; writes: create a role, a taken name, edit, delete a role someone holds. The seed adds an ID and a relay
  server that refuse at once on both sides.
- From the independent review: `/health/ready` reads its targets under the database lock and probes after releasing it;
  `/health/live` and `/health/ready` have PHP's global limits (120 and 30 a minute, 429 with `Retry-After: 60`). A backup
  download now writes PHP's `backup.download` audit row (missing since 7b).
- `compare-local.sh`: a page read back from a capture may differ from PHP's by one second of clock ("43s" / "42s"); that is not reported. Only the local, read-back comparison does this.

## 0.7.18 (2026-10-25): what the 0.7.17 replay still showed; PHP's answers kept for a comparison without PHP
- The replay keeps PHP's answer to every page and dialog of run A, with the starting database, the throwaway app key and the
  moment, in `/tmp/hte-replay-capture.tgz` on the server (`HTE_REPLAY_CAPTURE` to put it elsewhere; placeholder data only).
  `replay/compare-local.sh <that file>` then compares a local build with them on a Mac, no PHP and no image build: the
  pages and dialogs exactly as run A compares them (same code: `page-replay` with `HTE_PAGEREPLAY_PHP_FROM`). The local
  console runs on the captured clock (`HTE_CONSOLE_CLOCK_START`, and each page at the second PHP answered it, via a header
  honoured only while that clock is set), so "N minutes ago" and dates read alike. CSV exports, writes and databases still
  need a live run.
Three differences, two causes: "Stored in <directory>." was empty on the Settings tabs that are not Backups (PHP prints it always); and PHP's "Uploading…" line under the file field (a Livewire loading `<div>`) was compared (the replay now ignores loading `<div>`s as it ignores loading `<span>`s).

## 0.7.17 (2026-10-25): the rest of the 0.7.15 dialog list, and the Backups tab
The 0.7.16 replay showed no new differences; it showed what 0.7.16 had not yet done from the 0.7.15 list.
- Strategy assign: a device is its id with the alias or hostname under it (no dash), "N selected" under the list, "No devices match."; Compliance: "No devices in this state.".
- Settings > Backups: PHP's markup (toolbar, desktop table and mobile cards), "Stored in <dir>.", the Schedule card ("Automatic backups", "Runs every day at 03:30 server time. On by default.", and the keep-tier explanation with the current numbers).
- Replay: the Users add/edit helper lines ("Ignored for an administrator." / "Not used for an administrator.", ours only, an improvement) are counted once under "by design".
- Ported, so that nothing is left out of Settings > Backups: **Restore from a file** (upload an archive: checked, stored like any backup, restored; the form carries multipart, so request bodies of `multipart/form-data` now fill the input like urlencoded ones; the upload limit is 256 MiB, `HTE_CONSOLE_UPLOAD_MAX_BYTES`) and the **Off-site copy** (None / FTP-FTPS / S3-compatible, with its validation messages, write-only passwords stored encrypted, Test connection, and the mirror after each run: new archive up, pruned or deleted archives down, one copy at a time by a lock file). Deleting an archive in Settings also removes its off-site copy. New modules `backup_remote` (the interface, the mirror), `backup_s3` (SigV4) and `backup_ftp` (passive and active mode, explicit FTPS, certificate not verified as PHP); `cortendesk:backup --no-copy` is honoured.

## 0.7.16 (2026-10-25): the strategies dialogs say what PHP's say
From the 0.7.15 dialog comparison. Our own extra helper lines stay (improvements); what PHP says and we did not is now there.
- Strategy editor: required star on Name, "Change note (kept in the revision history)" after Note (placeholder "What changed and why"), the help line under Enabled / Default / Enforce and the timeout, the "Not managed" alert, and `key — help` under every option.
- Review (save / delete / restore): "Nothing has been changed yet.", the delete and restore alerts, "N device(s) will receive a different effective strategy or policy.", High-impact controls, the reset list, one "Policy diff" table, the "Affected-device sample (up to 50)" and a Back button.
- Assign: `Assign "Name"` heading, the precedence explanation, tab counts as badges. History and Compliance: PHP's titles and subtitles.
- Settings: the two disabled buttons no longer carry hidden "Contacting provider…" / "Sending…" text.
- Not ported, for a reason: Settings > Backups "Restore from a file" (upload) and the off-site FTP/S3 copy.

## 0.7.15 (2026-10-25): the dialog comparison, made fair
From the first run that opened the dialogs (0.7.14): its report was dominated by noise, none of it in the console.
- A dialog opened over another (PHP's delete review sits over the edit form) is now taken as the one in front, not the one behind.
- Text that PHP shows only while a Livewire call runs (`wire:loading` spans: "Saving…", "Calculating…") is not compared, on any page.
- Dialogs are compared by what they say and offer (text); their CSS classes are not (listed once as "by design").

## 0.7.14 (2026-10-25): the replay opens the dialogs; Add/Edit Device answered 500
- `page-replay` opens 16 dialogs on both sides (PHP by a Livewire call, hte-console by its query) and compares them like pages: strategies add/edit/assign/
  history/compliance/delete, users add/edit/devices, groups add (both kinds)/edit, devices add/delete, device edit/delete.
- Found by the new check, and fixed: **Add Device and Edit Device (`/devices?create=1`, `?edit=N`, and on the device page) answered 500**: the dialog's
  template reads `errors.rustdesk_id` and a dialog opened without an error had no such key (strict undefined). Only the re-opened dialog after a failed save
  worked. A test (`the_dialogs_the_replay_opens`) now opens all 16.
- Includes 0.7.12 (Settings option-group wrappers, no extra prune note, About card out of the comparison) and 0.7.13 (every difference of a page is listed).

## 0.7.13 (2026-10-25): the replay lists every difference of a page, not the first
- `page-replay` compares the text and the class sequence with a longest-common-subsequence walk and prints each place that differs (what PHP has that
  hte-console lacks, what hte-console has extra, with context; 25 places per page and kind at most), so one run shows everything left on a page.
  No change to the console itself.

## 0.7.12 (2026-10-25): the last two differences of the live replay of 0.7.11 (both on Settings -> Maintenance / Notifications)
- The option-group wrappers (Apprise scope pickers, snooze target) carry a `class` only when hidden, so the one in force has no empty `class=""`.
- Removed the extra "Pruning also runs nightly..." note under Prune now (the confirm dialog already says it saves the retention first).
- The replay leaves the About card out (PHP lists Laravel and PHP versions, hte-console its own) and lists it with the other by-design Settings item.

## 0.7.11 (2026-10-25): the last two differences of the live replay of 0.7.10 (131 requests, 2 differences, B equal, C caught)
- Both were Settings -> Notifications: hte-console ships both Apprise delivery-mode groups (the other one hidden with `d-none`, switched by a click handler,
  no server round trip) while PHP renders only the one in force. Kept as an improvement; the replay now leaves hidden `data-rd-group` blocks out of both sides
  and lists that as "by design". Strategy history: PHP's empty text and restore button.

## 0.7.10 (2026-10-25): the ten differences left in the live replay of 0.7.9
The 0.7.9 run (131 requests) went from 36 to 10 differences, section B was equal (214 lines: the API token step now matches), C caught the mutation. Fixed:
- Every POST control that stands where PHP has a link (Disconnect on the Dashboard, tag remove on the device page and in address books, Approve/Reject/Restore/Destroy,
  address-book Remove, phone-list icon buttons) is a class-free inline form around a button with PHP's exact classes; no `d-inline`, `d-contents` or `btn btn-link`.
  The replay reports only the first difference per page, so all such places were fixed, not just the ones named.
- User detail: the device platform icon carries `fs-18 align-middle` like PHP's component.
- Settings: "Test Connection" and "Send test email" (not ported, disabled) now have PHP's markup and text; "not available" moved to the button's tooltip.

## 0.7.9 (2026-10-25): the markup differences the live replay of 0.7.8 found (36), and the replay itself
Fixes (the replay compares what a person reads and the CSS class sequence of every page with PHP's):
- Dashboard (`/`): no extra "Dashboard" breadcrumb item (PHP shows none on this page).
- `/dashboard/stats` and `/dashboard/sessions` stay: they are the htmx refresh URLs of the two cards (PHP polls through Livewire, which has no URL); they
  answer under the same permission and reach rules as the page. The replay lists them as "by design".
- Devices list: the two hidden forms use the `hidden` attribute, so no extra `d-none` elements among the status chips.
- Device and user detail: the "Back to Devices" / "Back to Users" link before the card; the sidebar no longer marks Devices/Users on a detail page.
- Users and Groups row actions: buttons for the POST actions carry exactly PHP's link classes (`rd-act me-2`, `text-warning me-2`, `text-danger`), the forms
  are inline and class-free, and `hte-pages.css` draws them like the links beside them.
- Address books: no `flex-grow-1` on the narrow-screen book select's form (the CSS keeps it wide).
- Strategies: PHP's subtitle ("Client settings pushed to devices on their next heartbeat."), the "No default strategy" notice in a toolbar, the `d-none d-md-block`
  table with `rd-cell-title d-inline`, `text-muted d-block`, icon counts, an Enabled switch with its hidden label, the action order and classes, the
  empty state, and the phone card list (`d-md-none rd-cardlist`).
- Settings -> Security: the API Tokens card is PHP's (header with `rd-card-sub` and an `rd-card-actions` New Token button, responsive table, phone card
  list), shared with `/api-tokens` as one partial; shown only to people who may read tokens.
Replay:
- The PHP half of the API token step now drives the real Livewire component inside Settings (PHP has no `/api-tokens` page), so the token comparison applies.
- The report separates "by design: ..." (the htmx fragments; the Invitations card at the end of Users, left out of both sides) from "DIFFERENCE: ...".
- `replay-pages.sh` no longer stops when the database diff fails (a `diff | head` under `pipefail`): sections B and C and the final line always run.

## 0.7.8 (2026-10-25): phase 7b, Settings Backups, Prune now, API tokens, the replay's writes
- Settings -> Backups (local only: list, Back up now, download, delete, restore from a stored archive, schedule and retention) and
  Maintenance -> Prune now, on the phase 6 code. API tokens is a real page (`/api-tokens`: create, shown once, revoke).
  Still not ported: the connection/mail/Apprise test buttons, the off-site FTP/S3 settings, restore from an upload.
- `page-replay` now carries the writes of the new pages (PHP through Livewire, hte-console through its forms; `HTE_PAGEREPLAY_RUST_ONLY=1`
  runs hte-console's half alone); `snapshot` masks token hash/prefix with `HTE_SNAPSHOT_MASK_TOKENS=1`; the seed gains a pending computer.
- Web client: "Your computers" (`GET /webclient/devices`, the live reach rule) above a secondary ID field; `POST /webclient/credential` now answers for any computer in reach with a confirmed password (`hte_device_passwords`), no address-book entry needed.
- `Reply::Bytes` (a stored file as it is); the demo server's login takes `?to=` and `?theme=`.

## 0.7.7 (2026-10-25): phase 7b, the rest of the console's pages
- Pages: Dashboard (stat cards and sessions refreshing every 15 s, connection and platform charts, versions, alerts, Disconnect), Devices
  (list, filters, sort, columns, bulk, edit, approve/reject, groups, address books, detail page), Users (list, editor, assign devices, actions,
  person page), Groups, Address books (books, tags, entries, sharing rules), Strategies (editor with impact review, assign, history/restore,
  compliance), Settings (eight tabs; secrets are encrypted like Laravel's and never shown back; relay pool; presence snoozes).
- "Not available yet" pages for Roles, Invitations, Client downloads and Setup (not routed by default; PHP keeps them).
  (0.7.8 adds Prune now, the Backups tab and the API tokens page.)
- `page-seed` and `page-replay` cover the new pages' reads; the writes are covered by the integration tests (`tests/pages7b.rs`) only.
- CI: actions/checkout v7, upload-artifact v7, download-artifact v8 (Node 24 majors; were v4). Verified only by the next tag's CI run.
- The reverse proxy moved the pages one at a time.

## 0.7.6 (2026-10-25): the sidebar and top bar follow the theme (they were dark in both; PHP has the same fault), and the sidebar's HTE mark is no longer squashed (new css/hte-pages.css, which scripts/sync-assets.sh leaves alone)

## 0.7.5 (2026-10-25): an invalid theme answers 422 with the messages again (a documented, deliberate difference from PHP's redirect back); the replay expects exactly that

## 0.7.4 (2026-10-25): an invalid theme is Laravel's redirect back (PHP renders JSON errors for /api/* only), found by the second real-PHP replay; the replay treats http://host and http://host/ as one place

## 0.7.3 (2026-10-25): first real-PHP replay findings: Laravel's hasPages() (a page past the end keeps its pager) and empty first/last item in the pager; the replay fetches PHP's CSVs through Livewire's export call, asks for JSON on the theme calls, and turns the release check off on both sides

## 0.7.2 (2026-10-25): page-replay uses only the path of Livewire's announced update address, and reports an error part way together with the differences found before it

## 0.7.1 (2026-10-25): page-replay finds Livewire 4's hashed update address (`data-update-uri`); replay-pages.sh hands the copy to uid 82 and reads WAL databases writable

## 0.7.0 (2026-10-25): phase 7a, the page layer (sessions, CSRF, templates, htmx) and the first pages
- Reads PHP's session: the `hte-remote-session` cookie decrypted with `/data/.app_key`, the `sessions` table (PHP must run
  `SESSION_DRIVER=database`). A request without a valid session is forwarded to PHP, never served.
- CSRF compatible with Livewire and plain forms (`_token`, `X-CSRF-TOKEN`, `X-XSRF-TOKEN`, `Sec-Fetch-Site`); flashes with
  Laravel's one-request lifetime; `console-can` redirect.
- minijinja templates and the CSS/JS/images (HTE brand included) embedded in the binary; htmx 2.0.4 vendored, no CDN.
- Pages: Account (profile, password, theme; the 2FA card is read-only and links to PHP), Logs: Connections, File Transfers,
  Alarms, Logins, Console (filters, paging, CSV). Dashboard NOT ported.
- `page-seed` / `page-replay` (reads and writes against real PHP, databases compared), `replay/replay-pages.sh`,
  `examples/pages_demo.rs` (screenshots on synthetic data). `HTE_CONSOLE_PAGES=0` turns the pages off.
- Not routed by default: the reverse proxy sends a page here when it is switched over.

## 0.6.0 (2026-10-25): phase 6, local backups, restore, pruning and the daily scheduler entries
  Review (read-only) fixes: the archive is created 0600 from the start; the schema version is read before the
  restore's copy; staged server files are copied aside first and old `*.restore` files dropped, and a failure after the
  database commit says so ("The database WAS restored..."); a tar entry larger than the file is refused.
  Known, left on purpose: a stop during a running backup leaves the `cortendesk:backup` cache lock until its 3600 s expiry
  (and `panic = abort` skips the guard); the once-per-day check is read before the lock, so two `--scheduled` runs within
  the same second could both back up; no cap on the decompressed size of a restore (PHP has none either); an
  undecryptable value is carried over unchanged on re-keying.


Built on top of 0.4.1 (phase 5, the admin API, is built in parallel and is not in this version).

- `backup`, `backups`, `restore`, `prune-logs`, `prune-invitations` on the command line, and the three daily entries of
  PHP's schedule as scheduler jobs (`HTE_CONSOLE_JOBS`, none by default): `cortendesk:backup --scheduled` (03:30 UTC),
  `cortendesk:prune-logs` (04:10), `cortendesk:prune-invitations` (04:20). Ported from `BackupService`, `Backup`,
  `Restore`, `PruneLogs`, `PruneInvitations` of 1.15.0-hte.1 (`src/backup.rs`, `src/prune.rs`, `src/housekeeping.rs`,
  `src/tarfile.rs`).
- The archive is PHP's, byte layout and all: a plain tar of `manifest.json`, `db/<table>.ndjson.gz` and
  `files/{app_key,server_secret,rustdesk/*}`, plus the `.tar.json` sidecar. An archive PHP made restores here
  (proven on a real one from the live server) and one made here restores in PHP (`replay/backup-roundtrip.sh` runs
  that against PHP itself).
- Safer than PHP, invisible to its reader: the dump is one `VACUUM INTO` snapshot; a restore is built and checked
  (integrity, foreign keys, row counts against the manifest) in a temporary database and applied to the live one in a
  single transaction; a cut or incomplete archive is refused; `hte_device_passwords` is re-keyed with the others.
- Not ported (yet): off-site copies (FTP, S3), Apprise notifications, the upload/download routes of
  Settings -> Backups (UI), `cortendesk:check-device-notifications`. A configured off-site target is reported as a
  failed copy where Settings shows it; the deploy stops if one is set.
- New env: `HTE_CONSOLE_JOBS`, `HTE_CONSOLE_BACKUPS_DIR` (else `CORTENDESK_BACKUPS_PATH`, else `/data/backups`),
  `HTE_CONSOLE_RUSTDESK_DIR` (else the directory of `HTE_CONSOLE_HBBS_DB`), `HTE_CONSOLE_LOG_RETENTION_DAYS` (else
  `CORTENDESK_LOG_RETENTION_DAYS`, else 365). Dependency: `flate2` (already in the lockfile).

## 0.5.3 (2026-10-25): phase 5, a flaky test

- `signin_api::pkce_and_client_secret_reach_the_provider` (phase 2) failed about one run in 64: it replaced the first character of
  the random PKCE verifier with `x`, which is no change when the verifier already starts with `x`. It now always changes it. No change to the console.

## 0.5.2 (2026-10-25): phase 5, the replay against PHP found one difference

- `unique` and `exists` are not run for an attribute that already failed a rule (Laravel's
  `hasNotFailedPreviousRuleIfPresenceRule`): `owner_user_id: "abc"` gets the integer message only. The first replay against PHP 1.15.0-hte.1
  matched 185 of 186 fixtures, with hte-console 186 of 186 and identical databases; this was the one difference.

## 0.5.1 (2026-10-25): phase 5, replay fixes

- First replay against PHP: the throwaway PHP's own first-start administrator made the user lists one longer, so the
  adminapi seed deletes it; the snapshot masks a random book guid in `console_audits.target_id`. No change to the API.

## 0.5.0 (2026-10-24): phase 5, the admin automation API

- Native: the 48 routes of `/api/v1/*` and `POST /api/devices/cli` (`--assign`), ported from 1.15.0-hte.1 behind PHP's
  api-token guard, `throttle:120,1`, model bindings and `api-token-can` (README section "Phase 5"). Everything else
  keeps going where it went.
- Hardening beyond PHP: a per-address limit on failed API authentications (300 a minute, 429), a 1 MiB body cap.
- `fixtures/adminapi/`: 186 synthetic fixtures and their seed, written by `replay/make-adminapi-fixtures.py`; a synthetic
  fixture may list `"scan_ignore"` pointers (Laravel's own vocabulary: validation messages, action names) and
  `"sanitise_expected"`; `seed-sql` no longer seeds `/api/v1/*` bearers as client tokens; the snapshot masks `remember_token`.
- Version 0.5.0. New env: `HTE_CONSOLE_ADMIN_MAX_BODY_BYTES`.

## 0.4.1 (2026-10-24): phase 4, the signed-in client, on top of phase 3

0.4.0 was tagged from a branch without phase 3 and must not be deployed; 0.4.1 is the same work merged with 0.3.0.

- Native: the address books (legacy `GET|POST /api/ab`, `POST /api/ab/get`, and the multi-book API under `/api/ab/`),
  `GET|POST /api/server-config`, the group tab (`/api/device-group/accessible`, `/api/users`, `/api/peers`), the session
  note and active-session lookup (`PUT /api/audit`, `GET /api/audit/conn/active`) and `GET /webclient-config/index.js`,
  ported from 1.15.0-hte.1 behind phase 2's bearer-token guard, with each person's reach (README section "Phase 4").
  `/webclient` and `/rdclient/*` stay PHP; the websocket bridge is Caddy's.
- `fixtures/clientapi/`: 118 synthetic fixtures and their seed, written by `replay/make-clientapi-fixtures.py`; the replay
  learns `"vars"` (preset variables), `{{name}}` in the path, masks `tm` and marks random UUIDs.
- Version 0.4.1. New env: `HTE_CONSOLE_CLIENT_MAX_BODY_BYTES`, `HTE_CONSOLE_ID_SERVER`,
  `HTE_CONSOLE_PUBLIC_KEY`.

## 0.3.0 (2026-10-24): phase 3, the server link and the sweeps

- Native: `GET /api/server/policy` (ServerLink::policy with HTE Remote's `scope` block, ETag/304, the pull recorded in
  Laravel's cache), `POST /api/server/local-addrs`, `POST /api/server/refusals` (alarm 102), behind PHP's shared
  secret and `throttle:600,1,server-link`; Laravel's validator for their bodies (`src/validate.rs`).
- Scheduled jobs (`HTE_CONSOLE_SWEEPS`, none by default): the reach sweep (15 s, alarm 103), computer passwords
  (rotation on schedule and on access loss, the "HTE Remote" books), stale sessions, the diagnostics heartbeat; each
  under the lock PHP's scheduler takes for it (`cache_locks`), so PHP skips what hte-console runs and resumes when
  it stops. Needs the PHP container on `CACHE_STORE=database`.
- New: `hte-console sweep`, `schedule-locks`, `sql-apply` (replay only). The replay forwards `If-None-Match`, captures
  a response header (`capture_header`) and compares a body by digest (`"kind": "sha256"`); `seed-sql` never seeds the
  server link's bearer as a client token; the snapshot compares Laravel's `cache` table for the two keys hte-console
  writes (times masked) and masks lock owners. `replay.sh`: the secret and the database cache on both consoles, the
  two policies compared, and `fixtures/sweeps/` run step by step on both databases.
- `fixtures/serverlink/` (31 synthetic fixtures and the ReachTest world as a seed, written by
  `replay/make-serverlink-fixtures.py`), `fixtures/sweeps/` (a scenario of SQL steps and sweeps).
- From the independent review before release: the validator walks the body by reference (a 500-entry batch cloned
  it some 30 000 times) and runs before the shared database connection is taken; a 4 MiB limit of the link's own;
  the scheduler does not take a lock after the stop gave them back, and a restarted service takes back the locks a
  killed one left (owners `hte-console-svc-`/`hte-console-cli-`); each sweep row in a savepoint; a lock insert that
  fails for another reason than the key is an error; the replay compares tokens both policies hold exactly and exits
  2 when a setup step fails. Tests for each.
- Phase 1's `Passwords::issue` now cuts the reason as `Str::limit($reason, 60, '')` does (the sweep's reasons can be
  longer than 60 characters).

## 0.2.0 (2026-10-24): phase 2, the client sign-in

- Native: `GET /api/login-options`, `POST /api/login` (password, the TOTP step), `POST /api/logout`,
  `POST /api/currentUser`, `POST /api/oidc/auth`, `GET /api/oidc/auth-query`, `GET /login/oidc/client-callback`,
  ported from 1.15.0-hte.1 with what they write (tokens, OIDC requests, login logs, accounts, alarms, devices).
  README section "Phase 2" has the rules and the deliberate differences (RS256 only, exp required, azp with several
  audiences, Entra tenant, JWKS refetch, https-only provider, single-use state, redirect URI from
  `HTE_CONSOLE_PUBLIC_URL`, equal timing for unknown users, 64 KiB bodies).
- New: `hte-console fake-idp` (a fake OpenID provider, test only) and `hte-console seed-expand`; the replay learns
  run-time templates (`{{name}}`, captures, `{{totp}}`), a browser step through the fake provider, HTML checks for
  pages, and masks what sign-in mints at random (tokens, codes, state, nonce, verifier, bcrypt hashes, the TOTP step).
- `fixtures/signin/`: 151 synthetic sign-in fixtures and their seed, written by `replay/make-signin-fixtures.py`.
- The shadow never records sign-in paths. A replay template (`{{name}}`) counts as a placeholder in the leftover scan.
- From the independent review before release: the callback's token exchange and writes run in their own task with a
  guard, so a browser that disconnects mid-exchange no longer leaves the state marked in use (the retry read as
  expired until a restart); tests for that, a concurrent duplicate, `iat` ahead without `nbf`, the global 2FA switch,
  forwarded port/prefix and an IPv6 Host, and the `email_verified` forms.

## 0.1.2 (2026-10-24): review fixes

From a code review of 0.1.1 against PHP 1.15.0-hte.1, Laravel 13.35 and Symfony http-foundation 8.1:

- `TRUSTED_PROXIES` is read as `TrustConfiguredProxies` and Symfony read it: `*` alone trusts every peer,
  `REMOTE_ADDR` the request's own peer, `PRIVATE_SUBNETS`/`private_ranges` Symfony's list. 0.1.1 dropped such entries
  silently, so `*` would have recorded Caddy's address for every device. Entries that are no address are still
  ignored, as in PHP, and now named in a warning at start. Not the default configuration.
- The uuid pin is compared in constant time (`hash_equals`, as PHP).
- Rate-limit and nonce memory expire in two generations instead of scanning the whole map once full: a flood of
  new addresses or nonces costs nothing per request; memory stays bounded.
- `json_encode` leaves DEL (0x7f) as it is, like PHP (reachable only through a strategy value containing it).
- Checked and kept: 404/405/413 answers carry `Access-Control-Allow-Origin: *`, because Laravel renders those
  exceptions inside the middleware pipeline and HandleCors adds the header on the way out.
- README: the known differences that depend on configuration this port does not cover (empty `TRUSTED_PROXIES`,
  `APP_PREVIOUS_KEYS`, the older Apprise offline marker).
- `replay.sh`: the tamper check picks its fixture with a glob (under `pipefail`, `ls | grep -m1` with 900+ fixtures
  also ran the fallback and named two files). The replay itself is unchanged; the image does not contain it.
- Tests: trusted-proxy keywords and two `X-Forwarded-For` headers, form and `charset` bodies over HTTP, stored
  timestamps Carbon cannot read (500), the password hook on a pending device and with no or unreadable ciphertext,
  a soft-deleted strategy reached through a link, the CORS header on 405 and 413.

## 0.1.1 (2026-10-24): the replay paces itself

The first live replay with 0.1.0 (725 fixtures) compared 429s: 700 captured heartbeats from a few devices, sent in one
burst, tripped the console's own limit of 120 a minute per address and device, on PHP and on hte-console alike (the
databases came out identical, every other answer matched). `hte-console replay` now sends at most 110 a minute per
address and device id (`HTE_CONSOLE_REPLAY_PER_MINUTE`), waiting when needed; `replay.sh`'s tamper check replays only
the changed fixture. No change to the endpoints. A racy test of the 413 path now sends only the headers.

## 0.1.0 (2026-10-24): phase 1, the device endpoints

- `serve` with `HTE_CONSOLE_DATABASE` answers `POST /api/heartbeat`, `/api/sysinfo`, `/api/audit/conn`,
  `/api/audit/file`, `/api/audit/alarm` and `GET /api/version` itself, on the PHP console's SQLite file (WAL,
  busy timeout, foreign keys; no schema change). Ported from v1.15.0-hte.1: `SyncController`, the tokenless half of
  `AuditController`, `Strategy` (resolution and delivery), `DeviceEnrollment` (approval gate, default group,
  approval by a signed-in client), the presence marker of `CheckDeviceNotifications::reportOnline`, and HTE Remote's
  password hook (`App\Hte\Passwords`: `hte_pw`, issue, confirm, book entries, the password sealed with
  `crypto_box_seal` to the device's ed25519 key from hbbs's `peer` table). Everything else is forwarded as in 0.0.x.
- PHP and Laravel semantics as a library (`php.rs`, `laravel.rs`), so answers to bad input are PHP's own.
- Hardening: 1 MiB body cap, the `device-sync` rate limit, no panics on input (a seeded fuzz test), bound
  parameters only, no secrets in logs, refuses to start under a uid that would leave WAL files PHP cannot write.
- `hte-console snapshot <sqlite>`; `replay.sh` replays against PHP and hte-console and compares the databases.
- Synthetic fixtures 009-024 (bad input, audit paths); raw request bodies in synthetic fixtures.
- Graceful stop on SIGTERM. Image built with `cross` (libsodium, SQLite).
- Not ported: Apprise notifications; multipart bodies.

## 0.0.2 (2026-10-24)

Status tokens recorded as text, replay classifies replies like capture, several fixture directories, a built-in
"does the replay notice a change" check, eight synthetic fixtures, extra seed SQL, the default strategy derived
from captured answers.

## 0.0.1 (2026-10-24): phase 0, the shadow proxy

Forwards every request to PHP and returns its answer unchanged; records sanitised fixtures (`SANITISER.md`);
`scan`, `seed-sql`, `replay`, `replay/replay.sh`.
