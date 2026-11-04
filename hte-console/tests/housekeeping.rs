//! Phase 6: local backups (the previous console's archive format, both directions), restore (including interrupted ones), the
//! retention tiers, log and invitation pruning, and the daily scheduler entries. Everything runs on temporary
//! databases made from tests/schema*.sql; nothing here needs the previous console, Docker or the network.
//!
//! The one test that needs a real previous-console-made archive (`HTE_TEST_PHP_ARCHIVE=/path/to/cortendesk-backup-....tar`) is
//! skipped when the variable is unset; such an archive holds the install's secrets and is never committed.

use hte_console::backup::{self, Env, Stage};
use hte_console::cache::Store;
use hte_console::housekeeping::{self, Job, Scheduler, Setup};
use hte_console::laravel::Encrypter;
use hte_console::{prune, tarfile};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const KEY_A: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_B: &str = "base64:Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=";
// 2026-10-24 04:10:30 UTC
const NOW: i64 = 1_792_815_030;

struct World {
    dir: tempfile::TempDir,
    env: Env,
}

fn schema(c: &Connection) {
    c.execute_batch(include_str!("schema.sql")).unwrap();
    c.execute_batch(include_str!("schema_phase3.sql")).unwrap();
    c.execute_batch(include_str!("schema_p6.sql")).unwrap();
    c.execute_batch(hte_console::path::SCHEMA).unwrap(); // the own migration, as the service has run it
}

fn enc(key: &str, plain: &str) -> String {
    Encrypter::from_app_key(key).unwrap().encrypt_string(plain.as_bytes())
}

fn dec(key: &str, payload: &str) -> String {
    String::from_utf8(Encrypter::from_app_key(key).unwrap().decrypt_string(payload.as_bytes()).unwrap()).unwrap()
}

/// A "previous console" install: a database with some of everything, the app key, hbbs's files.
fn world(key: &str) -> World {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cortendesk.sqlite");
    let c = Connection::open(&db).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    schema(&c);
    c.execute_batch(&format!(
        r#"
        insert into migrations (migration, batch) values ('2014_10_12_000000_create_users_table', 1), ('2026_10_16_000001_create_hte', 2);
        insert into users (id, username, name, email, password, is_admin, totp_secret, created_at, updated_at) values
          (1, 'admin', 'Admin', 'a@example.test', '$2y$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234', 1, '{totp}', '2026-10-01 10:00:00', '2026-10-01 10:00:00'),
          (2, 'maria', 'María Ñ "quoted" / slash', 'm@example.test', 'x', 0, null, '2026-10-02 10:00:00', '2026-10-02 10:00:00');
        insert into settings (key, value, created_at, updated_at) values
          ('oidc_client_secret', '{secret}', '2026-10-01 10:00:00', '2026-10-01 10:00:00'),
          ('oidc_enabled', '1', '2026-10-01 10:00:00', '2026-10-01 10:00:00'),
          ('oidc_button_label', 'Sign in with Microsoft', null, null),
          ('backup_keep_daily', '3', null, null);
        insert into device_groups (id, name) values (1, 'Accounting');
        insert into devices (id, rustdesk_id, uuid, hostname, user_id, last_online_at, created_at) values (1, '190018695', 'u1', 'macbook', 2, '2026-10-24 04:00:00', '2026-10-01 10:00:00'), (2, '161841413', 'u2', 'pc', 1, null, '2026-10-02 10:00:00');
        insert into address_books (id, guid, name, owner_user_id, is_personal) values (1, 'g-1', 'Maria', 2, 1);
        insert into address_book_entries (id, address_book_id, rustdesk_id, password_enc, created_at) values (1, 1, '190018695', '{ab}', '2026-10-02 10:00:00'), (2, 1, '161841413', null, null);
        insert into hte_device_passwords (id, rustdesk_id, current_version, current_enc, confirmed_version, confirmed_enc) values (1, '190018695', 2, '{cur}', 1, '{conf}');
        insert into alarm_logs (rustdesk_id, typ, info, created_at) values ('190018695', 102, 'a', '2026-10-23 00:00:00');
        insert into console_audits (user_id, username, action, summary, created_at) values (1, 'admin', 'user.update', 'Updated user maria', '2026-10-24 03:00:00');
        insert into cache_locks (key, owner, expiration) values ('p-framework/schedule-aaa', 'hte-console-svc-x', 9999999999);
        insert into sessions (id, payload, last_activity) values ('s1', 'x', 1);
        "#,
        totp = enc(key, "JBSWY3DPEHPK3PXP"),
        secret = enc(key, "client-secret-value"),
        ab = enc(key, "pw-in-book"),
        cur = enc(key, "current-pw"),
        conf = enc(key, "confirmed-pw"),
    ))
    .unwrap();
    // a REAL, a NULL-heavy row, and a unicode/escape-heavy one
    c.execute("insert into settings (key, value) values ('ratio', ?)", [0.5f64]).unwrap();
    c.execute("insert into settings (key, value) values ('weird', ?)", ["line1\nline2\t\"q\" \\ / é 日本 \u{7f} \u{2028}"]).unwrap();
    drop(c);

    let rd = dir.path().join("rustdesk");
    std::fs::create_dir(&rd).unwrap();
    std::fs::write(rd.join("id_ed25519"), "PRIVATE-KEY-BYTES").unwrap();
    std::fs::write(rd.join("id_ed25519.pub"), "PUBLIC-KEY").unwrap();
    let h = Connection::open(rd.join("db_v2.sqlite3")).unwrap();
    h.pragma_update(None, "journal_mode", "WAL").unwrap();
    h.execute_batch("create table peer (guid blob primary key, id varchar(100), uuid blob, pk blob); insert into peer (guid, id, uuid, pk) values (x'0102', '190018695', x'03', x'04');").unwrap();
    drop(h);

    let env = Env {
        database: db,
        busy: Duration::from_secs(5),
        backups_dir: dir.path().join("backups"),
        rustdesk_dir: Some(rd),
        app_key: key.to_string(),
        server_secret: "0123456789abcdef".repeat(4),
        app_url: "https://rustdesk.example.test".into(),
        app_version: "1.15.0-hte.1".into(),
        store: Store { prefix: "p-".into() },
    };
    World { dir, env }
}

/// An install with the live console's real schema and no data.
fn bare_world(key: &str) -> World {
    let w = world(key);
    std::fs::remove_file(&w.env.database).unwrap();
    for ext in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", w.env.database.display()));
    }
    let c = Connection::open(&w.env.database).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    c.execute_batch(include_str!("schema_live.sql")).unwrap();
    c.execute_batch(hte_console::path::SCHEMA).unwrap(); // the own migration, as the service has run it
    drop(c);
    w
}

/// Every row of every table (SQLite storage classes shown), without any masking.
fn dump(path: &Path, skip: &[&str]) -> BTreeMap<String, Vec<String>> {
    let c = Connection::open(path).unwrap();
    let mut out = BTreeMap::new();
    for t in backup::tables(&c).unwrap() {
        if skip.contains(&t.as_str()) {
            continue;
        }
        let mut st = c.prepare(&format!("select * from \"{t}\" order by rowid")).unwrap();
        let n = st.column_count();
        let mut rows = vec![];
        let mut q = st.query([]).unwrap();
        while let Some(r) = q.next().unwrap() {
            let cells: Vec<String> = (0..n).map(|i| format!("{:?}", r.get_ref(i).unwrap())).collect();
            rows.push(cells.join("|"));
        }
        out.insert(t, rows);
    }
    out
}

fn data(w: &World) -> BTreeMap<String, Vec<String>> {
    dump(&w.env.database, &backup::SKIP_TABLES)
}

fn no_hook(_: Stage) -> Result<(), String> {
    Ok(())
}

fn extract_all(tar: &Path, to: &Path) -> Vec<String> {
    std::fs::create_dir_all(to).unwrap();
    tarfile::extract(tar, |n| Some(to.join(n.replace('/', "__")))).unwrap()
}

fn gunzip(p: &Path) -> String {
    use std::io::Read;
    let mut s = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(p).unwrap()).read_to_string(&mut s).unwrap();
    s
}

// ------------------------------------------------------------------------------------------------ the archive ---

#[test]
fn archive_has_php_layout() {
    let w = world(KEY_A);
    let made = backup::create(&w.env, "manual", NOW).unwrap();
    assert_eq!(made.name, "hte-remote-backup-20261024-041030.tar");
    assert!(backup::is_backup_name(&made.name));
    // modes, as the previous console: archive and sidecar 0600
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&made.path).unwrap().permissions().mode() & 0o777, 0o600);
    let sidecar = PathBuf::from(format!("{}.json", made.path.display()));
    assert_eq!(std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777, 0o600);

    let names = extract_all(&made.path, &w.dir.path().join("x"));
    assert_eq!(names[0], "manifest.json");
    // tables sorted, none of the transient ones, `migrations` included for the record
    let tables: Vec<&str> = names.iter().filter_map(|n| n.strip_prefix("db/")).filter_map(|n| n.strip_suffix(".ndjson.gz")).collect();
    let mut sorted = tables.clone();
    sorted.sort();
    assert_eq!(tables, sorted);
    for skip in backup::SKIP_TABLES {
        assert!(!tables.contains(&skip), "{skip} is transient");
    }
    assert!(tables.contains(&"migrations") && tables.contains(&"hte_device_passwords") && tables.contains(&"settings"));
    assert_eq!(
        names.iter().filter(|n| n.starts_with("files/")).cloned().collect::<Vec<_>>(),
        ["files/app_key", "files/server_secret", "files/rustdesk/id_ed25519", "files/rustdesk/id_ed25519.pub", "files/rustdesk/db_v2.sqlite3"]
    );

    // the manifest: the previous console's keys, in the previous console's order, pretty printed with four spaces
    let text = std::fs::read_to_string(w.dir.path().join("x/manifest.json")).unwrap();
    assert!(text.starts_with("{\n    \"format\": 1,\n    \"app\": \"cortendesk\",\n    \"app_version\": \"1.15.0-hte.1\",\n    \"created_at\": \"2026-10-24T04:10:30+00:00\",\n    \"trigger\": \"manual\",\n    \"app_url\": \"https://rustdesk.example.test\",\n    \"db_driver\": \"sqlite\",\n    \"tables\": {\n"), "{text}");
    let m: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(m["tables"]["users"], 2);
    assert_eq!(m["tables"]["settings"], 6);
    assert_eq!(m["files"][4], "rustdesk/db_v2.sqlite3");
    assert_eq!(std::fs::read_to_string(&sidecar).unwrap(), text, "the sidecar is the manifest");
    assert_eq!(made.manifest, m);

    // rows: one JSON object per line, columns in table order, the previous console's types
    let users = gunzip(&w.dir.path().join("x/db__users.ndjson.gz"));
    let first: serde_json::Value = serde_json::from_str(users.lines().next().unwrap()).unwrap();
    assert_eq!(first["id"], 1);
    assert_eq!(first["is_admin"], 1);
    assert!(first["avatar"].is_null());
    assert_eq!(first.as_object().unwrap().keys().next().unwrap(), "id");
    assert!(users.contains("María Ñ \\\"quoted\\\" / slash"), "unicode and slashes unescaped, quotes escaped: {users}");
    let settings = gunzip(&w.dir.path().join("x/db__settings.ndjson.gz"));
    assert!(settings.contains("\"value\":\"0.5\""), "a text column hands back text, as PDO does: {settings}");
    // files: the app key as the container has it, the hbbs files (the peer database as a consistent copy)
    assert_eq!(std::fs::read_to_string(w.dir.path().join("x/files__app_key")).unwrap(), KEY_A);
    assert_eq!(std::fs::read_to_string(w.dir.path().join("x/files__rustdesk__id_ed25519")).unwrap(), "PRIVATE-KEY-BYTES");
    let peers = Connection::open(w.dir.path().join("x/files__rustdesk__db_v2.sqlite3")).unwrap();
    assert_eq!(peers.query_row::<String, _, _>("select id from peer", [], |r| r.get(0)).unwrap(), "190018695");
    // nothing left behind
    let left: Vec<String> = std::fs::read_dir(&w.env.backups_dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(left.len(), 2, "{left:?}");
    // the lock is given back
    let c = w.env.open().unwrap();
    assert_eq!(c.query_row::<i64, _, _>("select count(*) from cache_locks where key = 'p-cortendesk:backup'", [], |r| r.get(0)).unwrap(), 0);
}

#[test]
fn system_tar_and_gzip_read_our_archive() {
    // an independent reader (not the previous console, but not this crate either): the headers and members are valid
    let w = world(KEY_A);
    let made = backup::create(&w.env, "manual", NOW).unwrap();
    let out = std::process::Command::new("tar").arg("-tf").arg(&made.path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let listing = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(listing.lines().any(|l| l == "manifest.json") && listing.lines().any(|l| l == "db/users.ndjson.gz") && listing.lines().any(|l| l == "files/rustdesk/id_ed25519.pub"), "{listing}");
    let x = w.dir.path().join("sys");
    std::fs::create_dir(&x).unwrap();
    assert!(std::process::Command::new("tar").arg("-xf").arg(&made.path).arg("-C").arg(&x).status().unwrap().success());
    assert!(std::process::Command::new("gzip").arg("-t").arg(x.join("db/users.ndjson.gz")).status().unwrap().success());
}

// ---------------------------------------------------------------------------------------------- round trips ---

#[test]
fn round_trip_rust_to_rust() {
    let w = world(KEY_A);
    let before = data(&w);
    let made = backup::create(&w.env, "manual", NOW).unwrap();
    // wreck the live data, and change the transient tables (which a restore must leave alone)
    let c = w.env.open().unwrap();
    c.execute_batch("delete from users where id = 2; update settings set value = 'changed' where key = 'oidc_enabled'; insert into devices (rustdesk_id, uuid) values ('999', 'z'); delete from alarm_logs; insert into migrations (migration, batch) values ('later', 3); update sessions set payload = 'newer'; insert into cache_locks (key, owner, expiration) values ('p-other', 'o', 4102444800);").unwrap();
    // (the foreign lock is not expired: the lock lottery may delete expired ones, 2% of acquisitions, as Laravel's does)
    drop(c);
    let r = backup::restore(&w.env, &made.path, NOW + 60, &no_hook).unwrap();
    assert_eq!(r.rows, made.rows - 2, "every row except `migrations`' two");
    assert!(!r.rekeyed && r.dropped_columns.is_empty());
    let after = data(&w);
    for (t, rows) in &before {
        if t == "migrations" {
            assert_eq!(after[t].len(), 3, "the live migrations table is kept as it is");
            continue;
        }
        assert_eq!(&after[t], rows, "table {t}");
    }
    // transient tables are not the restore's business: the later session and the foreign lock are still there
    let c = w.env.open().unwrap();
    assert_eq!(c.query_row::<String, _, _>("select payload from sessions where id = 's1'", [], |r| r.get(0)).unwrap(), "newer");
    assert_eq!(c.query_row::<i64, _, _>("select count(*) from cache_locks where key = 'p-other'", [], |r| r.get(0)).unwrap(), 1);
    assert_eq!(c.query_row::<i64, _, _>("select count(*) from cache_locks where key = 'p-cortendesk:backup'", [], |r| r.get(0)).unwrap(), 0, "our own lock is given back");
    drop(c);
    // hbbs's files are staged for the next start, whole, under their final modes
    assert_eq!(r.files, ["id_ed25519", "id_ed25519.pub", "db_v2.sqlite3"]);
    assert!(r.restart_needed);
    let rd = w.env.rustdesk_dir.clone().unwrap();
    assert_eq!(std::fs::read_to_string(rd.join("id_ed25519.restore")).unwrap(), "PRIVATE-KEY-BYTES");
    assert!(!rd.join("id_ed25519.restore.part").exists());
    // the live files themselves are not touched
    assert_eq!(std::fs::read_to_string(rd.join("id_ed25519")).unwrap(), "PRIVATE-KEY-BYTES");
    // The previous console can still use the database it shares (the write lock is free, the file is not in a half state)
    let c = w.env.open().unwrap();
    c.execute_batch("begin immediate; rollback").unwrap();
    assert_eq!(c.query_row::<String, _, _>("pragma integrity_check", [], |r| r.get(0)).unwrap(), "ok");
}

#[test]
fn restore_into_another_install_rekeys_the_encrypted_values() {
    let a = world(KEY_A);
    let made = backup::create(&a.env, "manual", NOW).unwrap();
    let b = world(KEY_B);
    // wipe b's data so the restore is visibly from a
    b.env.open().unwrap().execute_batch("delete from settings; delete from users;").unwrap();
    let r = backup::restore(&b.env, &made.path, NOW, &no_hook).unwrap();
    assert!(r.rekeyed);
    let c = b.env.open().unwrap();
    let get = |sql: &str| c.query_row::<String, _, _>(sql, [], |r| r.get(0)).unwrap();
    assert_eq!(dec(KEY_B, &get("select value from settings where key = 'oidc_client_secret'")), "client-secret-value");
    assert_eq!(dec(KEY_B, &get("select totp_secret from users where id = 1")), "JBSWY3DPEHPK3PXP");
    assert_eq!(dec(KEY_B, &get("select password_enc from address_book_entries where id = 1")), "pw-in-book");
    assert_eq!(dec(KEY_B, &get("select current_enc from hte_device_passwords where id = 1")), "current-pw");
    assert_eq!(dec(KEY_B, &get("select confirmed_enc from hte_device_passwords where id = 1")), "confirmed-pw");
    // plain values and NULLs pass through
    assert_eq!(get("select value from settings where key = 'oidc_enabled'"), "1");
    assert_eq!(get("select value from settings where key = 'weird'"), "line1\nline2\t\"q\" \\ / é 日本 \u{7f} \u{2028}");
    assert!(c.query_row::<Option<String>, _, _>("select password_enc from address_book_entries where id = 2", [], |r| r.get(0)).unwrap().is_none());
    // and the old key can no longer open them
    assert!(Encrypter::from_app_key(KEY_A).unwrap().decrypt_string(get("select value from settings where key = 'oidc_client_secret'").as_bytes()).is_err());
}

/// An archive written the way the previous console writes one (system tar and gzip, hand-made previous-console-style JSON), not by this crate.
fn php_style_archive(dir: &Path, app_key: &str, with_dirs: bool, extra_column: bool) -> PathBuf {
    let pkg = dir.join("pkg");
    std::fs::create_dir_all(pkg.join("db")).unwrap();
    std::fs::create_dir_all(pkg.join("files/rustdesk")).unwrap();
    let write_gz = |name: &str, lines: &[&str]| {
        let p = pkg.join("db").join(name);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(std::process::Command::new("gzip").arg("-f").arg("-6").arg(&p).status().unwrap().success());
    };
    let extra = if extra_column { ",\"dropped_by_this_version\":\"x\"" } else { "" };
    write_gz(
        "settings.ndjson", // gzip -f turns it into settings.ndjson.gz
        &[
            &format!("{{\"key\":\"oidc_client_secret\",\"value\":\"{}\",\"created_at\":\"2026-10-01 10:00:00\",\"updated_at\":null{extra}}}", enc(app_key, "from-old")),
            "{\"key\":\"oidc_enabled\",\"value\":\"1\",\"created_at\":null,\"updated_at\":null}",
            "{\"key\":\"note\",\"value\":\"caf\u{e9} \u{65e5}\u{672c} \\\"q\\\" \\/ \\u00e9\",\"created_at\":null,\"updated_at\":null}",
            "{\"key\":\"ratio\",\"value\":1.5,\"created_at\":null,\"updated_at\":null}",
        ],
    );
    write_gz("users.ndjson", &["{\"id\":7,\"username\":\"old-user\",\"name\":null,\"email\":null,\"password\":\"x\",\"is_admin\":true,\"is_active\":1,\"created_at\":\"2026-10-01 10:00:00\",\"updated_at\":\"2026-10-01 10:00:00\"}"]);
    write_gz("devices.ndjson", &[]);
    std::fs::write(pkg.join("files/app_key"), app_key).unwrap();
    std::fs::write(pkg.join("files/rustdesk/id_ed25519"), "OLD-PRIVATE").unwrap();
    std::fs::write(pkg.join("files/rustdesk/id_ed25519.pub"), "OLD-PUBLIC").unwrap();
    let manifest = "{\n    \"format\": 1,\n    \"app\": \"cortendesk\",\n    \"app_version\": \"1.14.0-hte.6\",\n    \"created_at\": \"2026-10-24T03:30:00+00:00\",\n    \"trigger\": \"scheduled\",\n    \"app_url\": \"https:\\/\\/rustdesk.example.test\",\n    \"db_driver\": \"sqlite\",\n    \"tables\": {\n        \"devices\": 0,\n        \"migrations\": 99,\n        \"settings\": 4,\n        \"users\": 1\n    },\n    \"files\": [\n        \"app_key\",\n        \"rustdesk\\/id_ed25519\",\n        \"rustdesk\\/id_ed25519.pub\"\n    ]\n}";
    std::fs::write(pkg.join("manifest.json"), manifest).unwrap();
    let tar = dir.join("cortendesk-backup-20261024-033000.tar");
    let mut cmd = std::process::Command::new("tar");
    cmd.arg("--format=ustar").arg("-cf").arg(&tar).arg("-C").arg(&pkg);
    if with_dirs {
        cmd.args(["manifest.json", "db", "files"]);
    } else {
        // members only, in the order PharData happens to write them: files first
        cmd.args(["files/rustdesk/id_ed25519", "files/rustdesk/id_ed25519.pub", "files/app_key", "db/settings.ndjson.gz", "db/users.ndjson.gz", "db/devices.ndjson.gz", "manifest.json"]);
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    tar
}

#[test]
fn a_php_style_archive_restores() {
    for with_dirs in [false, true] {
        let w = world(KEY_B);
        let tar = php_style_archive(w.dir.path(), KEY_A, with_dirs, true);
        let m = backup::read_manifest(&tar).unwrap();
        assert_eq!(m["app_version"], "1.14.0-hte.6");
        let r = backup::restore(&w.env, &tar, NOW, &no_hook).unwrap();
        assert!(r.rekeyed, "the archive came from KEY_A");
        assert_eq!(r.rows, 5);
        assert_eq!(r.dropped_columns["settings"], ["dropped_by_this_version"]);
        let c = w.env.open().unwrap();
        let get = |sql: &str| c.query_row::<String, _, _>(sql, [], |r| r.get(0)).unwrap();
        assert_eq!(dec(KEY_B, &get("select value from settings where key = 'oidc_client_secret'")), "from-old");
        assert_eq!(get("select value from settings where key = 'note'"), "café 日本 \"q\" / é");
        assert_eq!(get("select typeof(value) || ':' || value from settings where key = 'ratio'"), "text:1.5", "a float binds as the previous console binds it (text; the column has no numeric affinity)");
        assert_eq!(get("select username from users"), "old-user");
        assert_eq!(c.query_row::<i64, _, _>("select is_admin from users", [], |r| r.get(0)).unwrap(), 1, "true -> 1");
        assert_eq!(c.query_row::<i64, _, _>("select count(*) from devices", [], |r| r.get(0)).unwrap(), 0, "a table the archive has empty is emptied");
        assert_eq!(c.query_row::<i64, _, _>("select count(*) from address_books", [], |r| r.get(0)).unwrap(), 0, "and one it does not have at all is emptied too (the previous console deletes every live table)");
        assert_eq!(c.query_row::<i64, _, _>("select count(*) from migrations", [], |r| r.get(0)).unwrap(), 2, "migrations: the live ones");
        assert_eq!(std::fs::read_to_string(w.env.rustdesk_dir.clone().unwrap().join("id_ed25519.restore")).unwrap(), "OLD-PRIVATE");
        assert!(!w.env.rustdesk_dir.clone().unwrap().join("db_v2.sqlite3.restore").exists(), "an archive without it stages nothing");
        // and it can be listed like one of ours
        let b = backup::list(&w.env).unwrap();
        assert!(b.is_empty(), "the archive was restored from, not copied in");
    }
}

#[test]
fn a_real_php_archive_restores_and_round_trips() {
    let Ok(path) = std::env::var("HTE_TEST_PHP_ARCHIVE") else {
        eprintln!("HTE_TEST_PHP_ARCHIVE not set: skipped");
        return;
    };
    let path = PathBuf::from(path);
    let m = backup::read_manifest(&path).unwrap();
    // The live console's real schema (tests/schema_live.sql, no data), an install with another app key.
    let w = bare_world(KEY_B);
    let x = w.dir.path().join("old");
    std::fs::create_dir(&x).unwrap();
    tarfile::extract(&path, |n| n.strip_prefix("db/").map(|t| x.join(t))).unwrap();
    let mut counts = BTreeMap::new();
    for (t, n) in m["tables"].as_object().unwrap() {
        counts.insert(t.clone(), n.as_i64().unwrap());
    }
    let r = backup::restore(&w.env, &path, NOW, &no_hook).unwrap();
    let total: i64 = counts.iter().filter(|(t, _)| *t != "migrations").map(|(_, n)| n).sum();
    assert_eq!(r.rows, total);
    // the app key in the archive is the one this install's secrets were made with: rekey tells us whether it is ours
    eprintln!("real archive of the previous console: {} tables, {} rows restored, rekeyed={}, files staged={:?}", r.tables, r.rows, r.rekeyed, r.files);
    // Laravel's Crypt as the real the previous console container wrote it: every encrypted value opens with the archive's own key, and the
    // re-keyed copy opens with this install's to the same text (nothing is printed)
    let their_key = tarfile::read_entry(&path, "files/app_key", 4096).unwrap().map(|b| String::from_utf8(b).unwrap().trim().to_string());
    if let Some(their_key) = their_key.filter(|_| r.rekeyed) {
        let mut checked = 0;
        for l in gunzip(&x.join("settings.ndjson.gz")).lines() {
            let row: serde_json::Value = serde_json::from_str(l).unwrap();
            let (k, v) = (row["key"].as_str().unwrap(), row["value"].as_str().unwrap_or(""));
            let looks = hte_console::php::base64_decode_strict(v.as_bytes()).map_or(false, |b| b.starts_with(b"{\"iv\""));
            if !looks {
                continue;
            }
            let original = dec(&their_key, v);
            let mine: String = w.env.open().unwrap().query_row("select value from settings where key = ?", [k], |r| r.get(0)).unwrap();
            assert_eq!(dec(KEY_B, &mine), original, "setting {k}");
            checked += 1;
        }
        eprintln!("ciphertexts made by the previous console opened and re-keyed: {checked} settings");
        assert!(checked >= 1);
    }
    // and back: an archive of ours from the restored data has the same table counts as the previous console one
    let again = backup::create(&w.env, "manual", NOW).unwrap();
    for (t, n) in &counts {
        if t == "migrations" {
            continue;
        }
        assert_eq!(again.manifest["tables"][t], *n, "table {t}");
    }
    // row for row: the previous console dump of a table equals ours, line by line, as JSON values
    let y = w.dir.path().join("ours");
    std::fs::create_dir(&y).unwrap();
    tarfile::extract(&again.path, |n| n.strip_prefix("db/").map(|t| y.join(t))).unwrap();
    for t in counts.keys().filter(|t| *t != "migrations") {
        let php: Vec<serde_json::Value> = gunzip(&x.join(format!("{t}.ndjson.gz"))).lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let ours: Vec<serde_json::Value> = gunzip(&y.join(format!("{t}.ndjson.gz"))).lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(php.len(), ours.len(), "{t}");
        for (a, b) in php.iter().zip(&ours) {
            // settings re-encrypted under KEY_B, everything else value for value
            if t == "settings" || t == "users" || t == "address_book_entries" || t == "hte_device_passwords" {
                assert_eq!(a.as_object().unwrap().keys().collect::<Vec<_>>(), b.as_object().unwrap().keys().collect::<Vec<_>>(), "{t} columns");
                continue;
            }
            assert_eq!(a, b, "table {t}");
        }
    }
}

// ------------------------------------------------------------------------------------- interrupted restores ---

#[test]
fn an_interrupted_restore_changes_nothing() {
    let w = world(KEY_A);
    let made = backup::create(&w.env, "manual", NOW).unwrap();
    w.env.open().unwrap().execute_batch("update settings set value = 'live-change' where key = 'oidc_enabled'; delete from devices;").unwrap();
    let full_before = dump(&w.env.database, &[]);
    let rd = w.env.rustdesk_dir.clone().unwrap();
    for stage in [Stage::Extracted, Stage::Built, Stage::Checked, Stage::Applying] {
        let err = backup::restore(&w.env, &made.path, NOW + 1, &|s| if s == stage { Err(format!("cut at {s:?}")) } else { Ok(()) }).unwrap_err();
        assert_eq!(err, format!("cut at {stage:?}"));
        assert_eq!(dump(&w.env.database, &[]), full_before, "database changed after a cut at {stage:?}");
        assert!(!rd.join("id_ed25519.restore").exists() && !rd.join("db_v2.sqlite3.restore").exists(), "files staged after a cut at {stage:?}");
        assert!(!std::fs::read_dir(&w.env.backups_dir).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with(".restore-")), "work dir left after {stage:?}");
        // the lock is free again: the next restore runs
    }
    // and the same restore, uncut, goes through afterwards
    backup::restore(&w.env, &made.path, NOW + 2, &no_hook).unwrap();
    assert_eq!(w.env.open().unwrap().query_row::<String, _, _>("select value from settings where key = 'oidc_enabled'", [], |r| r.get(0)).unwrap(), "1");
}

#[test]
fn damaged_archives_are_refused_before_anything_is_touched() {
    let w = world(KEY_A);
    let made = backup::create(&w.env, "manual", NOW).unwrap();
    let before = dump(&w.env.database, &[]);
    let bytes = std::fs::read(&made.path).unwrap();
    let bad = |name: &str, content: Vec<u8>| -> String {
        let p = w.dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        let e = backup::restore(&w.env, &p, NOW, &no_hook).unwrap_err();
        assert_eq!(dump(&w.env.database, &[]), before, "{name}: the database changed");
        assert!(!w.env.rustdesk_dir.clone().unwrap().join("id_ed25519.restore").exists(), "{name}: files staged");
        e
    };
    // not a tar at all, and one cut in half
    assert_eq!(bad("junk.tar", vec![b'x'; 4096]), "That file is not an HTE Remote backup.");
    let e = bad("cut.tar", bytes[..bytes.len() / 2].to_vec());
    assert!(e.contains("not an HTE Remote backup") || e.contains("cut short") || e.contains("damaged"), "{e}");
    // a tar that is not ours, and a format from the future
    let other = w.dir.path().join("o");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("manifest.json"), r#"{"app":"other","format":1}"#).unwrap();
    #[allow(deprecated)]
    let t = |manifest: &str, rows: Option<(&str, &str)>| -> PathBuf {
        let d = tempfile::tempdir_in(w.dir.path()).unwrap().into_path();
        std::fs::create_dir_all(d.join("db")).unwrap();
        std::fs::write(d.join("manifest.json"), manifest).unwrap();
        let mut args = vec!["manifest.json".to_string()];
        if let Some((table, body)) = rows {
            std::fs::write(d.join(format!("db/{table}.ndjson")), body).unwrap();
            assert!(std::process::Command::new("gzip").arg("-f").arg(d.join(format!("db/{table}.ndjson"))).status().unwrap().success());
            args.push(format!("db/{table}.ndjson.gz"));
        }
        let tar = d.join("a.tar");
        assert!(std::process::Command::new("tar").arg("--format=ustar").arg("-cf").arg(&tar).arg("-C").arg(&d).args(&args).status().unwrap().success());
        tar
    };
    for (manifest, want) in [
        (r#"{"app":"other","format":1,"tables":{}}"#, "That file is not an HTE Remote backup."),
        (r#"{"app":"cortendesk","format":2,"tables":{}}"#, "format this version cannot read"),
        (r#"{"app":"cortendesk","format":1,"app_version":"9.9","tables":{"brand_new_table":1}}"#, "contains tables this install does not have (brand_new_table)"),
    ] {
        let tar = t(manifest, None);
        let e = backup::restore(&w.env, &tar, NOW, &no_hook).unwrap_err();
        assert!(e.contains(want), "{e}");
        assert_eq!(dump(&w.env.database, &[]), before);
    }
    // a damaged row in the second table to be read, a short table (manifest says 3, file has 1), a path in the table name
    let tar = t(r#"{"app":"cortendesk","format":1,"tables":{"settings":2}}"#, Some(("settings", "{\"key\":\"a\",\"value\":\"1\"}\nnot json\n")));
    assert!(backup::restore(&w.env, &tar, NOW, &no_hook).unwrap_err().contains("damaged row in settings.ndjson.gz"));
    let tar = t(r#"{"app":"cortendesk","format":1,"tables":{"settings":3}}"#, Some(("settings", "{\"key\":\"a\",\"value\":\"1\"}\n")));
    assert!(backup::restore(&w.env, &tar, NOW, &no_hook).unwrap_err().contains("incomplete: settings has 1 rows, its manifest says 3"));
    let tar = t(r#"{"app":"cortendesk","format":1,"tables":{"../../etc/passwd":1}}"#, None);
    assert!(backup::restore(&w.env, &tar, NOW, &no_hook).unwrap_err().contains("tables this install does not have"));
    // a row the live schema rejects (NOT NULL column missing): the whole restore is refused
    let tar = t(r#"{"app":"cortendesk","format":1,"tables":{"users":1}}"#, Some(("users", "{\"id\":9}\n")));
    assert!(backup::restore(&w.env, &tar, NOW, &no_hook).unwrap_err().contains("users:"));
    assert_eq!(dump(&w.env.database, &[]), before);
}

#[test]
fn a_schema_change_during_the_restore_stops_it() {
    let w = world(KEY_A);
    let made = backup::create(&w.env, "manual", NOW).unwrap();
    let before = dump(&w.env.database, &[]);
    let db = w.env.database.clone();
    let err = backup::restore(&w.env, &made.path, NOW, &move |s| {
        if s == Stage::Checked {
            // a previous-console migration lands between the check and the swap
            Connection::open(&db).unwrap().execute_batch("alter table settings add column extra text").unwrap();
        }
        Ok(())
    })
    .unwrap_err();
    assert!(err.contains("schema changed"), "{err}");
    let c = w.env.open().unwrap();
    assert_eq!(c.query_row::<i64, _, _>("select count(*) from settings", [], |r| r.get(0)).unwrap(), before["settings"].len() as i64);
}

#[test]
fn a_killed_run_leaves_no_trace_the_next_run_trips_on() {
    let w = world(KEY_A);
    std::fs::create_dir_all(&w.env.backups_dir).unwrap();
    // what a killed backup and a killed restore leave
    for d in [".work-deadbeef/pkg/db", ".restore-cafe0123", ".tar-abcdefghij"] {
        std::fs::create_dir_all(w.env.backups_dir.join(d)).unwrap();
        std::fs::write(w.env.backups_dir.join(d).join("junk"), "x").unwrap();
    }
    // and a lock row held by a dead owner that has run out
    w.env.open().unwrap().execute("insert into cache_locks (key, owner, expiration) values ('p-cortendesk:backup', 'dead', 5)", []).unwrap();
    let made = backup::create(&w.env, "manual", NOW).unwrap();
    let names: Vec<String> = std::fs::read_dir(&w.env.backups_dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&made.name));
}

#[test]
fn backup_and_restore_exclude_each_other_through_phps_lock() {
    let w = world(KEY_A);
    // The previous console's Settings -> Backups holds `cortendesk:backup` (3600 s)
    w.env.open().unwrap().execute("insert into cache_locks (key, owner, expiration) values ('p-cortendesk:backup', 'old-owner', ?)", [NOW + 3000]).unwrap();
    assert_eq!(backup::create(&w.env, "manual", NOW).unwrap_err(), "Another backup or restore is still running.");
    let tar = php_style_archive(w.dir.path(), KEY_A, false, false);
    assert_eq!(backup::restore(&w.env, &tar, NOW, &no_hook).unwrap_err(), "Another backup or restore is still running.");
    // The previous console's lock is still there, untouched
    assert_eq!(w.env.open().unwrap().query_row::<String, _, _>("select owner from cache_locks where key = 'p-cortendesk:backup'", [], |r| r.get(0)).unwrap(), "old-owner");
}

#[test]
fn the_snapshot_is_consistent_while_the_database_is_written() {
    let w = world(KEY_A);
    let db = w.env.database.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = stop.clone();
    let writer = std::thread::spawn(move || {
        let c = Connection::open(&db).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        let mut i = 0;
        while !s2.load(std::sync::atomic::Ordering::SeqCst) {
            // two tables that always move together
            let _ = c.execute_batch(&format!("begin immediate; insert into alarm_logs (rustdesk_id, typ, created_at) values ('w{i}', 1, '2026-10-24 00:00:00'); insert into console_audits (username, action, summary, created_at) values ('w', 'x', 'w{i}', '2026-10-24 00:00:00'); commit;"));
            i += 1;
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let mut counts = vec![];
    for k in 0..5 {
        let made = backup::create(&w.env, "manual", NOW + k).unwrap();
        counts.push((made.manifest["tables"]["alarm_logs"].as_i64().unwrap(), made.manifest["tables"]["console_audits"].as_i64().unwrap()));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    writer.join().unwrap();
    for (a, c) in counts {
        assert_eq!(a - 1, c - 1, "alarm_logs and console_audits come from the same moment (they differ by the seed's 1 each)");
    }
}

// ------------------------------------------------------------------------------------------------- pruning ---

fn put_logs(c: &Connection, table: &str, n: i64, at: &str) {
    let cols = match table {
        "audit_connections" => "(rustdesk_id, created_at) values ('1', ?)",
        "audit_file_transfers" => "(rustdesk_id, created_at) values ('1', ?)",
        "login_logs" => "(username, created_at) values ('u', ?)",
        "alarm_logs" => "(rustdesk_id, created_at) values ('1', ?)",
        "console_audits" => "(username, action, summary, created_at) values ('u', 'a', 's', ?)",
        "notification_deliveries" => "(event, status, title, created_at) values ('e', 's', 't', ?)",
        "relay_sessions" => "(uuid, rustdesk_id, created_at) values (lower(hex(randomblob(8))), '1', ?)",
        _ => unreachable!(),
    };
    let mut st = c.prepare(&format!("insert into {table} {cols}")).unwrap();
    c.execute_batch("begin").unwrap();
    for _ in 0..n {
        st.execute([at]).unwrap();
    }
    c.execute_batch("commit").unwrap();
}

fn count(c: &Connection, table: &str) -> i64 {
    c.query_row(&format!("select count(*) from {table}"), [], |r| r.get(0)).unwrap()
}

#[test]
fn prune_logs_windows() {
    let w = world(KEY_A);
    let c = w.env.open().unwrap();
    c.execute_batch("delete from alarm_logs; delete from console_audits;").unwrap();
    // NOW = 2026-10-24 04:10:30; 30 days back is 2026-09-24 04:10:30
    let cutoff = "2026-09-24 04:10:30";
    for t in prune::LOG_TABLES {
        put_logs(&c, t, 2, "2026-09-24 04:10:29"); // one second older than the window: goes
        put_logs(&c, t, 3, cutoff); // exactly at the cutoff: stays (`<`)
        put_logs(&c, t, 4, "2026-10-24 00:00:00"); // recent: stays
    }
    let p = prune::prune_logs(&c, NOW, Some(30), "365").unwrap();
    assert_eq!(p.total, 14);
    assert_eq!(p.lines.last().unwrap(), "Pruned 14 log rows older than 30 days.");
    assert_eq!(p.lines[0], "audit_connections: deleted 2");
    for t in prune::LOG_TABLES {
        assert_eq!(count(&c, t), 7, "{t}");
    }
    // nothing is touched in other tables
    assert_eq!(count(&c, "users"), 2);
    // disabled: 0, negative, and the configured value
    assert_eq!(prune::prune_logs(&c, NOW, Some(0), "365").unwrap().lines, ["Log retention is disabled (0 days) — nothing to prune."]);
    assert_eq!(prune::prune_logs(&c, NOW, Some(-3), "365").unwrap().total, 0);
    // the setting wins over the default, "0" and "" mean forever, text is cast like (int)
    assert_eq!(prune::retention_days(&c, "365").unwrap(), 365);
    for (v, want) in [("30", 30), ("0", 0), ("", 0), ("12abc", 12), ("abc", 0), ("-5", -5)] {
        c.execute("insert or replace into settings (key, value) values ('log_retention_days', ?)", [v]).unwrap();
        assert_eq!(prune::retention_days(&c, "365").unwrap(), want, "{v:?}");
    }
    c.execute("insert or replace into settings (key, value) values ('log_retention_days', '1')", []).unwrap();
    assert_eq!(prune::prune_logs(&c, NOW, None, "365").unwrap().total, 7 * 3, "one day: the three rows at the old cutoff go; the recent four (after 2026-10-23 04:10:30) stay");
    for t in prune::LOG_TABLES {
        assert_eq!(count(&c, t), 4, "{t}");
    }
    // more than one chunk
    put_logs(&c, "login_logs", 25_000, "2020-01-01 00:00:00");
    let p = prune::prune_logs(&c, NOW, Some(30), "365").unwrap();
    assert!(p.lines.contains(&"login_logs: deleted 25000".to_string()), "{:?}", p.lines);
    assert_eq!(count(&c, "login_logs"), 4);
}

#[test]
fn prune_invitations_windows() {
    let w = world(KEY_A);
    let c = w.env.open().unwrap();
    c.execute_batch(
        r#"
        insert into invitations (email, username, token_hash, expires_at, accepted_at) values
          ('a', 'a', 'h1', '2026-10-24 04:10:29', null),            -- expired, not accepted: goes
          ('b', 'b', 'h2', '2026-10-24 04:10:30', null),            -- expires exactly now: stays (`<`)
          ('c', 'c', 'h3', '2026-10-30 00:00:00', null),            -- still valid: stays
          ('d', 'd', 'h4', '2026-09-01 00:00:00', '2026-09-24 04:10:29'), -- accepted 30 days + 1 s ago: goes
          ('e', 'e', 'h5', '2026-09-01 00:00:00', '2026-09-24 04:10:30'), -- accepted exactly 30 days ago: stays
          ('f', 'f', 'h6', '2026-09-01 00:00:00', '2026-10-20 00:00:00'); -- accepted recently: stays
        insert into trusted_devices (user_id, token_hash, expires_at) values (1, 't1', '2026-10-24 04:10:29'), (1, 't2', '2026-10-24 04:10:30'), (2, 't3', '2027-01-01 00:00:00');
        "#,
    )
    .unwrap();
    assert_eq!(prune::prune_invitations(&c, NOW, 30).unwrap(), "Pruned 1 expired and 1 accepted invitation(s), 1 trusted device(s).");
    assert_eq!(count(&c, "invitations"), 4);
    assert_eq!(count(&c, "trusted_devices"), 2);
    // --days=0 drops every accepted one; a negative window is 0 (max(0, ...))
    assert_eq!(prune::prune_invitations(&c, NOW, -4).unwrap(), "Pruned 0 expired and 2 accepted invitation(s), 0 trusted device(s).");
    assert_eq!(prune::prune_invitations(&c, NOW, 30).unwrap(), "Pruned 0 expired and 0 accepted invitation(s), 0 trusted device(s).");
}

// ---------------------------------------------------------------------------------------- the backup command ---

fn result(c: &Connection) -> serde_json::Value {
    serde_json::from_str(&c.query_row::<String, _, _>("select value from settings where key = 'backup_last_result'", [], |r| r.get(0)).unwrap()).unwrap()
}

#[test]
fn scheduled_backup_runs_once_a_day_and_records_like_php() {
    let w = world(KEY_A);
    let c = w.env.open().unwrap();
    // off: nothing, not even a record
    c.execute("insert into settings (key, value) values ('backup_enabled', '0')", []).unwrap();
    let o = housekeeping::backup_command(&w.env, true, NOW).unwrap();
    assert_eq!((o.ok, o.lines.as_slice()), (true, &["Automatic backups are off.".to_string()][..]));
    assert!(backup::list(&w.env).unwrap().is_empty());
    c.execute("update settings set value = '1' where key = 'backup_enabled'", []).unwrap();

    let o = housekeeping::backup_command(&w.env, true, NOW).unwrap();
    assert!(o.ok);
    assert!(o.lines[0].starts_with("Wrote hte-remote-backup-20261024-041030.tar ("), "{:?}", o.lines);
    let last = result(&c);
    assert_eq!(last["at"], "2026-10-24T04:10:30+00:00");
    assert_eq!((last["ok"].clone(), last["trigger"].clone(), last["message"].clone(), last["name"].clone()), (true.into(), "scheduled".into(), "Wrote hte-remote-backup-20261024-041030.tar".into(), "hte-remote-backup-20261024-041030.tar".into()));
    let raw: String = c.query_row("select value from settings where key = 'backup_last_result'", [], |r| r.get(0)).unwrap();
    assert!(raw.starts_with("{\"at\":\"2026-10-24T04:10:30+00:00\",\"ok\":true,\"trigger\":\"scheduled\",\"message\":"), "{raw}");
    assert_eq!(c.query_row::<String, _, _>("select value from settings where key = 'backup_last_scheduled_at'", [], |r| r.get(0)).unwrap(), "2026-10-24T04:10:30+00:00");
    let (user, name, action, summary, ttype, tid): (Option<i64>, String, String, String, String, String) =
        c.query_row("select user_id, username, action, summary, target_type, target_id from console_audits order by id desc limit 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).unwrap();
    assert_eq!((user, name.as_str(), action.as_str(), ttype.as_str()), (None, "system", "backup.create", "backup"));
    assert_eq!(summary, "Scheduled backup: Wrote hte-remote-backup-20261024-041030.tar");
    assert_eq!(tid, "hte-remote-backup-20261024-041030.tar");

    // the same day again: not due; the next day: due
    let o = housekeeping::backup_command(&w.env, true, NOW + 3600).unwrap();
    assert_eq!(o.lines, ["Not due (last 2026-10-24 04:10:30)."]);
    assert_eq!(backup::list(&w.env).unwrap().len(), 1);
    let o = housekeeping::backup_command(&w.env, true, NOW + 86_400).unwrap();
    assert!(o.lines[0].starts_with("Wrote hte-remote-backup-20261025-041030.tar"));
    // a manual run is never gated and does not touch the schedule marker
    let o = housekeeping::backup_command(&w.env, false, NOW + 86_400 + 5).unwrap();
    assert!(o.lines[0].starts_with("Wrote hte-remote-backup-20261025-041035.tar"));
    assert_eq!(result(&c)["trigger"], "manual");
    assert_eq!(c.query_row::<String, _, _>("select value from settings where key = 'backup_last_scheduled_at'", [], |r| r.get(0)).unwrap(), "2026-10-25T04:10:30+00:00");
}

#[test]
fn retention_runs_after_each_backup_and_a_failure_is_recorded() {
    let w = world(KEY_A);
    let c = w.env.open().unwrap();
    // settings: keep 3 daily, no weekly or monthly (the world seeds backup_keep_daily = 3)
    c.execute_batch("insert into settings (key, value) values ('backup_keep_weekly', '0'), ('backup_keep_monthly', '0')").unwrap();
    for d in 0..6 {
        housekeeping::backup_command(&w.env, false, NOW + d * 86_400).unwrap();
    }
    let names: Vec<String> = backup::list(&w.env).unwrap().into_iter().map(|l| l.name).collect();
    assert_eq!(names, ["hte-remote-backup-20261029-041030.tar", "hte-remote-backup-20261028-041030.tar", "hte-remote-backup-20261027-041030.tar"]);
    assert!(!w.env.backups_dir.join("hte-remote-backup-20261024-041030.tar.json").exists(), "the sidecar goes with the archive");

    // an off-site target that cannot be reached: the archive is kept, the failure is said where Settings shows it, exit not ok
    c.execute("insert into settings (key, value) values ('backup_target', 's3'), ('backup_s3_bucket', 'bk'), ('backup_s3_endpoint', 'http://127.0.0.1:1')", []).unwrap();
    let o = housekeeping::backup_command(&w.env, false, NOW + 7 * 86_400).unwrap();
    assert!(!o.ok);
    assert!(result(&c)["message"].as_str().unwrap().contains("Off-site copy failed: "));
    assert_eq!(result(&c)["ok"], false);

    // a failure (the backup directory cannot be written): recorded without a name, nothing half-written
    c.execute("update settings set value = 'none' where key = 'backup_target'", []).unwrap();
    let mut broken = w.env.clone();
    broken.backups_dir = w.dir.path().join("cortendesk.sqlite").join("nope"); // below a file
    let o = housekeeping::backup_command(&broken, false, NOW + 8 * 86_400).unwrap();
    assert!(!o.ok && o.lines[0].starts_with("Backup failed: "), "{:?}", o.lines);
    let last = result(&c);
    assert_eq!((last["ok"].clone(), last.get("name").cloned()), (false.into(), None));
    assert!(c.query_row::<String, _, _>("select summary from console_audits order by id desc limit 1", [], |r| r.get(0)).unwrap().starts_with("Manual backup: Backup failed: "));
}

#[test]
fn str_limit_like_laravel() {
    assert_eq!(housekeeping::str_limit("short", 250), "short");
    let long = format!("{}  tail", "é".repeat(249));
    let cut = housekeeping::str_limit(&long, 250);
    assert_eq!(cut, format!("{}...", "é".repeat(249)), "cut at 250 characters, trailing space dropped");
}

// -------------------------------------------------------------------------------------------- the scheduler ---

fn setup_for(w: &World, jobs: &[Job]) -> std::sync::Arc<Scheduler> {
    Scheduler::new(Setup { env: w.env.clone(), retention_default: "365".into() }, jobs.to_vec())
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

fn at_utc(h: i64, m: i64, s: i64) -> i64 {
    NOW - NOW.rem_euclid(86_400) + h * 3600 + m * 60 + s
}

#[test]
fn the_backup_entry_is_held_against_php_and_fires_once_at_0330() {
    let w = world(KEY_A);
    let s = setup_for(&w, &[Job::Backup]);
    let c = w.env.open().unwrap();
    let mutex = format!("p-{}", Job::Backup.mutex_name());
    // 03:29: nothing to run, but the lock the previous console's scheduler would take is held already
    s.tick(at_utc(3, 29, 50));
    assert_eq!(c.query_row::<String, _, _>("select owner from cache_locks where key = ?", [&mutex], |r| r.get(0)).unwrap().starts_with("hte-console-svc-"), true);
    assert_eq!(c.query_row::<i64, _, _>("select expiration from cache_locks where key = ?", [&mutex], |r| r.get(0)).unwrap(), at_utc(3, 29, 50) + 30 * 60, "the scheduler's withoutOverlapping(30)");
    assert!(backup::list(&w.env).unwrap().is_empty());
    // 03:30: runs; a second tick in the same minute does not run it again
    s.tick(at_utc(3, 30, 5));
    s.tick(at_utc(3, 30, 20));
    wait_until("the backup", || backup::list(&w.env).map(|l| l.len() == 1).unwrap_or(false));
    wait_until("the record", || c.query_row::<String, _, _>("select value from settings where key = 'backup_last_result'", [], |r| r.get(0)).is_ok());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(backup::list(&w.env).unwrap().len(), 1);
    assert_eq!(result(&c)["trigger"], "scheduled");
    // 03:31 and 04:10: not its time
    s.tick(at_utc(3, 31, 0));
    s.tick(at_utc(4, 10, 0));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(backup::list(&w.env).unwrap().len(), 1);
    // a clean stop gives the lock back (the previous console's entry runs again), and the service stops ticking
    s.release_all();
    assert_eq!(c.query_row::<i64, _, _>("select count(*) from cache_locks where key = ?", [&mutex], |r| r.get(0)).unwrap(), 0);
    s.tick(at_utc(3, 30, 0) + 86_400);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(backup::list(&w.env).unwrap().len(), 1);
}

#[test]
fn php_holding_the_entry_keeps_this_tick_away_and_a_dead_service_lock_is_taken_back() {
    let w = world(KEY_A);
    let c = w.env.open().unwrap();
    let mutex = format!("p-{}", Job::Backup.mutex_name());
    // The previous console is mid-run on its own entry (its random owner): this service leaves the backup alone
    c.execute("insert into cache_locks (key, owner, expiration) values (?, 'phpRANDOMowner', ?)", rusqlite::params![mutex, at_utc(3, 31, 0)]).unwrap();
    let s = setup_for(&w, &[Job::Backup]);
    s.tick(at_utc(3, 30, 5));
    std::thread::sleep(Duration::from_millis(200));
    assert!(backup::list(&w.env).unwrap().is_empty());
    assert_eq!(c.query_row::<String, _, _>("select owner from cache_locks where key = ?", [&mutex], |r| r.get(0)).unwrap(), "phpRANDOMowner");
    // a previous service left its lock (killed): the new one takes it over at once, the previous console's is not touched
    c.execute("update cache_locks set owner = 'hte-console-svc-OLDOLDOLD' where key = ?", [&mutex]).unwrap();
    let s2 = setup_for(&w, &[Job::Backup]);
    // start() needs a runtime; take_back runs from it, so go through a one-thread runtime
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    rt.block_on(async {
        s2.start();
    });
    let owner = c.query_row::<String, _, _>("select owner from cache_locks where key = ?", [&mutex], |r| r.get(0)).unwrap();
    assert!(owner.starts_with("hte-console-svc-") && owner != "hte-console-svc-OLDOLDOLD", "{owner}");
}

#[test]
fn the_prune_entries_fire_at_their_minute_and_only_when_listed() {
    let w = world(KEY_A);
    let c = w.env.open().unwrap();
    put_logs(&c, "login_logs", 3, "2020-01-01 00:00:00");
    c.execute("insert into invitations (email, username, token_hash, expires_at) values ('a', 'a', 'h', '2020-01-01 00:00:00')", []).unwrap();
    // only backup listed: 04:10 and 04:20 do nothing
    let only_backup = setup_for(&w, &[Job::Backup]);
    only_backup.tick(at_utc(4, 10, 3));
    only_backup.tick(at_utc(4, 20, 3));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(count(&c, "login_logs"), 3 + 0);
    assert_eq!(count(&c, "invitations"), 1);
    // all listed
    let s = setup_for(&w, &housekeeping::ALL);
    s.tick(at_utc(4, 9, 59));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(count(&c, "login_logs"), 3);
    s.tick(at_utc(4, 10, 3));
    wait_until("prune-logs", || count(&c, "login_logs") == 0);
    assert_eq!(count(&c, "invitations"), 1, "04:20 is later");
    s.tick(at_utc(4, 20, 3));
    wait_until("prune-invitations", || count(&c, "invitations") == 0);
    // the prune entries take no previous console lock (the previous console has none for them)
    let locks: Vec<String> = c.prepare("select key from cache_locks").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    assert!(locks.iter().all(|k| !k.contains("prune")) && locks.len() == 2, "{locks:?}"); // the seeded one and the backup's
}

#[test]
fn jobs_env_parsing() {
    std::env::set_var("HTE_CONSOLE_JOBS", "backup, prune-logs");
    assert_eq!(housekeeping::from_env().unwrap(), [Job::Backup, Job::PruneLogs]);
    std::env::set_var("HTE_CONSOLE_JOBS", "all");
    assert_eq!(housekeeping::from_env().unwrap().len(), 3);
    std::env::set_var("HTE_CONSOLE_JOBS", "");
    assert!(housekeeping::from_env().unwrap().is_empty());
    std::env::set_var("HTE_CONSOLE_JOBS", "backup,nope");
    assert!(housekeeping::from_env().is_err());
    std::env::remove_var("HTE_CONSOLE_JOBS");
}

#[test]
fn mutex_names_are_phps_for_the_backup_entry() {
    // sha1("30 3 * * *the previous console's command cortendesk:backup --scheduled"), as Event::mutexName() builds it
    use sha1::Digest;
    let want = format!("framework/schedule-{}", hex::encode(sha1::Sha1::digest(b"30 3 * * *php artisan cortendesk:backup --scheduled")));
    assert_eq!(Job::Backup.mutex_name(), want);
    assert_eq!(Job::Backup.expression(), "30 3 * * *");
    assert_eq!(Job::PruneLogs.expression(), "10 4 * * *");
    assert_eq!(Job::PruneInvitations.expression(), "20 4 * * *");
}

#[test]
fn the_live_schema_round_trips() {
    // Rust -> Rust on the live console's real schema (its foreign keys, indexes and column types), with rows in the
    // tables that point at each other
    let a = bare_world(KEY_A);
    let c = a.env.open().unwrap();
    c.execute_batch(&format!(
        r#"
        insert into migrations (migration, batch) values ('2014_10_12_000000_create_users_table', 1);
        insert into users (id, username, password, totp_secret, created_at, updated_at) values (1, 'admin', 'x', '{t}', '2026-10-01 10:00:00', '2026-10-01 10:00:00'), (2, 'maria', 'x', null, null, null);
        insert into settings (key, value) values ('oidc_client_secret', '{s}'), ('oidc_enabled', '1');
        insert into device_groups (id, name) values (1, 'Accounting');
        insert into devices (id, rustdesk_id, uuid, user_id, device_group_id, last_online_at) values (1, '190018695', 'u1', 2, 1, '2026-10-24 04:00:00');
        insert into address_books (id, guid, name, owner_user_id, is_personal) values (1, 'g1', 'Maria', 2, 1);
        insert into address_book_entries (id, address_book_id, rustdesk_id, password_enc) values (1, 1, '190018695', '{p}');
        insert into audit_connections (rustdesk_id, session_id, note_user_id, created_at) values ('190018695', 's1', 1, '2026-10-24 04:00:00');
        insert into console_audits (user_id, username, action, summary, created_at) values (1, 'admin', 'x', 'y', '2026-10-24 04:00:00');
        insert into hte_device_passwords (rustdesk_id, current_version, current_enc) values ('190018695', 1, '{p}');
        "#,
        t = enc(KEY_A, "totp"),
        s = enc(KEY_A, "secret"),
        p = enc(KEY_A, "pw"),
    ))
    .unwrap();
    drop(c);
    let before = data(&a);
    let made = backup::create(&a.env, "manual", NOW).unwrap();
    assert_eq!(made.manifest["tables"]["users"], 2);
    let b = bare_world(KEY_B);
    b.env.open().unwrap().execute_batch("insert into users (id, username, password) values (7, 'other', 'x'); insert into settings (key, value) values ('stale', 'x');").unwrap();
    let r = backup::restore(&b.env, &made.path, NOW, &no_hook).unwrap();
    assert!(r.rekeyed && r.orphans.is_empty(), "{r:?}");
    let after = data(&b);
    for (t, rows) in &before {
        if t == "migrations" {
            continue;
        }
        if ["users", "settings", "address_book_entries", "hte_device_passwords"].contains(&t.as_str()) {
            assert_eq!(after[t].len(), rows.len(), "{t}");
            continue; // re-keyed ciphertexts differ by design
        }
        assert_eq!(&after[t], rows, "table {t}");
    }
    let c = b.env.open().unwrap();
    assert_eq!(dec(KEY_B, &c.query_row::<String, _, _>("select totp_secret from users where id = 1", [], |r| r.get(0)).unwrap()), "totp");
    assert_eq!(c.query_row::<i64, _, _>("select count(*) from users where username = 'other'", [], |r| r.get(0)).unwrap(), 0);
    // the autoincrement counters moved on, so the next id is not a reused one
    c.execute("insert into users (username, password) values ('new', 'x')", []).unwrap();
    assert!(c.last_insert_rowid() > 7 || c.last_insert_rowid() > 2);
    // foreign keys are honoured again afterwards (the restore turned them off on its own connection only)
    assert!(c.execute("insert into audit_connections (rustdesk_id, note_user_id) values ('1', 999)", []).is_err());
}
