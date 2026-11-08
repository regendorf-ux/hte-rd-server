//! CortenDesk 1.23.0 (#159): two devices that share a hardware ID (so a UUID) and both kept reporting in well after the later one
//! appeared are two machines cloned from one image, not one reinstalled machine. Before that, every pair with a shared UUID was flagged.

use hte_console::duplicates::Duplicates;
use rusqlite::Connection;

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(include_str!("schema_live.sql")).unwrap();
    c
}

fn device(c: &Connection, id: i64, uuid: &str, created: &str, last_seen: Option<&str>) {
    c.execute(
        "insert into devices (id, rustdesk_id, uuid, hostname, username, os, status, created_at, updated_at, last_online_at) values (?1, ?2, ?3, ?4, 'dana', 'windows / Windows 11', 'active', ?5, ?5, ?6)",
        rusqlite::params![id, format!("10{id}"), uuid, format!("PC-{id}"), created, last_seen],
    )
    .unwrap();
}

#[test]
fn a_shared_uuid_is_a_reinstall_until_both_keep_reporting() {
    // the old install stopped reporting when the new one appeared: one machine, reinstalled
    let c = db();
    device(&c, 1, "shared-uuid", "2026-01-01 08:00:00", Some("2026-01-10 09:00:00"));
    device(&c, 2, "shared-uuid", "2026-01-10 09:05:00", Some("2026-01-11 09:00:00"));
    let d = Duplicates::all(&c).unwrap();
    assert!(d.has(1) && d.has(2), "a reinstall is still flagged");

    // both reported in more than an hour after the second appeared: two machines
    let c = db();
    device(&c, 1, "shared-uuid", "2026-01-01 08:00:00", Some("2026-01-12 09:00:00"));
    device(&c, 2, "shared-uuid", "2026-01-10 09:05:00", Some("2026-01-11 09:00:00"));
    let d = Duplicates::all(&c).unwrap();
    assert!(!d.has(1) && !d.has(2), "clones that both report are separate machines");

    // the old one reported only within the hour after the second appeared: still a reinstall
    let c = db();
    device(&c, 1, "shared-uuid", "2026-01-01 08:00:00", Some("2026-01-10 09:30:00"));
    device(&c, 2, "shared-uuid", "2026-01-10 09:05:00", Some("2026-01-11 09:00:00"));
    assert!(Duplicates::all(&c).unwrap().has(1));

    // a device that never reported decides nothing
    let c = db();
    device(&c, 1, "shared-uuid", "2026-01-01 08:00:00", None);
    device(&c, 2, "shared-uuid", "2026-01-10 09:05:00", Some("2026-01-11 09:00:00"));
    assert!(Duplicates::all(&c).unwrap().has(1));
}
