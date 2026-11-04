//! Phase 9: who owns the database schema once the previous console is gone.
//!
//! **Decision.** The previous console created the schema (41 migrations, the last one HTE Remote's `hte_device_passwords`), and
//! hte-console never changed an existing table. From the all-in-one image on, hte-console owns the schema in the narrowest
//! way that lets a later change happen without the previous console:
//! - it does NOT create the previous console's tables. On start it checks that every one of the previous console's 41 migrations is recorded in the
//!   `migrations` table and refuses to run otherwise (an empty or older database must come from the CortenDesk image once, or
//!   from a restored backup: the all-in-one image is an upgrade path for a console that already has its data, not an installer);
//! - it applies its own **additive** migrations (`OWN`: new tables or new columns only, written `create ... if not exists`,
//!   never touching a previous-console table), each recorded in the same `migrations` table under its own name with the next batch
//!   number, as Laravel records one. The CortenDesk image, should it ever come back, ignores names it has no file for;
//! - a name recorded that is in neither list (a newer the previous console release, a migration of a future HTE change) is reported, not
//!   an error.
//! A future schema change is therefore a new entry in `OWN`, in this file, with a test: nothing else.
//!
//! The list of the previous console's migrations is the directory `database/migrations` of the previous console's fork (`hte` branch,
//! 1.15.0-hte.1); `scripts/check-migrations.sh <fork>` compares the two.

use rusqlite::{params, Connection};

/// The previous console's migrations (file names without their extension), 1.15.0-hte.1.
pub const PHP_MIGRATIONS: [&str; 41] = [
    "0001_01_01_000000_create_users_table",
    "0001_01_01_000001_create_cache_table",
    "0001_01_01_000002_create_jobs_table",
    "2026_07_21_000001_create_core_domain_tables",
    "2026_07_21_000002_create_address_book_tables",
    "2026_07_21_000003_create_audit_and_settings_tables",
    "2026_07_21_000004_add_hash_to_entries_and_alarm_logs",
    "2026_07_22_000001_create_device_group_user_table",
    "2026_07_22_000002_create_user_group_user_table",
    "2026_07_22_000003_create_device_group_user_group_table",
    "2026_07_24_000001_create_console_audits_table",
    "2026_07_24_000002_create_api_tokens_table",
    "2026_07_24_000003_add_status_to_devices_table",
    "2026_07_24_000004_create_group_accesses_table",
    "2026_07_24_000005_add_two_factor_to_users",
    "2026_07_24_000006_add_oidc_to_users",
    "2026_07_24_000007_create_oidc_auth_requests_table",
    "2026_07_25_000001_create_strategies_tables",
    "2026_07_25_000002_add_strategy_state_to_devices",
    "2026_07_25_000010_create_invitations_table",
    "2026_07_25_000011_create_trusted_devices_table",
    "2026_07_25_000020_create_roles_table",
    "2026_07_25_000021_add_role_id_to_users_table",
    "2026_07_25_000030_create_password_resets_table",
    "2026_07_26_000001_add_disconnect_request_to_audit_connections",
    "2026_08_06_000001_add_devices_columns_to_users_table",
    "2026_08_12_000001_create_notification_deliveries_table",
    "2026_08_12_000020_add_setup_wizard_state_to_users",
    "2026_08_13_000010_add_device_sort_to_users_table",
    "2026_08_17_000010_create_client_downloads_table",
    "2026_08_21_000010_add_registered_ip_to_devices_table",
    "2026_08_21_000020_create_device_presence_notification_state_tables",
    "2026_08_21_000030_add_offline_claims_to_device_presence_notification_states",
    "2026_08_24_000010_create_strategy_revision_history",
    "2026_08_24_000030_add_strategy_compliance_columns",
    "2026_09_29_000010_add_note_to_audit_connections",
    "2026_09_29_000020_add_server_policy_columns_to_devices_table",
    "2026_10_07_000010_add_retry_columns_to_notification_deliveries_table",
    "2026_10_08_000010_add_theme_to_users_table",
    "2026_10_08_000020_create_device_duplicate_dismissals_table",
    "2026_10_16_900001_create_hte_device_passwords_table",
];

/// An additive migration of our own.
pub struct Own {
    pub name: &'static str,
    /// Idempotent SQL (`create table if not exists`, `create index if not exists`): safe to run again over a table that
    /// an earlier hte-console made without recording it (phase 8 created `hte_console_sessions` at start).
    pub sql: &'static str,
}

pub const OWN: &[Own] = &[
    Own { name: "2026_10_25_900001_create_hte_console_sessions_table", sql: crate::pages::websession::SCHEMA },
    Own { name: "2026_11_04_900001_create_relay_sessions_and_connection_paths", sql: crate::path::SCHEMA },
];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The previous console migrations the database does not record (an error when not empty)
    pub php_missing: Vec<String>,
    /// recorded names that are in neither list
    pub unknown: Vec<String>,
    /// our migrations not recorded yet
    pub own_pending: Vec<&'static str>,
    pub php_recorded: usize,
}

fn recorded(c: &Connection) -> Result<Vec<String>, String> {
    let has: i64 = c
        .query_row(r#"select count(*) from sqlite_master where type = 'table' and name = 'migrations'"#, [], |r| r.get(0))
        .map_err(|e| format!("database: {e}"))?;
    if has == 0 {
        return Err("the database has no migrations table: it was never set up by the previous console. This image does not create the previous console's tables; start the previous console's image once on this data, or restore a backup.".into());
    }
    let mut st = c.prepare(r#"select "migration" from "migrations""#).map_err(|e| format!("database: {e}"))?;
    let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(|e| format!("database: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|e| format!("database: {e}"))
}

/// Read-only: what is recorded, what is missing, what is ours and pending.
pub fn check(c: &Connection) -> Result<Report, String> {
    let have = recorded(c)?;
    let php_missing: Vec<String> = PHP_MIGRATIONS.iter().filter(|m| !have.iter().any(|h| h == *m)).map(|m| m.to_string()).collect();
    let unknown = have.iter().filter(|h| !PHP_MIGRATIONS.contains(&h.as_str()) && !OWN.iter().any(|o| o.name == h.as_str())).cloned().collect();
    let own_pending = OWN.iter().filter(|o| !have.iter().any(|h| h == o.name)).map(|o| o.name).collect();
    Ok(Report { php_recorded: PHP_MIGRATIONS.len() - php_missing.len(), php_missing, unknown, own_pending })
}

/// Check, then apply our pending migrations, each in its own transaction (DDL is transactional in SQLite): the schema
/// SQL and the `migrations` row commit together or not at all. Refuses when a previous-console migration is missing.
pub fn run(c: &Connection) -> Result<Report, String> {
    let r = check(c)?;
    if !r.php_missing.is_empty() {
        return Err(format!(
            "the database is older than the previous console 1.15.0-hte.1 this version ports: {} migration(s) are not recorded (first: {}). Start the previous console's image once on this data, or restore a backup. Nothing was changed.",
            r.php_missing.len(),
            r.php_missing[0]
        ));
    }
    for name in &r.own_pending {
        let own = OWN.iter().find(|o| o.name == *name).ok_or("migration list changed under us")?;
        c.execute_batch("BEGIN IMMEDIATE").map_err(|e| format!("{name}: {e}"))?;
        let done = c.execute_batch(own.sql).map_err(|e| format!("{name}: {e}")).and_then(|_| {
            // recheck inside the lock: another hte-console may have recorded it a moment ago
            let n: i64 = c.query_row(r#"select count(*) from "migrations" where "migration" = ?"#, params![name], |r| r.get(0)).map_err(|e| format!("{name}: {e}"))?;
            if n == 0 {
                let batch: i64 = c.query_row(r#"select coalesce(max("batch"), 0) + 1 from "migrations""#, [], |r| r.get(0)).map_err(|e| format!("{name}: {e}"))?;
                c.execute(r#"insert into "migrations" ("migration", "batch") values (?, ?)"#, params![name, batch]).map_err(|e| format!("{name}: {e}"))?;
            }
            Ok(())
        });
        match done {
            Ok(()) => c.execute_batch("COMMIT").map_err(|e| format!("{name}: {e}"))?,
            Err(e) => {
                let _ = c.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
        tracing::info!(migration = *name, "applied our migration");
    }
    check(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(with: &[&str]) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(r#"create table "migrations" ("id" integer primary key autoincrement not null, "migration" varchar not null, "batch" integer not null)"#).unwrap();
        c.execute_batch(r#"create table "audit_connections" ("id" integer primary key autoincrement not null, "rustdesk_id" varchar not null)"#).unwrap();
        for (i, m) in with.iter().enumerate() {
            c.execute(r#"insert into "migrations" ("migration", "batch") values (?, ?)"#, params![m, (i / 10 + 1) as i64]).unwrap();
        }
        c
    }

    #[test]
    fn the_php_list_is_sorted_unique_and_ends_with_htes() {
        let mut v = PHP_MIGRATIONS.to_vec();
        v.sort();
        assert_eq!(v, PHP_MIGRATIONS.to_vec(), "same order as Laravel runs them");
        v.dedup();
        assert_eq!(v.len(), 41);
        assert!(PHP_MIGRATIONS[40].contains("hte_device_passwords"));
    }

    #[test]
    fn applies_ours_once_and_records_it_in_the_next_batch() {
        let c = db(&PHP_MIGRATIONS);
        let before = check(&c).unwrap();
        assert_eq!(before.own_pending.len(), OWN.len());
        assert_eq!(before.php_recorded, 41);
        let after = run(&c).unwrap();
        assert!(after.own_pending.is_empty() && after.php_missing.is_empty() && after.unknown.is_empty());
        let batch: i64 = c.query_row(r#"select "batch" from "migrations" where "migration" = ?"#, params![OWN[0].name], |r| r.get(0)).unwrap();
        assert_eq!(batch, 6, "the previous console's last batch is 5 in this fixture (41 rows, 10 per batch), ours is the next");
        let second: i64 = c.query_row(r#"select "batch" from "migrations" where "migration" = ?"#, params![OWN[1].name], |r| r.get(0)).unwrap();
        assert_eq!(second, 7, "each pending migration of ours takes the next batch");
        let t: i64 = c.query_row(r#"select count(*) from sqlite_master where name = 'hte_console_sessions'"#, [], |r| r.get(0)).unwrap();
        assert_eq!(t, 1);
        // again: nothing to do, no second row
        run(&c).unwrap();
        let n: i64 = c.query_row(r#"select count(*) from "migrations" where "migration" = ?"#, params![OWN[0].name], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn the_connection_path_migration_keeps_the_rows_it_finds() {
        let c = db(&PHP_MIGRATIONS);
        c.execute(r#"insert into "audit_connections" ("rustdesk_id") values ('123456789')"#, []).unwrap();
        run(&c).unwrap();
        let (id, path, relay): (String, Option<String>, Option<i64>) =
            c.query_row(r#"select "rustdesk_id", "path", "relay_session_id" from "audit_connections""#, [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((id.as_str(), path, relay), ("123456789", None, None), "an old row reads as 'unknown'");
        let t: i64 = c.query_row(r#"select count(*) from sqlite_master where name = 'relay_sessions'"#, [], |r| r.get(0)).unwrap();
        assert_eq!(t, 1);
    }

    #[test]
    fn adopts_a_table_phase_8_made_without_recording_it() {
        let c = db(&PHP_MIGRATIONS);
        c.execute_batch(crate::pages::websession::SCHEMA).unwrap();
        c.execute(r#"insert into "hte_console_sessions" ("id_hash", "payload", "created_at", "last_activity") values ('h', 'p', 1, 1)"#, []).unwrap();
        run(&c).unwrap();
        let n: i64 = c.query_row(r#"select count(*) from "hte_console_sessions""#, [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "the rows of an adopted table stay");
    }

    #[test]
    fn refuses_a_database_missing_a_php_migration_and_changes_nothing() {
        let c = db(&PHP_MIGRATIONS[..40]);
        let e = run(&c).unwrap_err();
        assert!(e.contains("1 migration") && e.contains("hte_device_passwords"), "{e}");
        let t: i64 = c.query_row(r#"select count(*) from sqlite_master where name = 'hte_console_sessions'"#, [], |r| r.get(0)).unwrap();
        assert_eq!(t, 0);
    }

    #[test]
    fn refuses_a_database_php_never_set_up() {
        let c = Connection::open_in_memory().unwrap();
        assert!(run(&c).unwrap_err().contains("no migrations table"));
    }

    #[test]
    fn a_newer_php_migration_is_reported_not_refused() {
        let mut names: Vec<&str> = PHP_MIGRATIONS.to_vec();
        names.push("2027_01_01_000001_something_new");
        let c = db(&names);
        let r = run(&c).unwrap();
        assert_eq!(r.unknown, vec!["2027_01_01_000001_something_new".to_string()]);
    }

    #[test]
    fn our_names_do_not_collide_with_php_s() {
        for o in OWN {
            assert!(!PHP_MIGRATIONS.contains(&o.name));
        }
    }
}
