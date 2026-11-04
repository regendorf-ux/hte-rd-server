//! Phase 6: `cortendesk:prune-logs` and `cortendesk:prune-invitations` (1.15.0-hte.1), statement by statement.

use crate::laravel;
use crate::php::Val;
use crate::sqlite::{self as db, P};
use rusqlite::Connection;

/// `PruneLogs::TABLES`: each has a `created_at` column.
pub const LOG_TABLES: [&str; 7] = ["audit_connections", "audit_file_transfers", "login_logs", "alarm_logs", "console_audits", "notification_deliveries", "relay_sessions"]; // HTE: relay_sessions (path.rs)
const CHUNK: usize = 10_000;

/// The configured window: `(int) (Setting::get('log_retention_days', (string) config('cortendesk.log_retention_days')) ?: 0)`.
/// `default` is the env-backed config value (`HTE_REMOTE_LOG_RETENTION_DAYS`, 365 when unset).
pub fn retention_days(c: &Connection, default: &str) -> Result<i64, String> {
    let v = db::setting(c, "log_retention_days", default).map_err(|f| format!("{f:?}"))?;
    // `?: 0`: "", "0" and null are falsy; everything else is cast
    Ok(if v.is_empty() || v == b"0" { 0 } else { crate::php::str_to_int(&v) })
}

/// What the command printed, line by line.
pub struct Pruned {
    pub lines: Vec<String>,
    pub total: usize,
}

/// `cortendesk:prune-logs [--days=N]`: rows older than the window go, in chunks of 10 000 so the lock stays short.
/// `days` None = the configured window; 0 or less = nothing to do.
pub fn prune_logs(c: &Connection, now: i64, days: Option<i64>, default_days: &str) -> Result<Pruned, String> {
    let days = match days {
        Some(d) => d,
        None => retention_days(c, default_days)?,
    };
    if days <= 0 {
        return Ok(Pruned { lines: vec!["Log retention is disabled (0 days) — nothing to prune.".into()], total: 0 });
    }
    let cutoff = laravel::ts(now - days.saturating_mul(86_400));
    let mut lines = vec![];
    let mut total = 0;
    for table in LOG_TABLES {
        let mut deleted = 0;
        loop {
            // Laravel's SQLite grammar compiles delete-with-limit through rowid
            let sql = format!(r#"delete from "{table}" where "rowid" in (select "rowid" from "{table}" where "created_at" < ? limit {CHUNK})"#);
            let batch = db::exec(c, &sql, &[P(Val::str(&cutoff))]).map_err(|f| format!("{table}: {f:?}"))?;
            deleted += batch;
            if batch != CHUNK {
                break;
            }
        }
        if deleted > 0 {
            lines.push(format!("{table}: deleted {deleted}"));
        }
        total += deleted;
    }
    lines.push(format!("Pruned {total} log rows older than {days} days."));
    Ok(Pruned { lines, total })
}

/// `cortendesk:prune-invitations [--days=30]`
pub fn prune_invitations(c: &Connection, now: i64, days: i64) -> Result<String, String> {
    let days = days.max(0);
    let n = laravel::ts(now);
    let kept_for = laravel::ts(now - days.saturating_mul(86_400));
    let expired = db::exec(c, r#"delete from "invitations" where "accepted_at" is null and "expires_at" < ?"#, &[P(Val::str(&n))]).map_err(|f| format!("invitations: {f:?}"))?;
    let accepted = db::exec(c, r#"delete from "invitations" where "accepted_at" is not null and "accepted_at" < ?"#, &[P(Val::str(&kept_for))]).map_err(|f| format!("invitations: {f:?}"))?;
    let devices = db::exec(c, r#"delete from "trusted_devices" where "expires_at" < ?"#, &[P(Val::str(&n))]).map_err(|f| format!("trusted_devices: {f:?}"))?;
    Ok(format!("Pruned {expired} expired and {accepted} accepted invitation(s), {devices} trusted device(s)."))
}
