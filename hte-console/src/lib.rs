//! hte-console (HTE Remote console, in Rust, step by step). Phase 0: shadow proxy, sanitiser, replay.
//! Phase 1: the device endpoints (heartbeat, sysinfo, audit, version) answered natively.
//! Phase 2: the RustDesk client's sign-in (password, TOTP, OIDC) answered natively.
//! Phase 3: the server link (policy with HTE Remote's scope, local addresses, refusals) and the scheduled sweeps.
//! Phase 4: the bearer-token client endpoints (address books, group tab, audit note, server-config) answered natively.
//! Phase 5: the admin automation API (`/api/v1/*`, token-guarded) and the client's `--assign` answered natively.
//! Phase 7: the console pages (Laravel session, CSRF, templates, htmx), one group of pages at a time.
//! Phase 6: local backups (the previous console's archive format), restore, log and invitation pruning, and their daily scheduler entries.
/// HTE Remote's version: the console's crate version is the version of the whole server image (`hte-rd-server:<this>`).
pub const REMOTE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod admin;
pub mod admin_ctl;
pub mod api;
pub mod audit;
pub mod backup;
pub mod backup_ftp;
pub mod backup_remote;
pub mod backup_s3;
pub mod cache;
pub mod client;
pub mod config;
pub mod device_cli;
pub mod duplicates;
pub mod email;
pub mod envvar;
pub mod update_check;
pub mod fake_idp;
pub mod sqlite;
pub mod fixture;
pub mod housekeeping;
pub mod ice;
pub mod laravel;
pub mod link;
pub mod maintenance;
pub mod migrate;
pub mod mail;
pub mod multipart;
pub mod oidc;
pub mod pagereplay;
pub mod pages;
pub mod passwords;
pub mod passwords_sweep;
pub mod php;
pub mod proxy;
pub mod prune;
pub mod reach;
pub mod replay;
pub mod resolver;
pub mod sanitise;
pub mod seed;
pub mod signin;
pub mod snapshot;
pub mod strategy;
pub mod sweeps;
pub mod sync;
pub mod tarfile;
pub mod totp;
pub mod validate;
pub mod webreplay;
