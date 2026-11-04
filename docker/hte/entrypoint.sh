#!/bin/sh
# HTE Remote server container bootstrap: what the previous console's image did at start that still matters here. Brings the data directory to a state hbbs, hbbr and hte-console can start from, checks the database schema, then
# hands off to supervisord. Runs as uid 82 (see Dockerfile.hte): nothing here needs root.
set -e

# `docker run IMAGE hte-console status`, `docker run IMAGE sh`: run what was asked, not the services (the deploy's checks use it).
if [ "$#" -gt 0 ]; then exec "$@"; fi

log() { echo "[hte-remote] $*"; }
die() { echo "[hte-remote] $*" >&2; exit 1; }
_is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# --- file descriptors --------------------------------------------------------
# Docker hosts often start containers with a soft limit of 1024 open files and a much higher hard limit; a few hundred
# devices need more (hbbr runs out of sockets). Raise the soft limit toward the hard one before supervisord starts, so every
# program inherits it. Never above the hard limit, never below what the container has.
_fd_want=65536
_fd_hard="$(ulimit -Hn)"
if _is_uint "$_fd_hard" && [ "$_fd_hard" -lt "$_fd_want" ]; then _fd_want="$_fd_hard"; fi
_fd_soft="$(ulimit -Sn)"
if _is_uint "$_fd_soft" && [ "$_fd_soft" -lt "$_fd_want" ]; then ulimit -Sn "$_fd_want" 2>/dev/null || true; fi
FD_LIMIT="$(ulimit -Sn)"
if _is_uint "$FD_LIMIT" && [ "$FD_LIMIT" -lt 4096 ]; then
    log "WARNING: only $FD_LIMIT open files allowed (hard limit $_fd_hard). Larger fleets need more: ulimits: nofile in compose."
fi

# --- who we are and where the data is ---------------------------------------
[ "$(id -u)" != 0 ] || die "refusing to run as root: the files would not be readable by the CortenDesk image's uid 82 on a rollback. Run with user: \"82:82\"."
RD_DIR=/data/rustdesk
[ -d /data ] && [ -w /data ] || die "/data is missing or not writable by uid $(id -u) (the data directory must belong to 82:82)."
[ -f /data/cortendesk.sqlite ] || die "/data/cortendesk.sqlite does not exist. This image does not set up a new console (the tables came from the CortenDesk image): mount the data of the CortenDesk stack, or restore a backup (README: "Upgrading from the CortenDesk image")."
if [ -z "${APP_KEY:-}" ] && [ ! -s /data/.app_key ]; then
    die "no APP_KEY and no /data/.app_key: the console cannot read its encrypted settings. Mount the data of the CortenDesk stack."
fi
mkdir -p "$RD_DIR" /data/backups
[ -w "$RD_DIR" ] || die "$RD_DIR is not writable by uid $(id -u) (it must belong to 82:82)."

# --- the environment's names --------------------------------------------------
# HTE Remote's settings are HTE_REMOTE_<X>. The CortenDesk image's names, CORTENDESK_<X>, are still read when the new one is unset or empty
# (an .env from before the rename), with a warning per old name; the old name is then removed from the environment, so hbbs, hbbr
# and hte-console see only the new one. (`docker exec ... hte-console` does not go through here: hte-console has the same fallback.)
for _old in $(env | sed -n 's/^\(CORTENDESK_[A-Za-z0-9_]*\)=.*/\1/p'); do
    _new="HTE_REMOTE_${_old#CORTENDESK_}"
    eval "_nv=\${$_new:-}; _ov=\${$_old:-}"
    if [ -z "$_nv" ] && [ -n "$_ov" ]; then
        export "$_new=$_ov"
        log "WARNING: $_old is the old name of $_new; it is read for now, rename it in .env"
    elif [ -n "$_ov" ]; then
        log "WARNING: $_old is ignored: $_new is set (remove the old name from .env)"
    fi
    unset "$_old"
done
unset _old _new _nv _ov

# --- the reverse proxy in front of the WebSocket ports -------------------------
# hbbs and hbbr (1.3.0) believe X-Forwarded-For on /ws/id and /ws/relay only from a proxy listed in TRUSTED_PROXIES (comma-separated
# CIDRs, the proxy's address as this container sees it). Unset, every web client looks like the proxy: one rate limit and one block
# list for all of them. The console reads the same variable (its own default, the private ranges, applies when unset).
if [ -z "${TRUSTED_PROXIES:-}" ]; then
    log "WARNING: TRUSTED_PROXIES is not set: web clients arriving through the reverse proxy all show the proxy's address to hbbs and hbbr. Set it to the proxy's address (README)."
fi

# --- log levels --------------------------------------------------------------
# HTE_REMOTE_LOG_LEVEL (CORTENDESK_LOG_LEVEL in the CortenDesk image, its one knob) sets hbbs and hbbr; the console has its own, HTE_CONSOLE_LOG, because the
# checklists read its info lines (sign-ins, jobs) while hbbs may run at warn. hbbs and hbbr only know off, error,
# warn, info, debug and trace, and an unknown word silences them, so map onto those.
_rl=info
if [ -n "${HTE_REMOTE_LOG_LEVEL:-}" ]; then
    _ll="$(echo "$HTE_REMOTE_LOG_LEVEL" | tr 'A-Z' 'a-z')"
    case "$_ll" in
        debug)                          _rl=info,hbbs=debug,hbbr=debug,hbb_common=debug ;;
        info|notice)                    _rl=info ;;
        warn|warning)                   _rl=warn ;;
        error|critical|alert|emergency) _rl=error ;;
        *) log "WARNING: HTE_REMOTE_LOG_LEVEL='$HTE_REMOTE_LOG_LEVEL' is not one of debug, info, notice, warning, error, critical; ignoring it" ;;
    esac
fi
export HBBS_RUST_LOG="${HBBS_RUST_LOG:-$_rl}"
export HTE_CONSOLE_LOG="${HTE_CONSOLE_LOG:-info}"

# --- the ID server's files ---------------------------------------------------
# A restore (Settings -> Backups) stages the server's files beside the live ones rather than overwriting what hbbs has open.
# Swap them in now, before hbbs starts and before the key check below could generate a fresh pair over a restored one.
for _f in id_ed25519 id_ed25519.pub db_v2.sqlite3; do
    if [ -f "$RD_DIR/$_f.restore" ]; then
        mv -f "$RD_DIR/$_f.restore" "$RD_DIR/$_f"
        [ "$_f" = db_v2.sqlite3 ] && rm -f "$RD_DIR/db_v2.sqlite3-wal" "$RD_DIR/db_v2.sqlite3-shm"
        log "adopted restored $_f"
    fi
done
# Generate the key pair only if there is none (an existing server always has one: clients hold its public half). Keys containing
# / or : are rejected: they end up in URLs, config strings and command lines, and hbbs skips them for the same reason.
if [ ! -f "$RD_DIR/id_ed25519" ]; then
    _n=0
    while [ "$_n" -lt 300 ]; do
        _pair="$(hte-rd-utils genkeypair)"
        _pub="$(echo "$_pair" | awk '/Public Key:/ {print $3}')"
        _sec="$(echo "$_pair" | awk '/Secret Key:/ {print $3}')"
        case "$_pub" in *[/:]*) _n=$((_n + 1)); continue ;; esac
        break
    done
    # No trailing newline: the key is compared byte for byte, and hbbs writes these files the same way.
    printf '%s' "$_sec" > "$RD_DIR/id_ed25519"
    printf '%s' "$_pub" > "$RD_DIR/id_ed25519.pub"
    chmod 600 "$RD_DIR/id_ed25519"
    log "generated the server key pair in $RD_DIR"
fi

# The link between hbbs and the console: hbbs pulls the device policy with this secret and the console signs web client
# tickets with it. /data/.server_secret is the CortenDesk image's file; kept, never rewritten when it exists.
if [ -z "${HTE_REMOTE_SERVER_SECRET:-}" ]; then
    if [ ! -s /data/.server_secret ]; then
        od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > /data/.server_secret
        chmod 600 /data/.server_secret
        log "generated the server link secret (persisted in the /data volume)"
    fi
    HTE_REMOTE_SERVER_SECRET="$(cat /data/.server_secret)"
fi
export HTE_REMOTE_SERVER_SECRET
# hbbs and the console are in this container now: loopback, no network hop
export HTE_REMOTE_CONSOLE_URL="${HTE_REMOTE_CONSOLE_URL:-http://127.0.0.1:8080}"

# --- what clients are told ----------------------------------------------------
# The public address clients use to reach this host; the relay address hbbs hands out derives from it unless set.
_public_host() {
    _h="${APP_URL:-}"; _h="${_h#*://}"; _h="${_h%%/*}"
    case "$_h" in
        \[*\]*) echo "${_h%%\]*}]" ;;
        *)      echo "${_h%%:*}" ;;
    esac
}
HOST="$(_public_host)"
case "$HOST" in
    localhost|127.0.0.1|"") die "APP_URL has no public hostname, so clients would be told the relay is at '${HOST:-?}:21117' and every session that needs it would hang. Set APP_URL to the address clients reach." ;;
esac
export HTE_REMOTE_ID_SERVER="${HTE_REMOTE_ID_SERVER:-$HOST:21116}"
export HTE_REMOTE_RELAY_SERVER="${HTE_REMOTE_RELAY_SERVER:-$HOST:21117}"
export RUSTDESK_RELAY_ADVERTISED="$HTE_REMOTE_RELAY_SERVER"
export HTE_CONSOLE_ID_SERVER="${HTE_CONSOLE_ID_SERVER:-$HTE_REMOTE_ID_SERVER}"
export HTE_CONSOLE_PUBLIC_KEY="${HTE_CONSOLE_PUBLIC_KEY:-$(cat "$RD_DIR/id_ed25519.pub")}"
export HTE_CONSOLE_PUBLIC_URL="${HTE_CONSOLE_PUBLIC_URL:-$APP_URL}"

# --- the database -------------------------------------------------------------
# Check that every migration the previous console ran is recorded and apply our own additive ones (migrate.rs). A database that fails the
# check stops the container here, with the reason in the log, rather than serving from a schema we do not know.
hte-console migrate || die "the database check failed (above). Nothing was changed."

log "ready: console on :8080 (sign-in $( [ "${HTE_CONSOLE_SIGNIN:-}" = 1 ] && echo on || echo OFF )), ID server on :21116, relay on :21117, ws on :21118/:21119; relay advertised as $RUSTDESK_RELAY_ADVERTISED"
log "$(hte-console version), hbbs/hbbr log level '$HBBS_RUST_LOG', $FD_LIMIT open files"
exec supervisord -c /etc/supervisord.conf
