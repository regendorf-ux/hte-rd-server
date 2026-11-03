// Added for HTE Remote on 2026-11-02. See HTE.md.
// This file is part of a modified version of cortendesk-server, distributed
// under the AGPL-3.0 like the original.

//! WebRTC signalling is off unless `HTE_REMOTE_WEBRTC` says on.
//!
//! A WebRTC session goes machine to machine (and through a TURN server when
//! the clients are given one), never through `hbbr`, so the relay gate cannot
//! see it. Per-person reach still decides who may start one, because the offer
//! travels in the punch hole request that `policy::check_initiator` and
//! `policy::check_target` judge first. Off, `hbbs` behaves as it did before
//! signalling existed: the offer is dropped, no route is opened, answers and
//! candidates are not passed on, and 1.5 clients fall back to their other
//! transports.

use hbb_common::log;

fn parse(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "y" | "yes" | "true" | "on")
    )
}

lazy_static::lazy_static! {
    static ref ON: bool = parse(std::env::var("HTE_REMOTE_WEBRTC").ok().as_deref());
}

pub fn enabled() -> bool {
    *ON
}

/// Said once at start, so the log shows which way it is.
pub fn announce() {
    if enabled() {
        log::info!("WebRTC signalling: on (HTE_REMOTE_WEBRTC)");
    } else {
        log::info!("WebRTC signalling: off; set HTE_REMOTE_WEBRTC=1 to pass RustDesk 1.5 WebRTC offers, answers and candidates");
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn only_a_clear_yes_turns_it_on() {
        for on in ["1", "yes", "Y", "true", "ON", " on "] {
            assert!(parse(Some(on)), "{on:?}");
        }
        for off in ["", "0", "no", "false", "off", "maybe", "2"] {
            assert!(!parse(Some(off)), "{off:?}");
        }
        assert!(!parse(None));
    }
}
