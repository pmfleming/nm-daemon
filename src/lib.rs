mod actions;
mod app;
mod application;
mod auth;
mod cache;
mod cli;
mod client;
mod command;
mod connect;
mod connect_cancel;
mod connect_error;
mod connect_wait;
mod contract;
mod daemon;
mod daemon_band;
mod daemon_connect;
mod daemon_dispatch;
mod daemon_event;
mod daemon_forward;
mod daemon_hotspot;
mod daemon_methods;
mod daemon_qr;
mod daemon_runtime;
mod daemon_scan;
mod daemon_secret;
mod daemon_statistics;
mod daemon_status;
mod daemon_vpn;
mod deadline;
mod diagnose;
mod discovery;
mod error;
mod forget;
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated_config.rs"));
}
mod keyring;
mod logging;
mod model;
mod nl80211;
mod nm;
mod output;
mod protocol;
mod qr;
mod random;
mod variant;

#[cfg(test)]
mod test_support;

pub use app::{report_error, run};
