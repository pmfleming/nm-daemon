//! Privileged, network-scoped Cast policy. No caller-supplied firewall policy is
//! accepted over D-Bus: permission to enable discovery remains with NetworkManager.
mod firewall;
mod network;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use tokio::sync::{Mutex, Notify};
use zbus::{Connection, MatchRule, MessageStream, Proxy, message::Type};

pub(crate) const DESTINATION: &str = "org.laufan.NmCastPolicy";
pub(crate) const PATH: &str = "/org/laufan/NmCastPolicy";
pub(crate) const INTERFACE: &str = "org.laufan.NmCastPolicy1";
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Parser)]
#[command(about = "System firewall companion for nm-daemon's per-network Cast toggle")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the system service (requires CAP_NET_ADMIN).
    Serve {
        #[arg(long)]
        nft: PathBuf,
    },
    /// Synchronously reconcile policy from NetworkManager; cannot enable a profile.
    Reconcile,
    /// Close all Wi-Fi permissions, e.g. from ExecStopPost (requires CAP_NET_ADMIN).
    Close {
        #[arg(long)]
        nft: PathBuf,
    },
}

/// Entry point for the separate, system-service-only executable.
pub async fn run() -> Result<()> {
    match Args::parse().command {
        Command::Serve { nft } => serve(nft).await,
        Command::Close { nft } => {
            firewall::apply(&nft, &network::wifi_interfaces()?, &Default::default()).await
        }
        Command::Reconcile => {
            let conn = system_connection().await?;
            Proxy::new(&conn, DESTINATION, PATH, INTERFACE)
                .await?
                .call::<_, _, ()>("Reconcile", &())
                .await
                .context("reconcile Cast firewall policy")
        }
    }
}

async fn system_connection() -> Result<Connection> {
    Ok(zbus::connection::Builder::system()?
        .method_timeout(Duration::from_secs(10))
        .build()
        .await?)
}

struct Policy {
    conn: Connection,
    nft: PathBuf,
    // Explicit toggles, dispatcher calls and background refreshes must not apply
    // snapshots out of order. Hold this across both the NM read and nft commit.
    transaction: Mutex<()>,
}

impl Policy {
    async fn reconcile(&self) -> Result<()> {
        let _transaction = tokio::time::timeout(Duration::from_secs(2), self.transaction.lock())
            .await
            .context("Cast policy reconciliation is busy; retry")?;
        let wifi = network::wifi_interfaces()?;
        let snapshot = tokio::time::timeout(
            SNAPSHOT_TIMEOUT,
            network::enabled_interfaces(&self.conn, &wifi),
        )
        .await
        .context("timed out reading NetworkManager Cast policy")
        .and_then(|result| result);
        // On incomplete/unavailable NM data, withdraw every permission. The old
        // permission leases also expire if even nft or this service is unavailable.
        let enabled = snapshot.as_ref().cloned().unwrap_or_default();
        firewall::apply(&self.nft, &wifi, &enabled).await?;
        snapshot.map(|_| ())
    }
}

struct PolicyApi(Arc<Policy>);

#[zbus::interface(name = "org.laufan.NmCastPolicy1")]
impl PolicyApi {
    async fn reconcile(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        // zbus's no-argument dispatch otherwise ignores an unexpected body.
        if header.signature() != &zvariant::Signature::Unit {
            return Err(zbus::fdo::Error::InvalidArgs(
                "Reconcile takes no arguments".into(),
            ));
        }
        self.0
            .reconcile()
            .await
            .map_err(|error| zbus::fdo::Error::Failed(format!("{error:#}")))
    }
}

async fn serve(nft: PathBuf) -> Result<()> {
    if !nft.is_absolute() {
        bail!("--nft must be an absolute executable path");
    }
    // Install default-off before announcing readiness, even if NM is not up yet.
    firewall::apply(&nft, &network::wifi_interfaces()?, &Default::default()).await?;
    let conn = system_connection().await?;
    let policy = Arc::new(Policy {
        conn: conn.clone(),
        nft,
        transaction: Mutex::new(()),
    });
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(crate::nm::NM_DEST)?
        .path_namespace(crate::nm::NM_PATH)?
        .build();
    let mut signals = MessageStream::for_match_rule(rule, &conn, Some(32)).await?;
    // Drain independently of snapshots/nft so an NM signal burst cannot fill the
    // stream queue while we are waiting for replies on the same connection.
    let changed = Arc::new(Notify::new());
    let notify = changed.clone();
    let mut watcher = tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            signal?;
            notify.notify_one();
        }
        Err::<(), anyhow::Error>(anyhow::anyhow!("NetworkManager signal stream closed"))
    });
    conn.object_server()
        .at(PATH, PolicyApi(policy.clone()))
        .await?;
    conn.request_name(DESTINATION).await?;
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = refresh.tick() => {},
            result = &mut watcher => {
                result??;
                bail!("NetworkManager signal watcher stopped");
            },
            _ = changed.notified() => {
                // Coalesce bursts; the timed lease refresh is also the fallback
                // for hotplug, NM restart and missed signals.
                tokio::time::sleep(Duration::from_millis(100)).await;
            },
        }
        if let Err(error) = policy.reconcile().await {
            eprintln!("Cast policy reconciliation failed (default-off): {error:#}");
        }
    }
}
