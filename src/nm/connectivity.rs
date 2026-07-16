use std::time::Instant;

use anyhow::{Context, Result};

use super::{NM_IFACE, NM_PATH, Nm};
use crate::model::ConnectivityStatus;

impl Nm {
    pub(crate) fn connectivity_check(&self) -> Result<ConnectivityStatus> {
        let started = Instant::now();
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let code: u32 = match nm.call("CheckConnectivity", &()) {
            Ok(code) => code,
            Err(error) => {
                tracing::warn!(
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %error,
                    "NetworkManager connectivity check failed"
                );
                return Err(error).context("CheckConnectivity");
            }
        };
        let status = ConnectivityStatus::from_nm_code(code);
        tracing::debug!(
            connectivity_code = status.code,
            connectivity_state = status.state,
            captive_portal = status.captive_portal,
            full = status.full,
            elapsed_ms = started.elapsed().as_millis(),
            "NetworkManager connectivity check completed"
        );
        Ok(status)
    }
}
