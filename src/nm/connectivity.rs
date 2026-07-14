use anyhow::{Context, Result};

use super::{NM_IFACE, NM_PATH, Nm};
use crate::model::ConnectivityStatus;

impl Nm {
    pub(crate) fn connectivity_check(&self) -> Result<ConnectivityStatus> {
        let nm = self.proxy(NM_PATH, NM_IFACE)?;
        let code: u32 = nm
            .call("CheckConnectivity", &())
            .context("CheckConnectivity")?;
        let status = ConnectivityStatus::from_nm_code(code);
        tracing::debug!(
            connectivity_code = status.code,
            connectivity_state = status.state,
            captive_portal = status.captive_portal,
            full = status.full,
            "NetworkManager connectivity check completed"
        );
        Ok(status)
    }
}
