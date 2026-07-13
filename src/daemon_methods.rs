use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::application::{Application, NetworksRequest, ProfileOperation, ProfileOperationResult};
use crate::daemon_runtime::DaemonRuntime;
use crate::error::ErrorOperation;
use crate::model::NmObjectPath;
use crate::output::api_data_value;
use crate::protocol::Method;

pub(crate) fn call_status(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    runtime.call(ErrorOperation::Status, |nm| {
        let application = Application::new(nm);
        api_data_value(
            Method::WifiStatus.spec().response_key,
            &application.status()?,
            "serialize Wi-Fi status response JSON",
        )
    })
}

pub(crate) fn call_connectivity(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    runtime.call(ErrorOperation::Connectivity, |nm| {
        let application = Application::new(nm);
        api_data_value(
            Method::NetworkConnectivity.spec().response_key,
            &application.connectivity()?,
            "serialize connectivity response JSON",
        )
    })
}

pub(crate) fn call_networks(runtime: &Arc<DaemonRuntime>, params: NetworksParams) -> Result<Value> {
    let background_scans = runtime.background_scans();
    runtime.call(ErrorOperation::Networks, move |nm| {
        let application = Application::new(nm);
        let result = application
            .with_background_scans(&background_scans)
            .networks(NetworksRequest::new(
                params.cached,
                params.refresh_cache,
                Duration::from_secs(params.refresh_timeout.unwrap_or(10)),
            ))?;
        api_data_value(
            Method::WifiNetworks.spec().response_key,
            &result.networks,
            "serialize network response JSON",
        )
    })
}

pub(crate) fn call_disconnect(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    runtime.call(ErrorOperation::Disconnect, |nm| {
        api_data_value(
            Method::WifiDisconnect.spec().response_key,
            &Application::new(nm).disconnect()?,
            "serialize disconnect response JSON",
        )
    })
}

pub(crate) fn call_profile_operation(
    runtime: &Arc<DaemonRuntime>,
    params: ProfileOperationParams,
) -> Result<Value> {
    runtime.call(ErrorOperation::ProfileOperation, move |nm| {
        let result = Application::new(nm).profile_operation(params.into())?;
        let result = match result {
            ProfileOperationResult::Updated { message } => {
                json!({ "status": "ok", "message": message })
            }
            ProfileOperationResult::Share(payload) => serde_json::to_value(payload)?,
        };
        api_data_value(
            Method::WifiProfileOperation.spec().response_key,
            &result,
            "serialize profile operation response JSON",
        )
    })
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NetworksParams {
    cached: bool,
    refresh_cache: bool,
    refresh_timeout: Option<u64>,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ProfileOperationParams {
    Delete {
        path: NmObjectPath,
    },
    SetAutoconnect {
        path: NmObjectPath,
        enabled: bool,
    },
    SetMacRandomization {
        path: NmObjectPath,
        randomized: bool,
    },
    Share {
        path: NmObjectPath,
    },
    SetSendHostname {
        path: NmObjectPath,
        enabled: bool,
    },
}

impl From<ProfileOperationParams> for ProfileOperation {
    fn from(value: ProfileOperationParams) -> Self {
        match value {
            ProfileOperationParams::Delete { path } => Self::Delete { path },
            ProfileOperationParams::SetAutoconnect { path, enabled } => {
                Self::SetAutoconnect { path, enabled }
            }
            ProfileOperationParams::SetMacRandomization { path, randomized } => {
                Self::SetMacRandomization { path, randomized }
            }
            ProfileOperationParams::Share { path } => Self::Share { path },
            ProfileOperationParams::SetSendHostname { path, enabled } => {
                Self::SetSendHostname { path, enabled }
            }
        }
    }
}
