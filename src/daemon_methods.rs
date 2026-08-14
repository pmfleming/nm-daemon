use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::application::{Application, NetworksRequest, ProfileOperation, ProfileOperationResult};
use crate::daemon_runtime::DaemonRuntime;
use crate::error::{DomainError, ErrorOperation};
use crate::model::{
    NmObjectPath, WifiConnectTarget, WifiProfileUpdate, connect_target_for_network_key,
};
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

pub(crate) fn call_set_enabled(
    runtime: &Arc<DaemonRuntime>,
    params: SetEnabledParams,
) -> Result<Value> {
    runtime.call(ErrorOperation::Status, move |nm| {
        let result = Application::new(nm).set_wifi_enabled(params.enabled)?;
        api_data_value(
            Method::WifiSetEnabled.spec().response_key,
            &result,
            "serialize Wi-Fi power response JSON",
        )
    })
}

pub(crate) fn call_set_wwan_enabled(
    runtime: &Arc<DaemonRuntime>,
    params: SetEnabledParams,
) -> Result<Value> {
    runtime.call(ErrorOperation::Status, move |nm| {
        let result = Application::new(nm).set_wwan_enabled(params.enabled)?;
        api_data_value(
            Method::RadioSetWwanEnabled.spec().response_key,
            &result,
            "serialize WWAN power response JSON",
        )
    })
}

pub(crate) fn call_set_airplane_mode(
    runtime: &Arc<DaemonRuntime>,
    params: SetEnabledParams,
) -> Result<Value> {
    runtime.call(ErrorOperation::Status, move |nm| {
        let result = Application::new(nm).set_airplane_mode(params.enabled)?;
        api_data_value(
            Method::RadioSetAirplaneMode.spec().response_key,
            &result,
            "serialize airplane-mode response JSON",
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
    let background_scans = Arc::clone(runtime);
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

pub(crate) fn call_saved(runtime: &Arc<DaemonRuntime>) -> Result<Value> {
    runtime.call(ErrorOperation::ProfileOperation, |nm| {
        api_data_value(
            Method::WifiSaved.spec().response_key,
            &Application::new(nm).saved_profiles()?,
            "serialize saved Wi-Fi profile response JSON",
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
    let operation = match params {
        ProfileOperationParams::Details { path } => ProfileOperation::Details { path },
        ProfileOperationParams::Update { path, settings } => {
            ProfileOperation::Update { path, settings }
        }
        ProfileOperationParams::RevealSecret { path } => ProfileOperation::RevealSecret { path },
        ProfileOperationParams::Delete { path } => ProfileOperation::Delete { path },
        ProfileOperationParams::Forget {
            request_id,
            key,
            target,
        } => {
            let target = forget_target(key, target)?;
            let result = crate::forget::execute(runtime, request_id, target)?;
            return serialize_forget_result(&result);
        }
        ProfileOperationParams::SetAutoconnect { path, enabled } => {
            ProfileOperation::SetAutoconnect { path, enabled }
        }
        ProfileOperationParams::SetMacRandomization { path, randomized } => {
            ProfileOperation::SetMacRandomization { path, randomized }
        }
        ProfileOperationParams::Share { path } => ProfileOperation::Share { path },
        ProfileOperationParams::SetSendHostname { path, enabled } => {
            ProfileOperation::SetSendHostname { path, enabled }
        }
    };
    runtime.call(ErrorOperation::ProfileOperation, move |nm| {
        serialize_profile_result(Application::new(nm).profile_operation(operation)?)
    })
}

fn serialize_forget_result(result: &crate::forget::ForgetResult) -> Result<Value> {
    let result = serde_json::to_value(result)?;
    api_data_value(
        Method::WifiProfileOperation.spec().response_key,
        &result,
        "serialize forget response JSON",
    )
}

fn serialize_profile_result(result: ProfileOperationResult) -> Result<Value> {
    let result = match result {
        ProfileOperationResult::Updated { message } => {
            json!({ "status": "ok", "message": message })
        }
        ProfileOperationResult::Details(details) => serde_json::to_value(details)?,
        ProfileOperationResult::Secret(secret) => serde_json::to_value(secret)?,
        ProfileOperationResult::Share(payload) => serde_json::to_value(payload)?,
    };
    api_data_value(
        Method::WifiProfileOperation.spec().response_key,
        &result,
        "serialize profile operation response JSON",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetEnabledParams {
    enabled: bool,
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
    Details {
        path: NmObjectPath,
    },
    Update {
        path: NmObjectPath,
        settings: Box<WifiProfileUpdate>,
    },
    RevealSecret {
        path: NmObjectPath,
    },
    Delete {
        path: NmObjectPath,
    },
    Forget {
        #[serde(default)]
        request_id: String,
        #[serde(default)]
        key: Option<String>,
        #[serde(default)]
        target: Option<Box<WifiConnectTarget>>,
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

fn forget_target(
    key: Option<String>,
    target: Option<Box<WifiConnectTarget>>,
) -> Result<Box<WifiConnectTarget>> {
    let result = match (key, target) {
        (Some(key), None) => connect_target_for_network_key(&key, None).map(Box::new),
        (None, Some(target)) => Ok(target),
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "forget request must provide either key or target, not both"
        )),
        (None, None) => Err(anyhow::anyhow!("forget request must provide key or target")),
    };
    result.map_err(|error| {
        DomainError::validation(ErrorOperation::ProfileOperation, &error)
            .with_cause(error)
            .into()
    })
}
