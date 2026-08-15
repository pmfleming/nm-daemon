use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;

use super::{EmptyParams, parse_params, parse_required_params, wrong_dispatch_group};
use crate::daemon_methods::{
    ProfileOperationParams, SetEnabledParams, call_connectivity, call_disconnect, call_networks,
    call_profile_operation, call_saved, call_set_airplane_mode, call_set_enabled,
    call_set_wwan_enabled, call_status,
};
use crate::daemon_runtime::DaemonRuntime;
use crate::daemon_secret::{SecretCapabilitiesParams, SecretProvideParams};
use crate::protocol::Method;

pub(super) fn dispatch(
    method: Method,
    params_json: &str,
    owner: Option<&str>,
    runtime: &Arc<DaemonRuntime>,
) -> Result<Value> {
    match method {
        Method::WifiStatus
        | Method::NetworkConnectivity
        | Method::WifiDisconnect
        | Method::WifiSaved => dispatch_empty(method, params_json, runtime),
        Method::WifiSetEnabled | Method::RadioSetWwanEnabled | Method::RadioSetAirplaneMode => {
            dispatch_radio(method, params_json, runtime)
        }
        Method::WifiNetworks => call_networks(runtime, parse_params(params_json)?),
        Method::WifiBandStatus => crate::daemon_band::status(
            runtime,
            parse_required_params::<crate::daemon_band::BandStatusParams>(params_json)?,
        ),
        Method::WifiProfileOperation => call_profile_operation(
            runtime,
            parse_required_params::<ProfileOperationParams>(params_json)?,
        ),
        Method::WifiSecretCapabilities => {
            crate::daemon_secret::capabilities(parse_params::<SecretCapabilitiesParams>(
                params_json,
            )?)
        }
        Method::WifiSecretProvide => crate::daemon_secret::provide(
            owner,
            parse_required_params::<SecretProvideParams>(params_json)?,
        ),
        _ => Err(wrong_dispatch_group(method)),
    }
}

fn dispatch_empty(
    method: Method,
    params_json: &str,
    runtime: &Arc<DaemonRuntime>,
) -> Result<Value> {
    parse_params::<EmptyParams>(params_json)?;
    match method {
        Method::WifiStatus => call_status(runtime),
        Method::NetworkConnectivity => call_connectivity(runtime),
        Method::WifiDisconnect => call_disconnect(runtime),
        Method::WifiSaved => call_saved(runtime),
        _ => Err(wrong_dispatch_group(method)),
    }
}

fn dispatch_radio(
    method: Method,
    params_json: &str,
    runtime: &Arc<DaemonRuntime>,
) -> Result<Value> {
    let params = parse_required_params::<SetEnabledParams>(params_json)?;
    match method {
        Method::WifiSetEnabled => call_set_enabled(runtime, params),
        Method::RadioSetWwanEnabled => call_set_wwan_enabled(runtime, params),
        Method::RadioSetAirplaneMode => call_set_airplane_mode(runtime, params),
        _ => Err(wrong_dispatch_group(method)),
    }
}
