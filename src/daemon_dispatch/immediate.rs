use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;

use super::{EmptyParams, parse_params, parse_required_params, wrong_dispatch_group};
use crate::daemon_methods::{
    ActivateProfileParams, DeactivateParams, DiscoveryServicesParams, ProfileOperationParams,
    RequestStatusParams, SetEnabledParams, call_discovery_services, call_network_activate_profile,
    call_network_deactivate, call_networks, call_profile_operation, call_request_status,
    call_set_airplane_mode, call_set_enabled, call_set_wwan_enabled,
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
        | Method::NetworkInventory
        | Method::NetworkDevices
        | Method::NetworkConnections
        | Method::NetworkState
        | Method::HotspotCapabilities
        | Method::HotspotStatus
        | Method::HotspotStop
        | Method::VpnList
        | Method::VpnStatus
        | Method::WifiDisconnect
        | Method::WifiSaved => dispatch_empty(method, params_json, runtime),
        Method::WifiQrRender => crate::daemon_qr::call_render(parse_required_params::<
            crate::daemon_qr::QrPayloadParams,
        >(params_json)?),
        Method::WifiQrParse => crate::daemon_qr::call_parse(parse_required_params::<
            crate::daemon_qr::QrPayloadParams,
        >(params_json)?),
        Method::NetworkActivateProfile => call_network_activate_profile(
            runtime,
            parse_required_params::<ActivateProfileParams>(params_json)?,
        ),
        Method::VpnDisconnect => crate::daemon_vpn::call_disconnect(
            runtime,
            parse_params::<crate::daemon_vpn::VpnSelectParams>(params_json)?,
        ),
        Method::NetworkDeactivate => call_network_deactivate(
            runtime,
            parse_required_params::<DeactivateParams>(params_json)?,
        ),
        Method::WifiSetEnabled | Method::RadioSetWwanEnabled | Method::RadioSetAirplaneMode => {
            dispatch_radio(method, params_json, runtime)
        }
        Method::WifiNetworks => call_networks(runtime, parse_params(params_json)?),
        Method::DiscoveryServices => call_discovery_services(
            runtime,
            parse_required_params::<DiscoveryServicesParams>(params_json)?,
        ),
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
        Method::OperationStatus => call_request_status(
            runtime,
            parse_required_params::<RequestStatusParams>(params_json)?,
            owner,
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
        Method::WifiStatus => runtime.call_status(),
        Method::NetworkConnectivity => runtime.call_application(method, |app| app.connectivity()),
        Method::NetworkInventory => runtime.call_application(method, |app| app.network_inventory()),
        Method::NetworkDevices => runtime.call_application(method, |app| app.network_devices()),
        Method::NetworkConnections => {
            runtime.call_application(method, |app| app.network_connections())
        }
        Method::NetworkState => runtime.call_application(method, |app| app.network_state()),
        Method::HotspotCapabilities => {
            runtime.call_application(method, |app| app.hotspot_capabilities())
        }
        Method::HotspotStatus => runtime.call_application(method, |app| app.hotspot_status()),
        Method::HotspotStop => runtime.call_application(method, |app| app.stop_hotspot()),
        Method::VpnList => runtime.call_application(method, |app| app.vpn_profiles()),
        Method::VpnStatus => runtime.call_application(method, |app| app.vpn_status()),
        Method::WifiDisconnect => runtime.call_application(method, |app| app.disconnect()),
        Method::WifiSaved => runtime.call_application(method, |app| app.saved_profiles()),
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
