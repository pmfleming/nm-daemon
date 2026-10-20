use super::*;
use crate::command::SystemCommandRunner;
use crate::nl80211::UnavailableWirelessTelemetry;
use crate::test_support::{bus::TestBus, workflows::isolated};
use std::sync::{Arc, Mutex};

const DEVICE: &str = "/test/device";
const CONFIG: &str = "/test/ip";

struct Device;
#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl Device {
    #[zbus(property)]
    fn ip6_config(&self) -> OwnedObjectPath {
        CONFIG.try_into().unwrap()
    }
    #[zbus(property)]
    fn dhcp6_config(&self) -> OwnedObjectPath {
        "/".try_into().unwrap()
    }
}

// Match upstream introspection independently: Nameservers is aay, and there
// deliberately is no NameserverData property (unlike IP4Config).
struct Ip6Config(Arc<Mutex<Vec<Vec<u8>>>>);
#[zbus::interface(name = "org.freedesktop.NetworkManager.IP6Config")]
impl Ip6Config {
    #[zbus(property(emits_changed_signal = "false"))]
    fn nameservers(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}

#[test]
fn ipv6_nameservers_use_the_real_dbus_signature() -> Result<()> {
    isolated(
        "nm::ip_status::tests::ipv6_nameservers_use_the_real_dbus_signature",
        || {
            let runtime = tokio::runtime::Runtime::new()?;
            let _entered = runtime.enter();
            let bus = TestBus::new()?;
            let server = bus.connect()?;
            let values = Arc::new(Mutex::new(Vec::new()));
            server.object_server().at(DEVICE, Device)?;
            server
                .object_server()
                .at(CONFIG, Ip6Config(Arc::clone(&values)))?;
            let nm = Nm::with_connection_runner_destination_and_telemetry(
                bus.connect()?,
                Arc::new(SystemCommandRunner),
                server.unique_name().unwrap().to_string(),
                Arc::new(UnavailableWirelessTelemetry),
            )?;
            let address: Ipv6Addr = "2001:db8::53".parse()?;
            for (wire, expected) in [
                (
                    vec![
                        address.octets().to_vec(),
                        Ipv6Addr::LOCALHOST.octets().to_vec(),
                    ],
                    vec!["2001:db8::53", "::1"],
                ),
                // Do not pad/truncate malformed server addresses or invent DNS.
                (
                    vec![vec![], vec![0; 15], address.octets().to_vec(), vec![0; 17]],
                    vec!["2001:db8::53"],
                ),
                (vec![], vec![]),
            ] {
                *values.lock().unwrap() = wire;
                let status = nm
                    .device_ip_status(&DEVICE.try_into()?, IpFamily::V6)?
                    .unwrap();
                assert_eq!(status.dns, expected);
            }
            server.object_server().remove::<Ip6Config, _>(CONFIG)?;
            assert!(
                nm.device_ip_status(&DEVICE.try_into()?, IpFamily::V6)?
                    .unwrap()
                    .dns
                    .is_empty()
            );
            Ok(())
        },
    )
}
