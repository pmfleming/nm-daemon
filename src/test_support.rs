use std::os::unix::net::UnixStream;
use std::thread;

pub(crate) mod performance;
pub(crate) mod workflows;

use zbus::Guid;
use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;

struct TestEndpoint;

#[zbus::interface(name = "org.laufan.NmDaemon.TestEndpoint")]
impl TestEndpoint {
    fn echo(&self, value: u32) -> u32 {
        value
    }
}

pub(crate) struct TestPeer {
    pub(crate) server: Connection,
    pub(crate) client: Connection,
    _runtime: tokio::runtime::Runtime,
}

impl TestPeer {
    pub(crate) fn new(server_name: &str, client_name: &str) -> Self {
        let (server_socket, client_socket) =
            UnixStream::pair().expect("create test peer socket pair");
        server_socket
            .set_nonblocking(true)
            .expect("configure test server socket");
        client_socket
            .set_nonblocking(true)
            .expect("configure test client socket");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build test peer Tokio runtime");
        let (server_socket, client_socket) = {
            let _entered = runtime.enter();
            (
                tokio::net::UnixStream::from_std(server_socket)
                    .expect("register test server socket"),
                tokio::net::UnixStream::from_std(client_socket)
                    .expect("register test client socket"),
            )
        };
        let guid = Guid::generate();
        let server_name = server_name.to_owned();

        // Build both authenticated ends concurrently: each side waits for the
        // peer's D-Bus handshake. A real Unix socket also exercises zbus's
        // production transport instead of the release-build-sensitive in-memory channel.
        // Bootstrap both object servers with serve_at: Builder::build waits for
        // their method-call subscriptions before starting the socket readers.
        // Lazy object_server().at() alone can lose the first request if the
        // reader runs before the dispatch task has subscribed (zbus 5.16).
        let server_thread = thread::spawn(move || {
            Builder::unix_stream(server_socket)
                .server(guid)
                .expect("configure test peer server")
                .p2p()
                .unique_name(server_name)
                .expect("name test peer server")
                .serve_at("/", TestEndpoint)
                .expect("bootstrap test peer server dispatcher")
                .build()
                .expect("build test peer server")
        });
        let client = Builder::unix_stream(client_socket)
            .p2p()
            .unique_name(client_name)
            .expect("name test peer client")
            .serve_at("/", TestEndpoint)
            .expect("bootstrap test peer client dispatcher")
            .build()
            .expect("build test peer client");
        let server = server_thread.join().expect("join test peer server builder");

        Self {
            server,
            client,
            _runtime: runtime,
        }
    }
}

#[test]
fn both_endpoints_dispatch_the_first_call() -> anyhow::Result<()> {
    workflows::isolated(
        concat!(module_path!(), "::both_endpoints_dispatch_the_first_call"),
        || {
            // Recreate the endpoints to exercise startup, not just steady-state
            // dispatch. The isolated child uses one Tokio worker to expose races.
            for value in 0..64_u32 {
                let peer = TestPeer::new(":1.0", ":1.1");
                for (server, client, destination) in [
                    (&peer.server, &peer.client, ":1.0"),
                    (&peer.client, &peer.server, ":1.1"),
                ] {
                    server.object_server().at("/first_call", TestEndpoint)?;
                    let reply = client.call_method(
                        Some(destination),
                        "/first_call",
                        Some("org.laufan.NmDaemon.TestEndpoint"),
                        "Echo",
                        &value,
                    )?;
                    assert_eq!(reply.body().deserialize::<u32>()?, value);
                }
            }
            Ok(())
        },
    )
}
