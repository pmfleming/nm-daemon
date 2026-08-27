use std::os::unix::net::UnixStream;
use std::thread;

use zbus::Guid;
use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;

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
        let server_thread = thread::spawn(move || {
            Builder::unix_stream(server_socket)
                .server(guid)
                .expect("configure test peer server")
                .p2p()
                .unique_name(server_name)
                .expect("name test peer server")
                .build()
                .expect("build test peer server")
        });
        let client = Builder::unix_stream(client_socket)
            .p2p()
            .unique_name(client_name)
            .expect("name test peer client")
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
