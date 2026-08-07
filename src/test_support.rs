use std::os::unix::net::UnixStream;
use std::thread;

use zbus::Guid;
use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;

pub(crate) struct TestPeer {
    pub(crate) server: Connection,
    pub(crate) client: Connection,
}

impl TestPeer {
    pub(crate) fn new(server_name: &str, client_name: &str) -> Self {
        let (server_socket, client_socket) =
            UnixStream::pair().expect("create test peer socket pair");
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

        Self { server, client }
    }
}
