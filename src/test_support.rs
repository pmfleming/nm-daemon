use zbus::Guid;
use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;
use zbus::connection::socket::Channel;

pub(crate) struct TestPeer {
    pub(crate) server: Connection,
    pub(crate) client: Connection,
}

impl TestPeer {
    pub(crate) fn new(server_name: &str, client_name: &str) -> Self {
        let (server_socket, client_socket) = Channel::pair();
        let guid = Guid::generate();
        let client_guid = guid.clone();
        let server = Builder::authenticated_socket(server_socket, guid)
            .expect("configure authenticated test peer server socket")
            .p2p()
            .unique_name(server_name)
            .expect("name test peer server")
            .build()
            .expect("build test peer server");
        let client = Builder::authenticated_socket(client_socket, client_guid)
            .expect("configure authenticated test peer client socket")
            .p2p()
            .unique_name(client_name)
            .expect("name test peer client")
            .build()
            .expect("build test peer client");
        Self { server, client }
    }
}
