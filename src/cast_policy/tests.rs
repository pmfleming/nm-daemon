use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use tokio::sync::Mutex;

use super::{DESTINATION, INTERFACE, PATH, Policy, PolicyApi};
use crate::test_support::TestPeer;

#[test]
fn reconcile_rejects_caller_supplied_policy_arguments() -> Result<()> {
    crate::test_support::workflows::isolated(
        concat!(
            module_path!(),
            "::reconcile_rejects_caller_supplied_policy_arguments"
        ),
        || {
            let peer = TestPeer::new(":1.0", ":1.1");
            // No real NM or nft execution is needed: reject the body before
            // consulting either. An accidental dispatch would return Failed,
            // not a signature/InvalidArgs error.
            peer.server.object_server().at(
                PATH,
                PolicyApi(Arc::new(Policy {
                    conn: peer.client.inner().clone(),
                    nft: PathBuf::from("/nonexistent/nft"),
                    transaction: Mutex::new(()),
                })),
            )?;
            let proxy = zbus::blocking::Proxy::new(&peer.client, DESTINATION, PATH, INTERFACE)?;
            let error = proxy
                .call::<_, _, ()>("Reconcile", &("wlan0", true))
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    zbus::Error::MethodError(name, message, _)
                        if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs"
                            || (name.as_str() == "org.freedesktop.zbus.Error"
                                && message.as_deref().is_some_and(|m| m.contains("Signature mismatch")))
                ),
                "unexpected error: {error:?}"
            );
            Ok(())
        },
    )
}
