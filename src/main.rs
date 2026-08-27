#[tokio::main]
async fn main() {
    if let Err(err) = nm_daemon::run().await {
        nm_daemon::report_error(&err);
        std::process::exit(1);
    }
}
