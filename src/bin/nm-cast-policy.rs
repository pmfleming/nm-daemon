#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nm_daemon::run_cast_policy().await
}
