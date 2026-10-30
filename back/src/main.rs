#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keystone=info,tower_http=info".into()),
        )
        .init();
    let config = keystone::config::Config::from_env()?;
    std::fs::create_dir_all("data")?;
    let address = config.bind.clone();
    if !config.sso_configured() {
        tracing::warn!("SSO is unconfigured; admin endpoints remain locked");
    }
    if config.service_key.is_empty() {
        tracing::warn!("Service key is unconfigured; blog endpoints remain locked");
    }
    let state = keystone::state(config).await?;
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!(address, "Keystone listening");
    axum::serve(listener, keystone::router(state))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;
    Ok(())
}
