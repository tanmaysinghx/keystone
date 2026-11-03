use keystone::{cli, config};

fn main() {
    // A developer checkout may keep settings in .env; real deployments use keystone.properties.
    dotenvy::dotenv().ok();
    let args = match config::parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => fail(error),
    };
    let command = args.command.clone().unwrap_or_else(|| "serve".into());
    if args.flags.contains_key("help") || matches!(command.as_str(), "help" | "-h") {
        print!("{}", cli::HELP);
        return;
    }
    if args.flags.contains_key("version") || command == "version" {
        println!("keystone {}", config::VERSION);
        return;
    }
    let result = match command.as_str() {
        "gen-master-key" => {
            println!("{}", config::generate_master_key());
            Ok(())
        }
        "init" => cli::init(&args),
        "pull" => cli::pull(&args),
        "get" => cli::get(&args),
        "run" => cli::run(&args),
        "whoami" => cli::whoami(&args),
        "healthcheck" => config::Config::load(&args, false).and_then(|c| cli::healthcheck(&c)),
        "config" => config::Config::load(&args, false).map(|c| cli::show_config(&c)),
        "serve" | "backup" | "restore" | "migrate" | "rotate-master-key" | "connect-portal" => {
            runtime(async {
                let cfg = config::Config::load(&args, true)?;
                match command.as_str() {
                    "serve" => serve(cfg).await,
                    "backup" => cli::backup(&cfg, &args).await,
                    "restore" => cli::restore(&cfg, &args).await,
                    "migrate" => cli::migrate(&cfg, &args).await,
                    "rotate-master-key" => cli::rotate_master_key(&cfg, &args).await,
                    _ => cli::connect_portal(&cfg, &args).await,
                }
            })
        }
        other => Err(anyhow::anyhow!(
            "Unknown command '{other}'. Run `keystone help`."
        )),
    };
    if let Err(error) = result {
        fail(error);
    }
}

fn fail(error: anyhow::Error) -> ! {
    eprintln!("keystone: {error:#}");
    std::process::exit(1);
}

fn runtime(future: impl std::future::Future<Output = anyhow::Result<()>>) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

async fn serve(cfg: config::Config) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("keystone={0},tower_http={0}", cfg.log_level).into()),
        )
        .init();
    let address = cfg.bind.clone();
    tracing::info!(version = config::VERSION, home = %cfg.home.display(), config = ?cfg.config_file, "Starting Keystone Vault");
    if !cfg.sso_configured() {
        tracing::warn!(
            "Portal SSO is not configured: run `keystone connect-portal https://your-portal` to enable sign-in"
        );
    }
    if cfg.master_key.is_none() {
        tracing::warn!("No master key: the vault is sealed");
    }
    if cfg.ui_dir.is_none() && !keystone::ui::embedded() {
        tracing::warn!(
            "This binary was built without the console; set ui.dir or rebuild after `npm run build:ui`"
        );
    }
    let state = keystone::state(cfg).await?;
    keystone::backup::schedule(state.clone());
    let (shutdown, restart) = (state.shutdown.clone(), state.restart.clone());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!(address, "Keystone Vault listening");
    axum::serve(
        listener,
        keystone::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let ctrl_c = async { tokio::signal::ctrl_c().await.ok() };
        #[cfg(unix)]
        let term = async {
            if let Ok(mut s) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                s.recv().await;
            }
        };
        #[cfg(not(unix))]
        let term = std::future::pending::<()>();
        tokio::select! { _ = ctrl_c => {}, _ = term => {}, _ = shutdown.notified() => {} }
    })
    .await?;
    if restart.load(std::sync::atomic::Ordering::SeqCst) {
        restart_in_place();
    }
    Ok(())
}

/// Setup changed the configuration: start again with the same arguments. On Unix the process is
/// replaced in place (same PID), so systemd and container runtimes keep supervising it.
fn restart_in_place() {
    tracing::info!("Restarting to apply the new configuration");
    let exe = std::env::current_exe().expect("current executable");
    let mut command = std::process::Command::new(exe);
    command.args(std::env::args_os().skip(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        fail(anyhow::anyhow!("Could not restart: {error}"));
    }
    #[cfg(not(unix))]
    {
        match command.spawn() {
            Ok(_) => std::process::exit(0),
            Err(error) => fail(anyhow::anyhow!("Could not restart: {error}")),
        }
    }
}
