#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#[cfg(not(all(feature = "hardware-keystore", feature = "approved-software-fallback")))]
compile_error!("Najwa local web must include hardware protection and the explicit-approval fallback");
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
compile_error!("Najwa local web requires a supported hardware-keystore platform");
mod assets;
mod browser_access;
mod http;
mod transfer_http;
mod launch;
mod messaging;
mod os_lock;
mod profile;

use std::{path::PathBuf, time::Duration};

// S01 §6.1: zero every block on release, covering secret copies held inside
// dependencies (HTTP and JSON buffers) that Najwa's own code cannot wipe.
#[global_allocator]
static ALLOCATOR: najwa_crypto::memory::ZeroizingAllocator =
    najwa_crypto::memory::ZeroizingAllocator(std::alloc::System);

fn main() {
    let interactive = !std::env::args_os()
        .any(|arg| arg == "--no-browser" || arg == "--help" || arg == "--build-info");
    if let Err(error) = run() {
        launch::report(&error.to_string(), interactive);
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--build-info")) {
        println!(
            "{}",
            serde_json::json!({"product":"Najwa", "version":env!("CARGO_PKG_VERSION"), "embeddedUi":cfg!(feature="bundled-ui"), "os":std::env::consts::OS, "arch":std::env::consts::ARCH, "uiDigest":assets::bundled_digest(), "keyProtection":"hardware-preferred", "hardwareBackend":if cfg!(target_os="macos") {"secure-enclave"} else {"tpm2"}, "softwareFallback":"explicit-approval"})
        );
        return Ok(());
    }
    // S01 §5.2 / §6.3: suppress crash dumps and check the CSPRNG before any
    // profile state (the browser token, the identity record) is read.
    najwa_crypto::initialize()?;
    #[cfg(windows)]
    najwa_crypto::memory::exclude_from_error_reporting()?;
    let mut directory = directories::ProjectDirs::from("org", "Najwa", "Najwa Web")
        .ok_or("cannot find local application data directory")?
        .data_local_dir()
        .join("profile");
    let mut asset_directory = None;
    let mut browser = true;
    let mut port = 1421;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--profile") => {
                directory = PathBuf::from(args.next().ok_or("missing profile directory")?)
            }
            Some("--assets") => {
                asset_directory = Some(PathBuf::from(
                    args.next().ok_or("missing web assets directory")?,
                ))
            }
            Some("--no-browser") => browser = false,
            Some("--port") => {
                port = args
                    .next()
                    .ok_or("missing port")?
                    .to_str()
                    .ok_or("invalid port")?
                    .parse::<u16>()?
            }
            Some("--help") => {
                println!("Najwa\nUsage: najwa-web [--profile DIRECTORY] [--assets DIRECTORY] [--port 1421] [--no-browser]\nOpens your browser and keeps your encrypted profile on this computer. Docker is not required.\nProfiles start locked. Run the app again to open an existing instance.");
                return Ok(());
            }
            _ => return Err("unknown argument".into()),
        }
    }
    if port == 0 {
        return Err("port must be nonzero".into());
    }
    let assets = assets::Assets::resolve(asset_directory)?;
    let owner = match profile::Owner::open(&directory, assets, port) {
        Ok(owner) => owner,
        Err("this profile is already open") if browser => {
            launch::open(&directory, &launch::existing(&directory)?)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    // Own the profile before trusting any process at the configured local port.
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let _registration = launch::Registration::publish(&directory, &owner, port)?;
    // Session lock, user switch and sleep take the Lock button's path. Keep
    // unlocked only feeds the idle worker, so it cannot hold this lock off.
    // Weak: the listener thread outlives `run`, and must not keep the owner alive.
    let os_owner = std::sync::Arc::downgrade(&owner);
    os_lock::watch(move || {
        if let Some(owner) = os_owner.upgrade() {
            let epoch = owner.begin_lock();
            let _ = owner.finish_lock(epoch);
        }
    });
    let runtime = tokio::runtime::Runtime::new()?;
    if browser {
        launch::open(&directory, &format!("{}/#{}", owner.origin, owner.token))?;
    }
    let result = runtime.block_on(async {
        let timer_owner = owner.clone();
        let idle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if timer_owner.status().phase == "unlocked"
                    && timer_owner.idle_expired()
                {
                    let task = timer_owner.clone();
                    let epoch = task.begin_lock();
                    let _ = tokio::task::spawn_blocking(move || task.finish_lock(epoch)).await;
                }
            }
        });
        println!(
            "Najwa is ready at {}\nProfile: {}\nKeep this window open. Press Ctrl+C to stop.",
            owner.origin,
            directory.display()
        );
        let shutdown_owner = owner.clone();
        let result = axum::serve(
            tokio::net::TcpListener::from_std(listener)?,
            http::router(owner.clone()),
        )
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = shutdown_owner.shutdown.notified() => {},
            }
            let epoch = shutdown_owner.begin_lock();
            let _ = tokio::task::spawn_blocking(move || shutdown_owner.finish_lock(epoch)).await;
        })
        .await;
        idle.abort();
        result
    });
    let epoch = owner.begin_lock();
    owner
        .finish_lock(epoch)
        .map_err(|_| "could not finish locking profile")?;
    // Locked polling and cover keep fetch capabilities in memory (S13 §8.3);
    // tear the runtime down so they are zeroized before the process exits.
    drop(owner.client.prepare_wipe());
    result?;
    Ok(())
}
