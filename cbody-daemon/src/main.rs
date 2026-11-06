mod config;
mod loader;

use std::{path::Path, sync::mpsc::channel};

use anyhow::Context;
use aya::{Btf, EbpfLoader, programs::Lsm};
use aya_log::EbpfLogger;
use cbody_common::{PathKey, PortKey, UidList};
use log::{debug, warn};
use notify::{Event, RecursiveMode, Watcher};
use tokio::signal;

use crate::{
    config::load_config,
    loader::{
        exempt_uids, init_default_actions, sync_denied_binaries, sync_denied_files,
        sync_denied_ports,
    },
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump rlimit (for older kernels)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret: {}", ret);
    }

    // Load ebpf
    let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cbody-ebpf",
    )))?;

    // Load the config file
    let config = load_config()?;

    // Set the default actions
    init_default_actions(&mut ebpf, &config.settings.action)?;

    // Specify exempt UIDs
    exempt_uids(&mut ebpf, &config.exemptions.uids)?;

    // Load config rules into eBPF maps
    sync_denied_binaries(&mut ebpf, &config)?;
    sync_denied_ports(&mut ebpf, &config)?;
    sync_denied_files(&mut ebpf, &config)?;

    match EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )
            }?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let btf = Btf::from_sys_fs()?;

    // Attach bprm_check_security program
    let bprm_check_security: &mut Lsm = ebpf
        .program_mut("bprm_check_security")
        .unwrap()
        .try_into()?;
    bprm_check_security.load("bprm_check_security", &btf)?;
    bprm_check_security.attach()?;

    // Attach socket_connect program
    let socket_connect: &mut Lsm = ebpf.program_mut("socket_connect").unwrap().try_into()?;
    socket_connect.load("socket_connect", &btf)?;
    socket_connect.attach()?;

    // Attach file_open program
    let file_open: &mut Lsm = ebpf.program_mut("file_open").unwrap().try_into()?;
    file_open.load("file_open", &btf)?;
    file_open.attach()?;

    // Create channel for live-reloading
    let (tx, rx) = channel();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => {
            let is_modification = matches!(
                event.kind,
                notify::EventKind::Modify(notify::event::ModifyKind::Data(_))
            );

            if is_modification | event.kind.is_create() {
                let is_config_target = event
                    .paths
                    .iter()
                    .any(|path| path.file_name().map_or(false, |name| name == "config.toml"));

                if is_config_target {
                    let _ = tx.send(event);
                }
            }
        }
        Err(e) => eprintln!("Watch error: {:?}", e),
    })?;

    let watch_path = if cfg!(debug_assertions) {
        "."
    } else {
        "/etc/cbody"
    };
    watcher.watch(Path::new(watch_path), RecursiveMode::NonRecursive)?;
    println!("Watching {} for configuration changes...", watch_path);

    // Loop for live-reloading
    tokio::task::spawn_blocking(move || {
        let mut last_reload = std::time::Instant::now();

        for _res in rx {
            if last_reload.elapsed() < std::time::Duration::from_millis(2000) {
                continue;
            }
            last_reload = std::time::Instant::now();

            println!("Config change detected! Reloading daemon...");

            // Load new config and update maps
            match load_config() {
                Ok(new_config) => {
                    if let Err(e) = init_default_actions(&mut ebpf, &new_config.settings.action) {
                        eprintln!("Failed to update default actions: {:?}", e);
                    }
                    if let Err(e) = exempt_uids(&mut ebpf, &new_config.exemptions.uids) {
                        eprintln!("Failed to update exempt UIDs: {:?}", e);
                    }
                    if let Err(e) = sync_denied_binaries(&mut ebpf, &new_config) {
                        eprintln!("Failed to update denied binaries: {:?}", e);
                    }
                    if let Err(e) = sync_denied_ports(&mut ebpf, &new_config) {
                        eprintln!("Failed to update denied ports: {:?}", e);
                    }
                    if let Err(e) = sync_denied_files(&mut ebpf, &new_config) {
                        eprintln!("Failed to update denied files: {:?}", e);
                    }
                }
                Err(e) => eprintln!("Failed to load config: {:?}", e),
            }
        }
    });

    // let ctrl_c = signal::ctrl_c();
    // println!("Waiting for CTRL-C...");
    // ctrl_c.await?;
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

// fn main() -> anyhow::Result<()> {
//     let base = PathBuf::from(".");
//     let config_path = base.join("config.toml");
//
//     let config = load_config(config_path)?;
//
//     println!("Config:\n{:?}", config);
//
//     Ok(())
// }
