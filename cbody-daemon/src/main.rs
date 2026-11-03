mod config;

use std::path::PathBuf;

use aya::{Btf, EbpfLoader, programs::Lsm};
use aya_log::EbpfLogger;
use cbody_common::PathKey;
use log::{debug, warn};
use tokio::signal;

use crate::config::load_config;

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
    let base = PathBuf::from(".");
    let config_path = base.join("config.toml");
    let config = load_config(&config_path)?;

    // Load config properties into BPF map (ALLOWED_BINARIES)
    let mut allowed_map = aya::maps::HashMap::try_from(ebpf.map_mut("ALLOWED_BINARIES").unwrap())?;

    for path_str in config.default.allow_exec {
        let mut key_bytes = [0u8; 256];
        let bytes = path_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 256);
        key_bytes[..len].copy_from_slice(&bytes[..len]);

        let key = PathKey { path: key_bytes };
        allowed_map.insert(&key, &1, 0)?;
    }

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
    let program: &mut Lsm = ebpf
        .program_mut("bprm_check_security")
        .unwrap()
        .try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for CTRL-C...");
    ctrl_c.await?;
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
