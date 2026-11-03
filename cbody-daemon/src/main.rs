mod config;

use anyhow::Context;
use aya::{Btf, EbpfLoader, programs::Lsm};
use aya_log::EbpfLogger;
use cbody_common::{PathKey, UidList};
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
    let config = load_config()?;

    // Load config properties into BPF map (DENIED_BINARIES)
    let mut denied_map = aya::maps::HashMap::try_from(ebpf.map_mut("DENIED_BINARIES").unwrap())?;

    // Default rules in config
    for path_str in config.default.deny_exec {
        let mut key_bytes = [0u8; 256];
        let bytes = path_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 256);
        key_bytes[..len].copy_from_slice(&bytes[..len]);

        let key = PathKey { path: key_bytes };
        let value = UidList {
            uids: [0u32; 16],
            count: 0,
        };
        denied_map.insert(&key, &value, 0)?;
    }

    // Profile-level rules in config
    for (p_name, profile) in config.profiles {
        // let uids = profile.uids;

        for path_str in &profile.deny_exec {
            let mut key_bytes = [0u8; 256];
            let bytes = path_str.as_bytes();
            let len = core::cmp::min(bytes.len(), 256);
            key_bytes[..len].copy_from_slice(&bytes[..len]);

            let key = PathKey { path: key_bytes };

            let mut uid_list = match denied_map.get(&key, 0) {
                Ok(existing_val) => existing_val,
                Err(_) => UidList {
                    uids: [0; 16],
                    count: 0,
                },
            };

            for &uid in &profile.uids {
                let cur_count = uid_list.count as usize;
                if cur_count < 16 {
                    let mut exists = false;
                    for i in 0..cur_count {
                        if uid_list.uids[i] == uid {
                            exists = true;
                            break;
                        }
                    }

                    if !exists {
                        uid_list.uids[cur_count] = uid;
                        uid_list.count += 1;
                    }
                }
            }

            denied_map.insert(&key, &uid_list, 0)?;
        }
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
