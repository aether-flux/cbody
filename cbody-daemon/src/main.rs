mod config;

use std::path::PathBuf;

use aya::{Btf, EbpfLoader, programs::Lsm};
use aya_log::EbpfLogger;
use log::{debug, warn};
use tokio::signal;

use crate::config::load_config;

// #[tokio::main]
// async fn main() -> anyhow::Result<()> {
//     env_logger::init();
//
//     // Bump rlimit (for older kernels)
//     let rlim = libc::rlimit {
//         rlim_cur: libc::RLIM_INFINITY,
//         rlim_max: libc::RLIM_INFINITY,
//     };
//     let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
//     if ret != 0 {
//         debug!("remove limit on locked memory failed, ret: {}", ret);
//     }
//
//     // Load ebpf
//     let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(concat!(
//         env!("OUT_DIR"),
//         "/cbody-ebpf",
//     )))?;
//
//     match EbpfLogger::init(&mut ebpf) {
//         Err(e) => warn!("failed to initialize eBPF logger: {e}"),
//         Ok(logger) => {
//             let mut logger = unsafe {
//                 tokio::io::unix::AsyncFd::register_with_interest(
//                     logger,
//                     tokio::io::Interest::READABLE,
//                 )
//             }?;
//             tokio::task::spawn(async move {
//                 loop {
//                     let mut guard = logger.readable_mut().await.unwrap();
//                     guard.get_inner_mut().flush();
//                     guard.clear_ready();
//                 }
//             });
//         }
//     }
//
//     let btf = Btf::from_sys_fs()?;
//     let program: &mut Lsm = ebpf
//         .program_mut("bprm_check_security")
//         .unwrap()
//         .try_into()?;
//     program.load("bprm_check_security", &btf)?;
//     program.attach()?;
//
//     let ctrl_c = signal::ctrl_c();
//     println!("Waiting for CTRL-C...");
//     ctrl_c.await?;
//     println!("Exiting...");
//
//     Ok(())
// }

fn main() -> anyhow::Result<()> {
    let base = PathBuf::from(".");
    let config_path = base.join("config.toml");

    let config = load_config(config_path)?;

    println!("Config:\n{:?}", config);

    Ok(())
}
