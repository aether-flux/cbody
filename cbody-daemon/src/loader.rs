use aya::Ebpf;
use cbody_common::{PathKey, PortKey, UidList};

use crate::config::Config;

pub fn sync_denied_binaries(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut denied_bins = aya::maps::HashMap::try_from(ebpf.map_mut("DENIED_BINARIES").unwrap())?;

    // Default rules
    for path_str in &config.default.deny_exec {
        let mut key_bytes = [0u8; 256];
        let bytes = path_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 256);
        key_bytes[..len].copy_from_slice(&bytes[..len]);

        let key = PathKey { path: key_bytes };
        let value = UidList {
            uids: [0u32; 16],
            count: 0,
        };

        denied_bins.insert(&key, &value, 0)?;
    }

    // Profile-specific rules
    for (p_name, profile) in &config.profiles {
        for path_str in &profile.deny_exec {
            let mut key_bytes = [0u8; 256];
            let bytes = path_str.as_bytes();
            let len = core::cmp::min(bytes.len(), 256);
            key_bytes[..len].copy_from_slice(&bytes[..len]);

            let key = PathKey { path: key_bytes };

            let mut uid_list = match denied_bins.get(&key, 0) {
                Ok(existing_val) => existing_val,
                Err(_) => UidList {
                    uids: [0u32; 16],
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

            denied_bins.insert(&key, &uid_list, 0)?;
        }
    }

    Ok(())
}

pub fn sync_denied_ports(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut denied_ports = aya::maps::HashMap::try_from(ebpf.map_mut("DENIED_PORTS").unwrap())?;

    // Default rules
    for &port in &config.default.block_outbound_ports {
        let key = PortKey { port };
        let value = UidList {
            uids: [0u32; 16],
            count: 0,
        };

        denied_ports.insert(&key, &value, 0)?;
    }

    // Profile-specific rules
    for (p_name, profile) in &config.profiles {
        for &port in &profile.block_outbound_ports {
            let key = PortKey { port };

            let mut uid_list = match denied_ports.get(&key, 0) {
                Ok(existing_val) => existing_val,
                Err(_) => UidList {
                    uids: [0u32; 16],
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

            denied_ports.insert(&key, &uid_list, 0)?;
        }
    }

    Ok(())
}
