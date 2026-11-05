use aya::Ebpf;
use cbody_common::{FilePolicyList, PathKey, PortKey, UidList, UidPermission};

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

fn get_or_create_policy(
    denied_files: &mut aya::maps::HashMap<&mut aya::maps::MapData, PathKey, FilePolicyList>,
    path_str: &str,
    default_perm: u8,
) -> anyhow::Result<(PathKey, FilePolicyList)> {
    let mut key_bytes = [0u8; 256];
    let bytes = path_str.as_bytes();
    let len = core::cmp::min(bytes.len(), 256);
    key_bytes[..len].copy_from_slice(&bytes[..len]);

    let key = PathKey { path: key_bytes };

    let policy = match denied_files.get(&key, 0) {
        Ok(existing) => existing,
        Err(_) => FilePolicyList {
            permissions: [UidPermission {
                uid: 0,
                permission: 0,
                _pad: [0; 3],
            }; 16],
            count: 0,
            default_permission: default_perm,
            _pad: [0; 3],
        },
    };

    Ok((key, policy))
}

pub fn sync_denied_files(ebpf: &mut Ebpf, config: &Config) -> anyhow::Result<()> {
    let mut denied_files = aya::maps::HashMap::try_from(ebpf.map_mut("DENIED_FILES").unwrap())?;

    // Default READONLY rules
    for path_str in &config.default.readonly {
        let (key, value) = get_or_create_policy(&mut denied_files, &path_str, 1)?;

        denied_files.insert(&key, &value, 0)?;
    }

    // Default NOACCESS rules
    for path_str in &config.default.noaccess {
        let (key, value) = get_or_create_policy(&mut denied_files, &path_str, 2)?;

        denied_files.insert(&key, &value, 0)?;
    }

    // Profile-specific rules
    for (_p_name, profile) in &config.profiles {
        // READONLY rules
        for path_str in &profile.readonly {
            let (key, mut policies) = get_or_create_policy(&mut denied_files, &path_str, 1)?;

            for &uid in &profile.uids {
                let cur_count = policies.count as usize;
                if cur_count < 16 {
                    let mut exists = false;
                    for i in 0..cur_count {
                        if policies.permissions[i].uid == uid
                            && policies.permissions[i].permission != 2
                        {
                            exists = true;
                            break;
                        }
                    }

                    if !exists {
                        policies.permissions[cur_count].uid = uid;
                        policies.permissions[cur_count].permission = 1;
                        policies.count += 1;
                    }
                }
            }

            denied_files.insert(&key, &policies, 0)?;
        }

        // NOACCESS rules
        for path_str in &profile.noaccess {
            let (key, mut policies) = get_or_create_policy(&mut denied_files, &path_str, 2)?;

            for &uid in &profile.uids {
                let cur_count = policies.count as usize;
                if cur_count < 16 {
                    let mut exists = false;
                    for i in 0..cur_count {
                        if policies.permissions[i].uid == uid {
                            exists = true;
                            break;
                        }
                    }

                    if !exists {
                        policies.permissions[cur_count].uid = uid;
                        policies.permissions[cur_count].permission = 2;
                        policies.count += 1;
                    }
                }
            }

            denied_files.insert(&key, &policies, 0)?;
        }
    }

    Ok(())
}
