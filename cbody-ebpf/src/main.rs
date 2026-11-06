#![no_std]
#![no_main]

#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::cty::{c_int, c_void};
use aya_ebpf::helpers::{
    bpf_d_path, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::LsmContext;
use aya_log_ebpf::info;
use cbody_common::{DENY, FilePolicyList, LOG, NO_DENY, NO_LOG, PathKey, PortKey, UidList};

use crate::vmlinux::{file, linux_binprm, path, sock, sockaddr, sockaddr_in, socket};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const O_ACCMODE: u32 = 3;
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = (1 << 0);
const O_RDWR: u32 = (1 << 1);

#[map]
pub static DEFAULT_ACTIONS: Array<u32> = Array::with_max_entries(2, 0);

#[map]
pub static SCRATCH_MAP: PerCpuArray<PathKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static EXEMPT_UIDS: HashMap<u32, u32> = HashMap::with_max_entries(512, 0);

#[map]
pub static DENIED_BINARIES: HashMap<PathKey, UidList> = HashMap::with_max_entries(1024, 0);

#[map]
pub static DENIED_FILES: HashMap<PathKey, FilePolicyList> = HashMap::with_max_entries(1024, 0);

#[map]
pub static DENIED_PORTS: HashMap<PortKey, UidList> = HashMap::with_max_entries(1024, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match try_bprm_check_security(ctx) {
        Ok(_) => 0,
        Err(mut e) => {
            if e > 0 || e < -4095 {
                e = -1;
            }
            e
        }
    }
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    match try_socket_connect(ctx) {
        Ok(_) => 0,
        Err(mut e) => {
            if e > 0 || e < -4095 {
                e = -1;
            }
            e
        }
    }
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(_) => 0,
        Err(mut e) => {
            if e > 0 || e < -4095 {
                e = -1;
            }
            e
        }
    }
}

fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm_ptr: *const linux_binprm = ctx.arg(0);
    let filename_ptr = unsafe { (*bprm_ptr).filename };

    let deny_flag = unsafe { DEFAULT_ACTIONS.get(0).copied().unwrap_or(DENY) };
    let log_flag = unsafe { DEFAULT_ACTIONS.get(1).copied().unwrap_or(LOG) };

    let key = match SCRATCH_MAP.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Ok(0),
    };

    key.path = [0; 256];

    unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, &mut key.path)
            .map_err(|_| -1)?;
    }

    if let Some(uid_list) = unsafe { DENIED_BINARIES.get(&key) } {
        let cur_uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

        if unsafe { EXEMPT_UIDS.get(&cur_uid) } == Some(&1) {
            return Ok(0);
        }

        if uid_list.count == 0 {
            if log_flag == LOG {
                let filename = unsafe { core::str::from_utf8_unchecked(&key.path) };
                info!(&ctx, "Filename executed: {}", filename);
            }

            if deny_flag == DENY {
                return Err(-1);
            } else {
                return Ok(0);
            }
        }

        let count = uid_list.count as usize;
        for i in 0..16 {
            if i >= count {
                break;
            }
            if uid_list.uids[i] == cur_uid {
                if log_flag == LOG {
                    let filename = unsafe { core::str::from_utf8_unchecked(&key.path) };
                    info!(&ctx, "Filename executed: {}", filename);
                }

                if deny_flag == DENY {
                    return Err(-1);
                } else {
                    return Ok(0);
                }
            }
        }
    }

    Ok(0)
}

fn try_socket_connect(ctx: LsmContext) -> Result<i32, i32> {
    let sock: *const socket = ctx.arg(0);
    let address: *const sockaddr = ctx.arg(1);
    let addrlen: c_int = ctx.arg(2);

    if address.is_null() || sock.is_null() {
        return Ok(0);
    }

    let family =
        unsafe { bpf_probe_read_kernel(&(*address).sa_family as *const u16).map_err(|_| 0)? };

    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    if (addrlen as usize) < core::mem::size_of::<sockaddr_in>() {
        return Ok(0);
    }

    let deny_flag = unsafe { DEFAULT_ACTIONS.get(0).copied().unwrap_or(DENY) };
    let log_flag = unsafe { DEFAULT_ACTIONS.get(1).copied().unwrap_or(LOG) };

    let mut dport = 0u16;
    let mut daddr = [0u8; 16];
    unsafe {
        let a: sockaddr_in = bpf_probe_read_kernel(address as *const sockaddr_in).map_err(|_| 0)?;
        dport = u16::from_be(a.sin_port);
        daddr[..4].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
    }

    let key = PortKey { port: dport };

    if let Some(uid_list) = unsafe { DENIED_PORTS.get(&key) } {
        let cur_uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

        if unsafe { EXEMPT_UIDS.get(&cur_uid) } == Some(&1) {
            return Ok(0);
        }

        if uid_list.count == 0 {
            if log_flag == LOG {
                info!(&ctx, "Family: {}, Port: {}", family, dport);
            }

            if deny_flag == DENY {
                return Err(-1);
            } else {
                return Ok(0);
            }
        }

        let count = uid_list.count as usize;

        for i in 0..16 {
            if i >= count {
                break;
            }

            if uid_list.uids[i] == cur_uid {
                if log_flag == LOG {
                    info!(&ctx, "Family: {}, Port: {}", family, dport);
                }

                if deny_flag == DENY {
                    return Err(-1);
                } else {
                    return Ok(0);
                }
            }
        }
    }

    Ok(0)
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let file: *const file = ctx.arg(0);

    if file.is_null() {
        return Ok(0);
    }

    let deny_flag = unsafe { DEFAULT_ACTIONS.get(0).copied().unwrap_or(DENY) };
    let log_flag = unsafe { DEFAULT_ACTIONS.get(1).copied().unwrap_or(LOG) };

    let flags = unsafe { bpf_probe_read_kernel(&(*file).f_flags).map_err(|_| 0)? };

    let mut acc_mode = O_RDONLY;

    match (flags & O_ACCMODE) {
        0 => acc_mode = O_RDONLY,
        1 => acc_mode = O_WRONLY,
        2 => acc_mode = O_RDWR,
        _ => return Ok(0),
    }

    let mut buf = [0u8; 256];
    let len = unsafe {
        bpf_d_path(
            &(*file).__bindgen_anon_1.f_path as *const path as *const aya_ebpf::bindings::path,
            buf.as_mut_ptr() as *mut _,
            256,
        )
    };
    if len <= 0 || len > 256 {
        return Ok(0);
    }

    let bytes = match buf.get(..(len as usize - 1)) {
        Some(b) => b,
        None => return Ok(0),
    };
    let filename = unsafe { core::str::from_utf8_unchecked(bytes) };

    let key = match SCRATCH_MAP.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Ok(0),
    };

    key.path = [0; 256];

    unsafe {
        bpf_probe_read_kernel_str_bytes(bytes as *const _ as *const u8, &mut key.path)
            .map_err(|_| -1)?;
    }

    if let Some(policy_list) = unsafe { DENIED_FILES.get(&key) } {
        let cur_uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

        if unsafe { EXEMPT_UIDS.get(&cur_uid) } == Some(&1) {
            return Ok(0);
        }

        let cur_count = policy_list.count as usize;
        let mut matched = false;
        let mut enforced_perm = 0;

        for i in 0..16 {
            if i >= cur_count {
                break;
            }

            if policy_list.permissions[i].uid == cur_uid {
                matched = true;
                enforced_perm = policy_list.permissions[i].permission;
                break;
            }
        }

        if !matched {
            enforced_perm = policy_list.default_permission;
        }

        if enforced_perm == 2 {
            if log_flag == LOG {
                info!(
                    &ctx,
                    "FILEBLOCK (NOACCESS), access mode: {}, file: {}", acc_mode, filename
                );
            }

            if deny_flag == DENY {
                return Err(-1);
            } else {
                return Ok(0);
            }
        } else if enforced_perm == 1 && acc_mode != O_RDONLY {
            if log_flag == LOG {
                info!(
                    &ctx,
                    "FILEBLOCK (READONLY), access mode: {}, file: {}", acc_mode, filename
                );
            }

            if deny_flag == DENY {
                return Err(-1);
            } else {
                return Ok(0);
            }
        }
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
