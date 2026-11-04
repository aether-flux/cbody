#![no_std]
#![no_main]

#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::cty::c_int;
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
    bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::LsmContext;
use aya_log_ebpf::info;
use cbody_common::{PathKey, PortKey, UidList};

use crate::vmlinux::{file, linux_binprm, sock, sockaddr, sockaddr_in, socket};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map]
pub static SCRATCH_MAP: PerCpuArray<PathKey> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static DENIED_BINARIES: HashMap<PathKey, UidList> = HashMap::with_max_entries(1024, 0);

#[map]
pub static DENIED_PORTS: HashMap<PortKey, UidList> = HashMap::with_max_entries(1024, 0);

// #[lsm(hook = "bprm_check_security")]
// pub fn bprm_check_security(ctx: LsmContext) -> i32 {
//     match try_bprm_check_security(ctx) {
//         Ok(_) => 0,
//         Err(mut e) => {
//             if e > 0 || e < -4095 {
//                 e = -1;
//             }
//             e
//         }
//     }
// }
//
// #[lsm(hook = "socket_connect")]
// pub fn socket_connect(ctx: LsmContext) -> i32 {
//     match try_socket_connect(ctx) {
//         Ok(_) => 0,
//         Err(mut e) => {
//             if e > 0 || e < -4095 {
//                 e = -1;
//             }
//             e
//         }
//     }
// }

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
        if uid_list.count == 0 {
            let filename = unsafe { core::str::from_utf8_unchecked(&key.path) };
            info!(&ctx, "Filename executed: {}", filename);
            return Err(-1);
        }

        let cur_uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

        let count = uid_list.count as usize;
        for i in 0..16 {
            if i >= count {
                break;
            }
            if uid_list.uids[i] == cur_uid {
                let filename = unsafe { core::str::from_utf8_unchecked(&key.path) };
                info!(&ctx, "Filename executed: {}", filename);
                return Err(-1);
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

    let mut dport = 0u16;
    let mut daddr = [0u8; 16];
    unsafe {
        let a: sockaddr_in = bpf_probe_read_kernel(address as *const sockaddr_in).map_err(|_| 0)?;
        dport = u16::from_be(a.sin_port);
        daddr[..4].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
    }

    let key = PortKey { port: dport };

    if let Some(uid_list) = unsafe { DENIED_PORTS.get(&key) } {
        if uid_list.count == 0 {
            info!(&ctx, "Family: {}, Port: {}", family, dport);
            return Err(-1);
        }

        let cur_uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
        let count = uid_list.count as usize;

        for i in 0..16 {
            if i >= count {
                break;
            }

            if uid_list.uids[i] == cur_uid {
                info!(&ctx, "Family: {}, Port: {}", family, dport);
                return Err(-1);
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

    // Search /usr/include/asm-generic/fcntl.h for all flag values
    // if &(*file).f_flags ==

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
