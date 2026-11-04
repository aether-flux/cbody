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
use cbody_common::{PathKey, UidList};

use crate::vmlinux::{linux_binprm, sock, sockaddr, sockaddr_in, socket};

// const AF_UNIX: u16 = 1;
// const AF_INET: u16 = 2;
// const AF_INET6: u16 = 10;
//
// #[repr(C)]
// pub struct ConnectEvent {
//     pub pid: u32,
//     pub tgid: u32,
//     pub uid: u32,
//     pub family: u16,
//     pub sock_type: u16,
//     pub protocol: u16,
//     pub dport: u16,
//     pub sport: u16,
//     pub daddr: [u8; 16],
//     pub saddr: [u8; 16],
//     pub comm: [u8; 16],
// }

#[map]
pub static SCRATCH_MAP: PerCpuArray<PathKey> = PerCpuArray::with_max_entries(1, 0);

// #[map]
// pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static DENIED_BINARIES: HashMap<PathKey, UidList> = HashMap::with_max_entries(1024, 0);

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

        let cur_uid = (unsafe { bpf_get_current_uid_gid() } & 0xFFFFFFFF) as u32;

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

// fn try_socket_connect(ctx: LsmContext) -> Result<i32, i32> {
//     let sock: *const socket = ctx.arg(0);
//     let address: *const sockaddr = ctx.arg(1);
//     let addrlen: c_int = ctx.arg(2);
//     let prev_ret: c_int = ctx.arg(3);
//
//     if prev_ret != 0 {
//         return Ok(prev_ret);
//     }
//
//     if address.is_null() || sock.is_null() {
//         return Ok(0);
//     }
//
//     let family =
//         unsafe { bpf_probe_read_kernel(&(*address).sa_family as *const u16).map_err(|_| 0)? };
//
//     let mut ev = match EVENTS.reserve::<ConnectEvent>(0) {
//         Some(e) => e,
//         None => return Ok(0),
//     };
//     let e = ev.as_mut_ptr();
//     unsafe {
//         core::ptr::write_bytes(e, 0, 1);
//         (*e).family = family;
//     }
//
//     match family {
//         AF_INET => {
//             if (addrlen as usize) < core::mem::size_of::<sockaddr_in>() {
//                 ev.discard(0);
//                 return Ok(0);
//             }
//             unsafe {
//                 let a: sockaddr_in =
//                     bpf_probe_read_kernel(address as *const sockaddr_in).map_err(|_| 0)?;
//                 (*e).dport = u16::from_be(a.sin_port);
//                 (*e).daddr[..4].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
//             }
//         }
//         _ => {
//             ev.discard(0);
//             return Ok(0);
//         }
//     }
//
//     unsafe {
//         (*e).sock_type = bpf_probe_read_kernel::<i16>(&(*sock).type_).unwrap_or(0) as u16;
//         let sk: *const sock =
//             bpf_probe_read_kernel::<*mut sock>(&(*sock).sk).unwrap_or(core::ptr::null_mut());
//         if !sk.is_null() {
//             (*e).protocol = bpf_probe_read_kernel::<u16>(&(*sk).sk_protocol).unwrap_or(0) as u16;
//         }
//     }
//
//     unsafe {
//         let pt = bpf_get_current_pid_tgid();
//         (*e).pid = pt as u32;
//         (*e).tgid = (pt >> 32) as u32;
//         (*e).uid = bpf_get_current_uid_gid() as u32;
//         (*e).comm = bpf_get_current_comm().unwrap_or([0; 16]);
//     }
//
//     ev.submit(0);
//     Ok(0)
// }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
