#![no_std]
#![no_main]

#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::helpers::{bpf_get_current_uid_gid, bpf_probe_read_kernel_str_bytes};
use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::programs::LsmContext;
use aya_log_ebpf::info;
use cbody_common::{PathKey, UidList};

use crate::vmlinux::linux_binprm;

// #[repr(C)]
// pub struct ScratchBuf {
//     pub buf: [u8; 256],
// }

#[map]
pub static SCRATCH_MAP: PerCpuArray<PathKey> = PerCpuArray::with_max_entries(1, 0);

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
