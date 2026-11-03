#![no_std]
#![no_main]

#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::programs::LsmContext;
use aya_log_ebpf::info;
use cbody_common::PathKey;

use crate::vmlinux::linux_binprm;

#[repr(C)]
pub struct ScratchBuf {
    pub buf: [u8; 256],
}

#[map]
pub static SCRATCH_MAP: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static ALLOWED_BINARIES: HashMap<PathKey, u32> = HashMap::with_max_entries(1024, 0);

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

    let scratch = match SCRATCH_MAP.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Ok(0),
    };

    let bytes = unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, &mut scratch.buf)
            .map_err(|_| -1)?
    };

    let mut key = PathKey { path: [0; 256] };
    key.path.copy_from_slice(&scratch.buf);

    if unsafe { ALLOWED_BINARIES.get(&key).is_some() } {
        // return Ok(0);
        return Err(-1);
    }

    // let filename = unsafe { core::str::from_utf8_unchecked(bytes) };

    // info!(&ctx, "Filename executed: {}", filename);

    // Err(-1)
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
