#![no_std]
#![no_main]

#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;
use aya_log_ebpf::info;

use crate::vmlinux::linux_binprm;

#[lsm(hook = "lsm/bprm_check_security")]
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

    // let filename_ptr = unsafe {
    //     let bprm = match ctx.read(bprm_ptr) {
    //         Ok(b) => b,
    //         Err(_) => return Ok(0),
    //     };
    //     bprm.filename
    // };
    let filename_ptr = unsafe { (*bprm_ptr).filename };
    let mut filename_buf = [0u8; 256];

    unsafe {
        bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, &mut filename_buf)
            .map_err(|_| -1)?;
    }

    info!(&ctx, "Filename executed: {}", filename_buf);

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
