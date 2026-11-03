#![cfg_attr(not(feature = "std"), no_std)]

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PathKey {
    pub uid: u32,
    pub path: [u8; 256],
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for PathKey {}
