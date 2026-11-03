#![cfg_attr(not(feature = "std"), no_std)]

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PathKey {
    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UidList {
    pub uids: [u32; 16],
    pub count: u32,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for PathKey {}

#[cfg(feature = "std")]
unsafe impl aya::Pod for UidList {}
