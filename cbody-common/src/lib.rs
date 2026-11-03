#![cfg_attr(feature = "ebpf", no_std)]

#[cfg(feature = "ebpf")]
use aya::Pod;

#[cfg(not(feature = "ebpf"))]
pub trait Pod {}
#[cfg(not(feature = "ebpf"))]
impl<T: Copy> Pod for T {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PathKey {
    pub path: [u8; 256],
}

#[cfg(feature = "ebpf")]
unsafe impl aya::Pod for PathKey {}

#[cfg(not(feature = "ebpf"))]
impl Pod for PathKey {}
