#![cfg_attr(not(feature = "std"), no_std)]

pub const NO_DENY: u32 = 0;
pub const DENY: u32 = 1;
pub const NO_LOG: u32 = 0;
pub const LOG: u32 = 1;
pub const EV_EXEC: u8 = 0;
pub const EV_FILE: u8 = 1;
pub const EV_PORT: u8 = 2;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PathKey {
    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PortKey {
    pub port: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UidList {
    pub uids: [u32; 16],
    pub count: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UidPermission {
    pub uid: u32,
    pub permission: u8, // 1 = readonly, 2 = noaccess, _ => invalid
    pub _pad: [u8; 3],  // safety for Pod
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FilePolicyList {
    pub permissions: [UidPermission; 16],
    pub count: u32,
    pub default_permission: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Event {
    pub kind: u8,
    pub denied: u8,
    pub perm: u8,
    pub _pad: u8,
    pub family: u16,
    pub port: u16,
    pub pid: u32,
    pub uid: u32,
    pub mode: u32,
    pub path: [u8; 256],
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for PathKey {}

#[cfg(feature = "std")]
unsafe impl aya::Pod for PortKey {}

#[cfg(feature = "std")]
unsafe impl aya::Pod for UidList {}

#[cfg(feature = "std")]
unsafe impl aya::Pod for UidPermission {}

#[cfg(feature = "std")]
unsafe impl aya::Pod for FilePolicyList {}

#[cfg(feature = "std")]
unsafe impl aya::Pod for Event {}
