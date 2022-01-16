
use zerocopy::{AsBytes, FromBytes};

#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq, Clone)]
#[repr(C)]
pub(crate) struct BlockMagic(pub(crate) [u8; 4]);

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct Crc(pub(crate) u32);

pub(crate) const CRC_INIT: Crc = Crc(0x00000000);

pub(crate) const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_CKSUM);

#[derive(Copy, Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub struct Timestamp {
    pub secs: i64,
    pub nsecs: u64,
}
