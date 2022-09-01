use zerocopy::{AsBytes, FromBytes};

#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq, Clone)]
#[repr(C)]
pub(crate) struct BlockMagic(pub(crate) [u8; 4]);

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct Crc(pub(crate) u32);

pub(crate) const CRC_INIT: Crc = Crc(0x00000000);

pub(crate) const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_CKSUM);

#[derive(Debug, AsBytes, FromBytes, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct BlockId(pub u32);

#[derive(Debug, AsBytes, FromBytes, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct DirectoryId(pub u32);

impl From<DirectoryId> for BlockId {
    fn from(dir_id: DirectoryId) -> Self {
        BlockId(dir_id.0)
    }
}
#[derive(Debug, AsBytes, FromBytes, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct FileId(pub u32);

impl From<FileId> for BlockId {
    fn from(file_id: FileId) -> Self {
        BlockId(file_id.0)
    }
}

pub(crate) const DIR_ID_NULL: DirectoryId = DirectoryId(0xFFFFFFFF);
pub(crate) const FILE_ID_NULL: FileId = FileId(0xFFFFFFFF);
pub(crate) const BLOCK_ID_NULL: BlockId = BlockId(0xFFFFFFFF);

/// Maximum number of characters for directory or file name.
pub const NAME_NLEN: usize = 256;

#[derive(Copy, Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub struct Timestamp {
    pub secs: i64,
    pub nsecs: u64,
}
