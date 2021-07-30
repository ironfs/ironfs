#![no_std]

use zerocopy::{AsBytes, FromBytes};

const DATA_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DATA");
const FILE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"INOD");
const EXT_INODE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EINO");
const SUPER_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"SUPR");
const EXT_SUPER_BLOCK_MAGIC: [u8; 12] = *b" BLK IRON FS";
const DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DIRB");
const EXT_DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EDIR");
const FREE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"FREE");

const BLOCK_SIZE: usize = 4096;

const LBA_SIZE: usize = 512;

#[derive(AsBytes, FromBytes, PartialEq, Clone)]
#[repr(C)]
struct BlockMagic([u8; 4]);

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
struct BlockId(u32);

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
struct Crc(u32);

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct SuperBlock {
    magic: BlockMagic,
    ext_magic: [u8; 12],
    version: u32,
    root_dir_block: BlockId,
    num_blocks: u32,
    block_size: u32,
    created_on: u32,
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct DirBlock {
    magic: BlockMagic,
    next_dir_block: BlockId,
    name: [u8; 256],
    owner: u16,
    group: u16,
    perms: u16,
    reserved: u16,
    content_blocks: [BlockId; 955],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct ExtDirBlock {
    magic: BlockMagic,
    next_dir_block: BlockId,
    data: [BlockId; 1021],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct DataBlock {
    magic: BlockMagic,
    data: [u8; 4088],
    crc: Crc,
}

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
pub struct Timestamp {
    pub secs: i64,
    pub nsecs: u64,
}

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
struct FileBlock {
    magic: BlockMagic,
    next_inode: BlockId,
    name: [u8; 256],
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
    owner: u16,
    group: u16,
    perms: u16,
    reserved: u16,
    data: [u8; 1024],
    blocks: [BlockId; 687],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct ExtFileBlock {
    magic: BlockMagic,
    next_inode: BlockId,
    blocks: [BlockId; 1021],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct FreeBlock {
    magic: BlockMagic,
    next_free: BlockId,
    crc: Crc,
}

pub trait Storage {
    fn read(&self, lba: u32, data: &mut [u8]);
    fn write(&mut self, lba: u32, data: &[u8]);
    fn erase(&mut self, lba: u32, num_lba: u32);
}

pub struct IronFs<T: Storage> {
    storage: T,
}

pub struct DirectoryId(pub u32);
pub struct FileId(pub u32);

pub struct DirectoryListing;

impl DirectoryListing {
    pub fn get(&self, name: &str) -> Option<u32> {
        None
    }
}

pub enum ErrorKind {
    NotImplemented,
    NoEntry,
    InconsistentState,
}

/// Attributes associated with a file.
pub struct FileAttrs {
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub owner: u16,
    pub group: u16,
    pub perms: u16,
}

impl<T: Storage> IronFs<T> {
    pub fn new(storage: T) -> Self {
        IronFs { storage }
    }

    pub fn lookup(&self, dir_id: &DirectoryId, name: &str) -> Result<FileId, ErrorKind> {
        Err(ErrorKind::NoEntry)
    }

    pub fn mkdir(&self, dir_id: &DirectoryId, name: &str) -> Result<DirectoryId, ErrorKind> {
        Err(ErrorKind::NoEntry)
    }

    pub fn attrs(&self, entry: &FileId) -> Result<FileAttrs, ErrorKind> {
        // TODO
        match self.read_file_block(entry) {
            Ok(file) => Ok(FileAttrs {
                atime: file.atime,
                mtime: file.mtime,
                ctime: file.ctime,
                owner: file.owner,
                group: file.group,
                perms: file.perms,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn read_file_block(&self, entry: &FileId) -> Result<FileBlock, ErrorKind> {
        let lba_id = ((entry.0 as usize * BLOCK_SIZE) / LBA_SIZE) as u32;
        let mut bytes = [0u8; BLOCK_SIZE];
        // TODO
        self.storage.read(lba_id, &mut bytes);
        use zerocopy::{AsBytes, ByteSlice, ByteSliceMut, FromBytes, LayoutVerified, Unaligned};
        let file_block: Option<LayoutVerified<_, FileBlock>> = LayoutVerified::new(&bytes[..]);
        if let Some(file_block) = file_block {
            if file_block.magic != FILE_BLOCK_MAGIC {
                return Err(ErrorKind::InconsistentState);
            }

            return Ok((*file_block).clone());
        } else {
            return Err(ErrorKind::InconsistentState);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_file_block_size() {
        assert_eq!(core::mem::size_of::<FileBlock>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_ext_file_block_size() {
        assert_eq!(core::mem::size_of::<ExtFileBlock>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_dir_block_size() {
        assert_eq!(core::mem::size_of::<DirBlock>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_ext_dir_block_size() {
        assert_eq!(core::mem::size_of::<ExtDirBlock>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_data_block_size() {
        assert_eq!(core::mem::size_of::<DataBlock>(), BLOCK_SIZE);
    }
}
