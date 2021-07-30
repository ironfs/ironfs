#![no_std]

use zerocopy::{AsBytes, FromBytes};

const IRONFS_VERSION: u32 = 0;

const DATA_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DATA");
const FILE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"INOD");
const EXT_FILE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EINO");
const SUPER_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"SUPR");
const EXT_SUPER_BLOCK_MAGIC: [u8; 12] = *b" BLK IRON FS";
const DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DIRB");
const EXT_DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EDIR");
const FREE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"FREE");

const BLOCK_SIZE: usize = 4096;

const LBA_SIZE: usize = 512;

const NAME_NLEN: usize = 256;

#[derive(AsBytes, FromBytes, PartialEq, Clone)]
#[repr(C)]
struct BlockMagic([u8; 4]);

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
struct BlockId(u32);

const BLOCK_ID_NULL: BlockId = BlockId(0xFFFFFFFF);

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
struct Crc(u32);

const CRC_INIT: Crc = Crc(0x00000000);

#[derive(AsBytes, FromBytes)]
#[repr(packed)]
struct SuperBlock {
    magic: BlockMagic,
    ext_magic: [u8; 12],
    version: u32,
    root_dir_block: BlockId,
    num_blocks: u32,
    block_size: u32,
    created_on: Timestamp,
    crc: Crc,
}

#[derive(AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct DirBlock {
    magic: BlockMagic,
    next_dir_block: BlockId,
    name: [u8; NAME_NLEN],
    owner: u16,
    group: u16,
    perms: u16,
    reserved: u16,
    content_blocks: [BlockId; 955],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(packed)]
struct ExtDirBlock {
    magic: BlockMagic,
    next_dir_block: BlockId,
    data: [BlockId; 1021],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(packed)]
struct DataBlock {
    magic: BlockMagic,
    data: [u8; 4088],
    crc: Crc,
}

#[derive(AsBytes, FromBytes, Clone)]
#[repr(packed)]
pub struct Timestamp {
    pub secs: i64,
    pub nsecs: u64,
}

#[derive(AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct FileBlock {
    magic: BlockMagic,
    next_inode: BlockId,
    name: [u8; NAME_NLEN],
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
#[repr(packed)]
struct ExtFileBlock {
    magic: BlockMagic,
    next_inode: BlockId,
    blocks: [BlockId; 1021],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(packed)]
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

    pub fn format(&mut self, num_blocks: u32) {
        // Write out the initial settings for the super block.
        let mut super_block = SuperBlock {
            magic: SUPER_BLOCK_MAGIC,
            ext_magic: EXT_SUPER_BLOCK_MAGIC,
            version: IRONFS_VERSION,
            root_dir_block: BlockId(1),
            num_blocks,
            block_size: BLOCK_SIZE as u32,
            // TODO
            created_on: Timestamp { secs: 0, nsecs: 0 },
            crc: CRC_INIT,
        };
        const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_CKSUM);
        super_block.crc = Crc(CRC.checksum(super_block.as_bytes()));
        self.write_super_block(&super_block);

        // Write the initial settings for the directory block.
        let mut dir_block = DirBlock {
            magic: DIR_BLOCK_MAGIC,
            next_dir_block: BLOCK_ID_NULL,
            name: [0u8; NAME_NLEN],
            owner: 0,
            group: 0,
            perms: 0,
            reserved: 0,
            content_blocks: [BLOCK_ID_NULL; 955],
            crc: CRC_INIT,
        };
        dir_block.crc = Crc(CRC.checksum(dir_block.as_bytes()));
        self.write_dir_block(DirectoryId(1), &dir_block);
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

    fn id_to_lba(&self, id: u32) -> usize {
        (id as usize * self.block_size()) / LBA_SIZE
    }

    fn read_dir_block(&self, entry: &DirectoryId) -> Result<DirBlock, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0) as u32;
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        use zerocopy::{AsBytes, ByteSlice, ByteSliceMut, FromBytes, LayoutVerified, Unaligned};
        let block: Option<LayoutVerified<_, DirBlock>> = LayoutVerified::new(&bytes[..]);
        if let Some(block) = block {
            if block.magic != DIR_BLOCK_MAGIC {
                return Err(ErrorKind::InconsistentState);
            }

            return Ok((*block).clone());
        } else {
            return Err(ErrorKind::InconsistentState);
        }
    }

    fn read_file_block(&self, entry: &FileId) -> Result<FileBlock, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0) as u32;
        let mut bytes = [0u8; BLOCK_SIZE];
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

    fn write_super_block(&mut self, super_block: &SuperBlock) -> Result<(), ErrorKind> {
        let bytes = super_block.as_bytes();
        self.storage.write(0, &bytes);
        Ok(())
    }

    fn write_dir_block(
        &mut self,
        entry: DirectoryId,
        directory: &DirBlock,
    ) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(entry.0) as u32;
        let bytes = directory.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
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
