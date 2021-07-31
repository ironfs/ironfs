#![no_std]

use zerocopy::{AsBytes, FromBytes, LayoutVerified};

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

#[derive(AsBytes, FromBytes, Clone, Copy, PartialEq)]
#[repr(C)]
struct BlockId(u32);

const BLOCK_ID_NULL: BlockId = BlockId(0xFFFFFFFF);

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
struct Crc(u32);

const CRC_INIT: Crc = Crc(0x00000000);

#[derive(AsBytes, FromBytes, Clone)]
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

#[derive(AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct FreeBlock {
    magic: BlockMagic,
    next_free_id: BlockId,
    prev_free_id: BlockId,
    crc: Crc,
}

pub trait Storage {
    fn read(&self, lba: u32, data: &mut [u8]);
    fn write(&mut self, lba: u32, data: &[u8]);
    fn erase(&mut self, lba: u32, num_lba: u32);
}

pub struct IronFs<T: Storage> {
    storage: T,
    next_free_block_id: BlockId,
    is_formatted: bool,
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
    OutOfSpace,
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

const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_CKSUM);

impl<T: Storage> IronFs<T> {
    pub fn new(storage: T) -> Self {
        let mut ironfs = IronFs {
            storage,
            next_free_block_id: BLOCK_ID_NULL,
            is_formatted: false,
        };
        if let Some(super_block) = ironfs.read_super_block().ok() {
            ironfs.is_formatted = true;
            // Hunt for the first free_block.
            for i in 1..super_block.num_blocks {
                let block_id = BlockId(i);
                match ironfs.read_free_block(&block_id) {
                    Ok(_) => {
                        ironfs.next_free_block_id = block_id;
                        break;
                    }
                    Err(_) => {}
                }
            }
        }

        ironfs
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
        self.write_dir_block(&DirectoryId(1), &dir_block);
    }

    pub fn lookup(&self, dir_id: &DirectoryId, name: &str) -> Result<FileId, ErrorKind> {
        Err(ErrorKind::NoEntry)
    }

    pub fn mkdir(&mut self, dir_id: &DirectoryId, name: &str) -> Result<DirectoryId, ErrorKind> {
        let mut existing_directory = self.read_dir_block(dir_id)?;
        // Find existing slot for new directory to be added.
        if let Some(v) = existing_directory
            .content_blocks
            .iter_mut()
            .find(|v| **v == BLOCK_ID_NULL)
        {
            let id = self.alloc_next_free_block()?;
            let mut new_directory_block = DirBlock {
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
            let new_directory_block_id = DirectoryId(id.0);
            Self::fix_dir_block_crc(&mut new_directory_block);
            self.write_dir_block(&new_directory_block_id, &new_directory_block)?;
            *v = BlockId(id.0);
            Self::fix_dir_block_crc(&mut existing_directory);
            self.write_dir_block(&dir_id, &existing_directory)?;
        } else {
            // TODO handle creating a new ext directory.
            unreachable!();
        }
        //if let Some(i, _) = existing_directory.content_blocks.iter().enumerate().any(|(i, v)| v == BLOCK_ID_NULL) { }

        Err(ErrorKind::NoEntry)
    }

    pub fn attrs(&self, entry: &FileId) -> Result<FileAttrs, ErrorKind> {
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

    fn read_super_block(&mut self) -> Result<SuperBlock, ErrorKind> {
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(0, &mut bytes);
        let block: Option<LayoutVerified<_, SuperBlock>> = LayoutVerified::new(&bytes[..]);
        if let Some(block) = block {
            if block.magic != SUPER_BLOCK_MAGIC {
                return Err(ErrorKind::InconsistentState);
            }

            return Ok((*block).clone());
        } else {
            return Err(ErrorKind::InconsistentState);
        }
    }

    fn write_super_block(&mut self, super_block: &SuperBlock) -> Result<(), ErrorKind> {
        let bytes = super_block.as_bytes();
        self.storage.write(0, &bytes);
        Ok(())
    }

    fn fix_free_block_crc(free_block: &mut FreeBlock) {
        free_block.crc = CRC_INIT;
        free_block.crc = Crc(CRC.checksum(free_block.as_bytes()));
    }

    fn fix_dir_block_crc(dir_block: &mut DirBlock) {
        dir_block.crc = CRC_INIT;
        dir_block.crc = Crc(CRC.checksum(dir_block.as_bytes()));
    }

    fn fix_file_block_crc(file_block: &mut FileBlock) {
        file_block.crc = CRC_INIT;
        file_block.crc = Crc(CRC.checksum(file_block.as_bytes()));
    }

    fn write_dir_block(
        &mut self,
        entry: &DirectoryId,
        directory: &DirBlock,
    ) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(entry.0) as u32;
        let bytes = directory.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn read_free_block(&self, free_block_id: &BlockId) -> Result<FreeBlock, ErrorKind> {
        let lba_id = self.id_to_lba(free_block_id.0) as u32;
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        let block: Option<LayoutVerified<_, FreeBlock>> = LayoutVerified::new(&bytes[..]);
        if let Some(block) = block {
            if block.magic != FREE_BLOCK_MAGIC {
                return Err(ErrorKind::InconsistentState);
            }

            return Ok((*block).clone());
        } else {
            return Err(ErrorKind::InconsistentState);
        }
    }

    fn write_free_block(
        &mut self,
        free_block_id: &BlockId,
        free_block: &FreeBlock,
    ) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(free_block_id.0) as u32;
        let bytes = free_block.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn alloc_next_free_block(&mut self) -> Result<BlockId, ErrorKind> {
        if self.next_free_block_id == BLOCK_ID_NULL {
            return Err(ErrorKind::OutOfSpace);
        }

        let free_block_id = self.next_free_block_id;
        let free_block = self.read_free_block(&free_block_id)?;
        self.next_free_block_id = free_block.next_free_id;

        let mut prev_free_block = self.read_free_block(&free_block.prev_free_id)?;
        let mut next_free_block = self.read_free_block(&free_block.next_free_id)?;
        prev_free_block.next_free_id = free_block.next_free_id;
        next_free_block.prev_free_id = free_block.prev_free_id;
        Self::fix_free_block_crc(&mut prev_free_block);
        Self::fix_free_block_crc(&mut next_free_block);
        self.write_free_block(&free_block.prev_free_id, &prev_free_block)?;
        self.write_free_block(&free_block.next_free_id, &next_free_block)?;

        Ok(free_block_id)
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
