#![no_std]

use log::{debug, error, info, trace, warn};
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

pub const NAME_NLEN: usize = 256;

/// Representation of the different types of blocks in the filesystem.
enum BlockMagicType {
    DataBlock,
    FileBlock,
    ExtFileBlock,
    SuperBlock,
    DirBlock,
    ExtDirBlock,
    FreeBlock,
}

#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq, Clone)]
#[repr(C)]
struct BlockMagic([u8; 4]);

#[derive(Debug, AsBytes, FromBytes, Clone, Copy, PartialEq)]
#[repr(C)]
pub struct BlockId(pub u32);

const BLOCK_ID_NULL: BlockId = BlockId(0xFFFFFFFF);

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
struct Crc(u32);

const CRC_INIT: Crc = Crc(0x00000000);

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct GenericBlock {
    magic: BlockMagic,
    crc: Crc,
}

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct SuperBlock {
    magic: BlockMagic,
    crc: Crc,
    ext_magic: [u8; 12],
    version: u32,
    root_dir_block: BlockId,
    num_blocks: u32,
    block_size: u32,
    created_on: Timestamp,
}

const DIR_BLOCK_NUM_ENTRIES: usize = 942;

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct DirBlock {
    magic: BlockMagic,
    crc: Crc,
    next_dir_block: BlockId,
    name_len: u32,
    name: [u8; NAME_NLEN],
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
    owner: u16,
    group: u16,
    perms: u16,
    reserved1: u16,
    entries: [BlockId; DIR_BLOCK_NUM_ENTRIES],
}

impl DirBlock {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, ErrorKind> {
        let block: Option<LayoutVerified<_, DirBlock>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        return Err(ErrorKind::InconsistentState);
    }
}

impl Default for DirBlock {
    fn default() -> Self {
        // Todo record current time.
        DirBlock {
            magic: DIR_BLOCK_MAGIC,
            crc: CRC_INIT,
            next_dir_block: BLOCK_ID_NULL,
            name_len: 0,
            name: [0u8; NAME_NLEN],
            atime: Timestamp { secs: 0, nsecs: 0 },
            mtime: Timestamp { secs: 0, nsecs: 0 },
            ctime: Timestamp { secs: 0, nsecs: 0 },
            owner: 0,
            group: 0,
            perms: 0,
            reserved1: 0,
            entries: [BLOCK_ID_NULL; DIR_BLOCK_NUM_ENTRIES],
        }
    }
}

#[derive(AsBytes, FromBytes)]
#[repr(packed)]
struct ExtDirBlock {
    magic: BlockMagic,
    crc: Crc,
    next_dir_block: BlockId,
    data: [BlockId; 1021],
}

#[derive(AsBytes, FromBytes)]
#[repr(packed)]
struct DataBlock {
    magic: BlockMagic,
    crc: Crc,
    data: [u8; 4088],
}

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(packed)]
pub struct Timestamp {
    pub secs: i64,
    pub nsecs: u64,
}

#[derive(AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct FileBlock {
    magic: BlockMagic,
    crc: Crc,
    next_inode: BlockId,
    name_len: u32,
    name: [u8; NAME_NLEN],
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
    owner: u16,
    group: u16,
    perms: u16,
    reserved: u16,
    data: [u8; 1024],
    blocks: [BlockId; 686],
}

impl FileBlock {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, ErrorKind> {
        let block: Option<LayoutVerified<_, FileBlock>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        return Err(ErrorKind::InconsistentState);
    }
}

#[derive(AsBytes, FromBytes)]
#[repr(packed)]
struct ExtFileBlock {
    magic: BlockMagic,
    crc: Crc,
    next_inode: BlockId,
    blocks: [BlockId; 1021],
}

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(packed)]
struct FreeBlock {
    magic: BlockMagic,
    crc: Crc,
    next_free_id: BlockId,
    prev_free_id: BlockId,
}

pub struct Geometry {
    pub lba_size: usize,
    pub num_blocks: usize,
}

pub struct LbaId(pub usize);

pub trait Storage {
    fn read(&self, lba: LbaId, data: &mut [u8]);
    fn write(&mut self, lba: LbaId, data: &[u8]);
    fn erase(&mut self, lba: LbaId, num_lba: usize);
    fn geometry(&self) -> Geometry;
}

pub struct IronFs<T: Storage> {
    storage: T,
    next_free_block_id: BlockId,
    is_formatted: bool,
}

#[derive(Debug)]
pub struct DirectoryId(pub u32);
#[derive(Debug)]
pub struct FileId(pub u32);

pub struct DirectoryListing {
    block_id: DirectoryId,
    index: usize,
    cache: [u8; BLOCK_SIZE],
}

impl Iterator for DirectoryListing {
    type Item = BlockId;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO handle moving to next
        loop {
            if self.index < DIR_BLOCK_NUM_ENTRIES {
                let index = self.index;
                self.index += 1;

                let block: Option<LayoutVerified<_, DirBlock>> =
                    LayoutVerified::new(&self.cache[..]);
                if let Some(block) = block {
                    debug!("entries are: {:?}", &block.entries[..12]);
                    let id = block.entries[index];
                    if id != BLOCK_ID_NULL {
                        trace!("got entry for {} with id: {:?}", index, id);
                        return Some(id);
                    }
                } else {
                    #[cfg(debug_assertions)]
                    panic!("Filesystem is in inconsistent state.");
                    break;
                }
            } else {
                break;
            }
        }
        None
    }
}

impl DirectoryListing {
    pub fn get(&self, name: &str) -> Option<u32> {
        None
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    NotImplemented,
    NoEntry,
    InconsistentState,
    OutOfSpace,
    NotFormatted,
}

#[derive(Debug)]
pub enum AttrKind {
    File,
    Directory,
}

/// Attributes associated with a file.
pub struct Attrs {
    pub block_id: BlockId,
    pub kind: AttrKind,
    pub size: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub owner: u16,
    pub group: u16,
    pub perms: u16,
}

const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_CKSUM);

impl<T: Storage> IronFs<T> {
    pub fn from(storage: T) -> Self {
        IronFs {
            storage,
            next_free_block_id: BLOCK_ID_NULL,
            is_formatted: false,
        }
    }

    pub fn bind(&mut self) -> Result<(), ErrorKind> {
        debug!("entered bind.");
        if let Some(super_block) = self.read_super_block().ok() {
            if super_block.magic != SUPER_BLOCK_MAGIC {
                debug!("super block had wrong magic.");
                return Err(ErrorKind::NotFormatted);
            }
            self.is_formatted = true;
            debug!("filesystem is formatted");

            // Hunt for the first free_block.
            for i in 1..super_block.num_blocks {
                trace!("looking for free block at: {}", i);
                let block_id = BlockId(i);
                match self.read_free_block(&block_id) {
                    Ok(_) => {
                        debug!("found first free block at: {:?}", block_id);
                        self.next_free_block_id = block_id;
                        break;
                    }
                    Err(_) => {}
                }
            }
        } else {
            debug!("failure to read super block");
            return Err(ErrorKind::NotFormatted);
        }

        Ok(())
    }

    pub fn format(&mut self) -> Result<(), ErrorKind> {
        let geometry = self.storage.geometry();
        let num_blocks = ((geometry.lba_size * geometry.num_blocks) / BLOCK_SIZE) as u32;
        debug!("num blocks is: {}", num_blocks);

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
        self.write_super_block(&super_block)?;

        // Write the initial settings for the directory block.
        let mut dir_block = DirBlock::default();
        dir_block.name_len = 1;
        dir_block.name[0] = '/' as u8;
        dir_block.crc = Crc(CRC.checksum(dir_block.as_bytes()));
        trace!("writing root dir block.");
        self.write_dir_block(&DirectoryId(1), &dir_block);

        for i in 2..num_blocks {
            let prev_free_id = if i == 2 {
                BlockId(num_blocks - 1)
            } else {
                BlockId(i - 1)
            };
            let next_free_id = if i == (num_blocks - 1) {
                BlockId(2)
            } else {
                BlockId(i + 1)
            };
            let mut free_block = FreeBlock {
                magic: FREE_BLOCK_MAGIC,
                crc: CRC_INIT,
                next_free_id,
                prev_free_id,
            };
            Self::fix_free_block_crc(&mut free_block);

            self.write_free_block(&BlockId(i), &free_block)?;
        }
        self.next_free_block_id = BlockId(2);

        Ok(())
    }

    /*
    pub fn format(&mut self, num_blocks: u32) {
    }
    */

    pub fn lookup(&self, dir_id: &DirectoryId, name: &str) -> Result<BlockId, ErrorKind> {
        let dir = self.read_dir_block(dir_id)?;
        //trace!("read existing directory {:?} from dir_id: {:?}", dir, dir_id);
        // TODO handle extended directory.
        for block_id in dir.entries.iter() {
            if *block_id != BLOCK_ID_NULL {
                // Read out existing block. Check filename.
                let mut block = [0u8; BLOCK_SIZE];
                self.read_block(block_id, &mut block[..])
                    .expect("failure to read block");

                match block_magic_type(&block) {
                    Some(BlockMagicType::FileBlock) => {
                        let file_block = FileBlock::try_from_bytes(&block[..])
                            .expect("failure to convert bytes to file block");
                        let file_name =
                            core::str::from_utf8(&file_block.name[..file_block.name_len as usize]);
                        if let Ok(file_name) = file_name {
                            if name == file_name {
                                return Ok(*block_id);
                            }
                        } else {
                            error!("file name could not be converted to utf8");
                        }
                    }
                    Some(BlockMagicType::DirBlock) => {
                        let dir_block = DirBlock::try_from_bytes(&block[..])
                            .expect("failure to convert bytes to dir block");
                        let dir_name =
                            core::str::from_utf8(&dir_block.name[..dir_block.name_len as usize]);
                        if let Ok(dir_name) = dir_name {
                            if name == dir_name {
                                return Ok(*block_id);
                            }
                        } else {
                            error!("directory name could not be converted to utf8");
                        }
                    }
                    _ => {
                        // This is a major error.
                        unreachable!();
                    }
                }
            }
        }

        Err(ErrorKind::NoEntry)
    }

    pub fn mkdir(&mut self, dir_id: &DirectoryId, name: &str) -> Result<DirectoryId, ErrorKind> {
        // TODO handle directory already exists.
        // TODO handle permissions.
        let mut existing_directory = self.read_dir_block(dir_id)?;
        trace!("mkdir: read existing directory");
        // Find existing slot for new directory to be added.
        if let Some(v) = existing_directory
            .entries
            .iter_mut()
            .find(|v| **v == BLOCK_ID_NULL)
        {
            let id = self.acquire_free_block()?;
            trace!("mkdir: using free block: {:?}", id);
            let mut new_directory_block = DirBlock::default();
            new_directory_block.name_len = name.len() as u32;
            new_directory_block.name[..name.len()].copy_from_slice(name.as_bytes());
            let new_directory_block_id = DirectoryId(id.0);
            Self::fix_dir_block_crc(&mut new_directory_block);
            self.write_dir_block(&new_directory_block_id, &new_directory_block)?;
            trace!("mkdir: wrote new directory");
            *v = BlockId(id.0);
            Self::fix_dir_block_crc(&mut existing_directory);
            self.write_dir_block(&dir_id, &existing_directory)?;
            trace!("mkdir: wrote existing directory");
            return Ok(new_directory_block_id);
        } else {
            // TODO handle creating a new ext directory.
            Err(ErrorKind::NoEntry)
        }
    }

    pub fn attrs(&self, entry: &BlockId) -> Result<Attrs, ErrorKind> {
        let mut bytes = [0u8; BLOCK_SIZE];
        self.read_block(entry, &mut bytes[..])
            .expect("failure to read block");
        match block_magic_type(&bytes) {
            Some(BlockMagicType::FileBlock) => {
                let file = FileBlock::try_from_bytes(&bytes[..])
                    .expect("failure to convert bytes to file block");
                Ok(Attrs {
                    block_id: *entry,
                    kind: AttrKind::File,
                    size: 1,
                    atime: file.atime,
                    mtime: file.mtime,
                    ctime: file.ctime,
                    owner: file.owner,
                    group: file.group,
                    perms: file.perms,
                })
            }
            Some(BlockMagicType::DirBlock) => {
                let dir = DirBlock::try_from_bytes(&bytes[..])
                    .expect("failure to convert bytes to dir block");
                Ok(Attrs {
                    block_id: *entry,
                    kind: AttrKind::Directory,
                    size: 1,
                    atime: dir.atime,
                    mtime: dir.mtime,
                    ctime: dir.ctime,
                    owner: dir.owner,
                    group: dir.group,
                    perms: dir.perms,
                })
            }
            _ => Err(ErrorKind::InconsistentState),
        }
    }

    pub fn readdir(&self, directory_id: DirectoryId) -> Result<DirectoryListing, ErrorKind> {
        // TODO handle directory_id being invalid directory.
        trace!("readdir called with id: {:?}", directory_id);
        let mut listing = DirectoryListing {
            block_id: directory_id,
            index: 0,
            cache: [0u8; BLOCK_SIZE],
        };
        self.read_block(&BlockId(listing.block_id.0), &mut listing.cache[..])?;
        Ok(listing)
    }

    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    pub fn block_name<'a>(&'a self, block_id: &BlockId, name: &mut [u8]) -> Result<(), ErrorKind> {
        let mut bytes = [0u8; BLOCK_SIZE];
        self.read_block(block_id, &mut bytes[..])?;

        match block_magic_type(&bytes) {
            Some(BlockMagicType::FileBlock) => {
                let file_block: Option<LayoutVerified<_, FileBlock>> =
                    LayoutVerified::new(&bytes[..]);
                if let Some(file_block) = file_block {
                    let name_len = file_block.name_len as usize;
                    name[..name_len].copy_from_slice(&file_block.name[..name_len]);
                    return Ok(());
                }
            }
            Some(BlockMagicType::DirBlock) => {
                let dir_block: Option<LayoutVerified<_, DirBlock>> =
                    LayoutVerified::new(&bytes[..]);
                if let Some(dir_block) = dir_block {
                    let name_len = dir_block.name_len as usize;
                    name[..name_len].copy_from_slice(&dir_block.name[..name_len]);
                    return Ok(());
                }
            }
            _ => return Err(ErrorKind::InconsistentState),
        }

        unreachable!();
    }

    pub fn block_file_type(&self, block_id: &BlockId) -> Result<AttrKind, ErrorKind> {
        let mut block = [0u8; BLOCK_SIZE];
        self.read_block(block_id, &mut block[..])?;

        match block_magic_type(&block) {
            Some(BlockMagicType::FileBlock) => Ok(AttrKind::File),
            Some(BlockMagicType::DirBlock) => Ok(AttrKind::Directory),
            _ => Err(ErrorKind::InconsistentState),
        }
    }

    fn id_to_lba(&self, id: u32) -> LbaId {
        LbaId((id as usize * self.block_size()) / LBA_SIZE)
    }

    fn read_block(&self, entry: &BlockId, bytes: &mut [u8]) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        self.storage.read(lba_id, bytes);
        Ok(())
    }

    fn read_dir_block(&self, entry: &DirectoryId) -> Result<DirBlock, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        DirBlock::try_from_bytes(&bytes[..])
    }

    fn read_file_block(&self, entry: &FileId) -> Result<FileBlock, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
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
        self.storage.read(LbaId(0), &mut bytes);
        let block: Option<(LayoutVerified<_, SuperBlock>, &[u8])> =
            LayoutVerified::new_from_prefix(&bytes[..]);
        if let Some((block, _)) = block {
            if block.magic != SUPER_BLOCK_MAGIC {
                debug!("Failed to read proper super block magic.");
                return Err(ErrorKind::InconsistentState);
            }

            return Ok((*block).clone());
        } else {
            debug!("Failed to create verified layout of superblock");
            return Err(ErrorKind::InconsistentState);
        }
    }

    fn write_super_block(&mut self, super_block: &SuperBlock) -> Result<(), ErrorKind> {
        let bytes = super_block.as_bytes();
        self.storage.write(LbaId(0), &bytes);
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
        let lba_id = self.id_to_lba(entry.0);
        let bytes = directory.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn read_free_block(&self, free_block_id: &BlockId) -> Result<FreeBlock, ErrorKind> {
        let lba_id = self.id_to_lba(free_block_id.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        let block: Option<(LayoutVerified<_, FreeBlock>, _)> =
            LayoutVerified::new_from_prefix(&bytes[..]);
        if let Some((block, _)) = block {
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
        let lba_id = self.id_to_lba(free_block_id.0);
        let bytes = free_block.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn acquire_free_block(&mut self) -> Result<BlockId, ErrorKind> {
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

    fn release_free_block(&mut self, cur_free_block_id: BlockId) -> Result<(), ErrorKind> {
        if cur_free_block_id == BLOCK_ID_NULL {
            return Err(ErrorKind::InconsistentState);
        }

        let next_free_block_id = self.next_free_block_id;
        let mut next_free_block = self.read_free_block(&next_free_block_id)?;
        let prev_free_block_id = next_free_block.prev_free_id;
        let mut prev_free_block = self.read_free_block(&prev_free_block_id)?;

        let mut cur_free_block = FreeBlock {
            magic: FREE_BLOCK_MAGIC,
            next_free_id: next_free_block_id,
            prev_free_id: prev_free_block_id,
            crc: CRC_INIT,
        };

        next_free_block.prev_free_id = cur_free_block_id;
        prev_free_block.next_free_id = cur_free_block_id;
        Self::fix_free_block_crc(&mut prev_free_block);
        Self::fix_free_block_crc(&mut cur_free_block);
        Self::fix_free_block_crc(&mut next_free_block);
        self.write_free_block(&prev_free_block_id, &prev_free_block)?;
        self.write_free_block(&cur_free_block_id, &cur_free_block)?;
        self.write_free_block(&next_free_block_id, &next_free_block)?;

        Ok(())
    }
}

fn block_magic_type(bytes: &[u8]) -> Option<BlockMagicType> {
    let mut magic = [0u8; 4];
    magic.clone_from_slice(&bytes[0..4]);
    match BlockMagic(magic) {
        DATA_BLOCK_MAGIC => Some(BlockMagicType::DataBlock),
        FILE_BLOCK_MAGIC => Some(BlockMagicType::FileBlock),
        EXT_FILE_BLOCK_MAGIC => Some(BlockMagicType::ExtFileBlock),
        SUPER_BLOCK_MAGIC => Some(BlockMagicType::SuperBlock),
        DIR_BLOCK_MAGIC => Some(BlockMagicType::DirBlock),
        EXT_DIR_BLOCK_MAGIC => Some(BlockMagicType::ExtDirBlock),
        FREE_BLOCK_MAGIC => Some(BlockMagicType::FreeBlock),
        _ => None,
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
