#![deny(unsafe_code)]
#![allow(dead_code)]
#![cfg_attr(not(test), no_std)]

mod data_block;
mod dir_block;
mod dir_block_ext;
mod error;
mod file;
mod file_block;
mod file_block_ext;
mod storage;
mod util;

use data_block::DataBlock;
use dir_block::{DirBlock, DIR_BLOCK_NUM_ENTRIES};
use dir_block_ext::DirBlockExt;
pub use error::ErrorKind;
use file::File;
use file_block::FileBlock;
use file_block_ext::FileBlockExt;
pub use storage::{Geometry, LbaId, Storage};
use util::BlockMagic;
pub use util::Timestamp;
pub use util::{BlockId, DirectoryId, FileId, NAME_NLEN};
use util::{Crc, CRC, CRC_INIT};
use util::{BLOCK_ID_NULL, DIR_ID_NULL, FILE_ID_NULL};

use log::{debug, error, trace, warn};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

const IRONFS_VERSION: u32 = 0;

const SUPER_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"SUPR");
const EXT_SUPER_BLOCK_MAGIC: [u8; 12] = *b" BLK IRON FS";
const EXT_DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EDIR");
const FREE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"FREE");

pub(crate) const BLOCK_SIZE: usize = 4096;

const LBA_SIZE: usize = 512;

/// Representation of the different types of blocks in the filesystem.
enum BlockMagicType {
    DataBlock,
    FileBlock,
    FileBlockExt,
    SuperBlock,
    DirBlock,
    DirBlockExt,
    FreeBlock,
}

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
struct GenericBlock {
    magic: BlockMagic,
    crc: Crc,
}

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
struct SuperBlock {
    magic: BlockMagic,
    crc: Crc,
    ext_magic: [u8; 12],
    reserved1: [u8; 4],
    version: u32,
    root_dir_block: BlockId,
    num_blocks: u32,
    block_size: u32,
    created_on: Timestamp,
    reserved2: [u8; 4040],
}

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
struct FreeBlock {
    magic: BlockMagic,
    crc: Crc,
    next_free_id: BlockId,
    prev_free_id: BlockId,
}

impl FreeBlock {
    fn fix_crc(&mut self) {
        self.crc = CRC_INIT;
        self.crc = Crc(CRC.checksum(self.as_bytes()));
    }
}

pub struct IronFs<T: Storage> {
    storage: T,
    next_free_block_id: BlockId,
    is_formatted: bool,
    /// Routine that yields current time.
    get_now_timestamp: fn() -> Timestamp,
}

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
                    let id = block.entries[index];
                    if id != BLOCK_ID_NULL {
                        trace!("got entry for {} with id: {:?}", index, id);
                        return Some(id);
                    }
                } else {
                    #[cfg(debug_assertions)]
                    panic!("Filesystem is in inconsistent state.");
                    // TODO re-enable break after panic is removed.
                    // break;
                }
            } else {
                break;
            }
        }
        None
    }
}

impl DirectoryListing {
    pub fn get(&self, _name: &str) -> Option<u32> {
        None
    }
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
    pub perms: u32,
}

impl<T: Storage> IronFs<T> {
    pub fn new(storage: T, timestamp: fn() -> Timestamp) -> Self {
        IronFs {
            storage,
            next_free_block_id: BLOCK_ID_NULL,
            is_formatted: false,
            get_now_timestamp: timestamp,
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

    pub fn format(&mut self, now: Timestamp) -> Result<(), ErrorKind> {
        let geometry = self.storage.geometry();
        let num_blocks = ((geometry.lba_size * geometry.num_blocks) / BLOCK_SIZE) as u32;
        debug!("num blocks is: {}", num_blocks);

        // Write out the initial settings for the super block.
        let mut super_block = SuperBlock {
            magic: SUPER_BLOCK_MAGIC,
            ext_magic: EXT_SUPER_BLOCK_MAGIC,
            reserved1: [0u8; 4],
            version: IRONFS_VERSION,
            root_dir_block: BlockId(1),
            num_blocks,
            block_size: BLOCK_SIZE as u32,
            created_on: now,
            crc: CRC_INIT,
            reserved2: [0u8; 4040],
        };
        super_block.crc = Crc(CRC.checksum(super_block.as_bytes()));
        self.write_super_block(&super_block)?;

        // Write the initial settings for the directory block.
        let mut dir_block = DirBlock::from_timestamp(now);
        dir_block.name_len = 1;
        dir_block.name[0] = '/' as u8;
        dir_block.crc = Crc(CRC.checksum(dir_block.as_bytes()));
        trace!("writing root dir block.");
        self.write_dir_block(&DirectoryId(1), &dir_block)?;

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
            free_block.fix_crc();

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
                        let file_block = FileBlock::try_from(&block[..])
                            .expect("failure to convert bytes to file inode");
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
                        let dir_block = DirBlock::try_from(&block[..])
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

    pub fn create(
        &mut self,
        parent: &DirectoryId,
        name: &str,
        perms: u32,
        now: Timestamp,
    ) -> Result<FileId, ErrorKind> {
        let mut existing_directory = self.read_dir_block(parent)?;
        if let Some(v) = existing_directory
            .entries
            .iter_mut()
            .find(|v| **v == BLOCK_ID_NULL)
        {
            let id = self.acquire_free_block()?;
            trace!("create: using free block: {:?}", id);

            // TODO switch to File API.
            //let mut new_file = File::create_from_timestamp(self, now);

            let new_file_block = FileBlock::new(&now, name.as_bytes(), perms);
            let new_file_block_id = FileId(id.0);
            self.write_file_block(&new_file_block_id, &new_file_block)?;
            trace!("create: wrote new file");

            *v = BlockId(id.0);
            existing_directory.mtime = now;
            existing_directory.fix_crc();
            self.write_dir_block(&parent, &existing_directory)?;
            trace!("create: wrote existing directory");
            return Ok(new_file_block_id);
        } else {
            // TODO handle creating a new ext directory.
            Err(ErrorKind::NoEntry)
        }
    }

    pub fn mkdir(
        &mut self,
        dir_id: &DirectoryId,
        name: &str,
        now: Timestamp,
    ) -> Result<DirectoryId, ErrorKind> {
        trace!("mkdir: create a new directory block");
        let id = self.acquire_free_block()?;
        let new_directory_id = DirectoryId(id.0);
        trace!("mkdir: using free block: {:?}", id);
        let mut new_directory_block = DirBlock::from_timestamp(now);
        new_directory_block.name_len = name.len() as u32;
        new_directory_block.name[..name.len()].copy_from_slice(name.as_bytes());
        let new_directory_block_id = DirectoryId(id.0);
        new_directory_block.fix_crc();
        self.write_dir_block(&new_directory_block_id, &new_directory_block)?;
        trace!("mkdir: wrote new directory");

        // TODO handle directory already exists.
        // TODO handle permissions.

        let mut existing_directory = self.read_dir_block(dir_id)?;
        trace!("mkdir: read existing directory");

        // Find existing slot for new directory to be added.
        if existing_directory.has_empty_slot() {
            existing_directory.add_entry(id)?;
            existing_directory.mtime = now;
            existing_directory.fix_crc();
            self.write_dir_block(&dir_id, &existing_directory)?;
            trace!("mkdir: wrote existing directory");
        } else {
            // Look through ext dir block hunting for available entries.
            let mut next_dir_block = existing_directory.next_dir_block;
            if next_dir_block == DIR_ID_NULL {
                // We have to create a ext dir block.
                next_dir_block = DirectoryId(self.acquire_free_block()?.0);
                existing_directory.next_dir_block = next_dir_block;
                existing_directory.fix_crc();
                self.write_dir_block(dir_id, &existing_directory)?;
            }

            let ext_dir_block_id = next_dir_block;
            let mut ext_dir_block = self
                .read_dir_block_ext(&next_dir_block)
                .unwrap_or(DirBlockExt::default());
            loop {
                if ext_dir_block.has_empty_slot() {
                    ext_dir_block.add_entry(id)?;
                    existing_directory.mtime = now;
                    existing_directory.fix_crc();
                    self.write_dir_block(&dir_id, &existing_directory)?;
                    self.write_dir_block_ext(&ext_dir_block_id, &ext_dir_block)?;
                    trace!(
                        "mkdir: wrote id: {:?} into ext_dir_block: {:?}",
                        new_directory_id,
                        ext_dir_block_id
                    );
                    break;
                } else {
                    next_dir_block = ext_dir_block.next_dir_block;
                    if next_dir_block == DIR_ID_NULL {
                        // We have to create a ext dir block.
                        next_dir_block = DirectoryId(self.acquire_free_block()?.0);
                        ext_dir_block.next_dir_block = next_dir_block;
                        ext_dir_block.fix_crc();
                        self.write_dir_block_ext(&ext_dir_block_id, &ext_dir_block)?;
                        ext_dir_block = DirBlockExt::default();
                    } else {
                        ext_dir_block = self.read_dir_block_ext(&next_dir_block)?;
                    }
                }
            }
        }
        return Ok(new_directory_id);
    }

    pub fn attrs(&self, entry: &BlockId) -> Result<Attrs, ErrorKind> {
        let mut bytes = [0u8; BLOCK_SIZE];
        self.read_block(entry, &mut bytes[..])
            .expect("failure to read block");
        match block_magic_type(&bytes) {
            Some(BlockMagicType::FileBlock) => {
                let file = FileBlock::try_from(&bytes[..])
                    .expect("failure to convert bytes to file inode");
                Ok(Attrs {
                    block_id: *entry,
                    kind: AttrKind::File,
                    size: file.size as u32,
                    atime: file.atime,
                    mtime: file.mtime,
                    ctime: file.ctime,
                    owner: file.owner,
                    group: file.group,
                    perms: file.perms,
                })
            }
            Some(BlockMagicType::DirBlock) => {
                let dir =
                    DirBlock::try_from(&bytes[..]).expect("failure to convert bytes to dir block");
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
                    file_block.name(name)?;
                    return Ok(());
                }
            }
            Some(BlockMagicType::DirBlock) => {
                let dir_block: Option<LayoutVerified<_, DirBlock>> =
                    LayoutVerified::new(&bytes[..]);
                if let Some(dir_block) = dir_block {
                    dir_block.name(name)?;
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
        if *entry == BLOCK_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        debug!("Read block: {:?}", lba_id);
        self.storage.read(lba_id, bytes);
        Ok(())
    }

    fn read_data_block(&self, entry: &BlockId) -> Result<DataBlock, ErrorKind> {
        if *entry == BLOCK_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        trace!("Read data block: {}", entry.0);
        self.storage.read(lba_id, &mut bytes);
        DataBlock::try_from(&bytes[..])
    }

    fn read_dir_block(&self, entry: &DirectoryId) -> Result<DirBlock, ErrorKind> {
        if BlockId(entry.0) == BLOCK_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        trace!("Read dir block: {}", entry.0);
        self.storage.read(lba_id, &mut bytes);
        DirBlock::try_from(&bytes[..])
    }

    fn read_dir_block_ext(&self, entry: &DirectoryId) -> Result<DirBlockExt, ErrorKind> {
        if *entry == DIR_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        trace!("Read ext dir block: {}", entry.0);
        self.storage.read(lba_id, &mut bytes);
        DirBlockExt::try_from(&bytes[..])
    }

    fn read_file_block(&self, entry: &FileId) -> Result<FileBlock, ErrorKind> {
        if *entry == FILE_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        trace!("Read file block");
        self.storage.read(lba_id, &mut bytes);
        FileBlock::try_from(&bytes[..])
    }

    fn read_file_block_ext(&self, entry: &FileId) -> Result<FileBlockExt, ErrorKind> {
        if *entry == FILE_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        trace!("Read ext file block: {}", entry.0);
        self.storage.read(lba_id, &mut bytes);
        FileBlockExt::try_from(&bytes[..])
    }

    fn read_super_block(&mut self) -> Result<SuperBlock, ErrorKind> {
        let mut bytes = [0u8; BLOCK_SIZE];
        trace!("Reading super block");
        self.storage.read(LbaId(0), &mut bytes);
        let block: Option<LayoutVerified<_, SuperBlock>> = LayoutVerified::new(&bytes[..]);
        if let Some(block) = block {
            if block.magic != SUPER_BLOCK_MAGIC {
                warn!("Failed to read proper super block magic.");
                return Err(ErrorKind::InconsistentState);
            }

            return Ok((*block).clone());
        } else {
            warn!("Failed to create verified layout of superblock");
            return Err(ErrorKind::InconsistentState);
        }
    }

    fn write_super_block(&mut self, super_block: &SuperBlock) -> Result<(), ErrorKind> {
        let bytes = super_block.as_bytes();
        debug!("Writing super block");
        self.storage.write(LbaId(0), &bytes);
        Ok(())
    }

    fn write_data_block(&mut self, entry: &BlockId, data: &DataBlock) -> Result<(), ErrorKind> {
        if *entry == BLOCK_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let bytes = data.as_bytes();
        trace!("Writing data block: {:x?} lba_id: {:x?}", entry, lba_id);
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn write_dir_block(
        &mut self,
        entry: &DirectoryId,
        directory: &DirBlock,
    ) -> Result<(), ErrorKind> {
        if *entry == DIR_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let bytes = directory.as_bytes();
        debug!("Write dir block");
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn write_dir_block_ext(
        &mut self,
        entry: &DirectoryId,
        directory: &DirBlockExt,
    ) -> Result<(), ErrorKind> {
        if *entry == DIR_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let bytes = directory.as_bytes();
        debug!("Write dir block");
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn write_file_block(&mut self, entry: &FileId, file: &FileBlock) -> Result<(), ErrorKind> {
        if *entry == FILE_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let bytes = file.as_bytes();
        debug!("Write file block");
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn write_file_block_ext(
        &mut self,
        entry: &FileId,
        ext_file: &FileBlockExt,
    ) -> Result<(), ErrorKind> {
        if *entry == FILE_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(entry.0);
        let bytes = ext_file.as_bytes();
        trace!(
            "writing ext file block lba_id: {:x?} with bytes len: {}",
            lba_id,
            bytes.len()
        );
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn read_free_block(&self, free_block_id: &BlockId) -> Result<FreeBlock, ErrorKind> {
        if *free_block_id == BLOCK_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
        let lba_id = self.id_to_lba(free_block_id.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        let block: Option<(LayoutVerified<_, FreeBlock>, _)> =
            LayoutVerified::new_from_prefix(&bytes[..]);
        if let Some((block, _)) = block {
            if block.magic != FREE_BLOCK_MAGIC {
                error!(
                    "Block {:?} was supposed to be free and was not.",
                    free_block_id
                );
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
        if *free_block_id == BLOCK_ID_NULL {
            error!("Invalid block ID NULL.");
            return Err(ErrorKind::InconsistentState);
        }
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

        if free_block.prev_free_id == free_block.next_free_id {
            warn!("Out of free blocks.");
            self.next_free_block_id = BLOCK_ID_NULL;
        } else {
            let mut prev_free_block = self.read_free_block(&free_block.prev_free_id)?;
            let mut next_free_block = self.read_free_block(&free_block.next_free_id)?;
            prev_free_block.next_free_id = free_block.next_free_id;
            next_free_block.prev_free_id = free_block.prev_free_id;
            prev_free_block.fix_crc();
            next_free_block.fix_crc();
            self.write_free_block(&free_block.prev_free_id, &prev_free_block)?;
            self.write_free_block(&free_block.next_free_id, &next_free_block)?;
            trace!(
                "Updated free blocks: {:?} {:?}",
                free_block.prev_free_id,
                free_block.next_free_id
            );
        }

        trace!("Acquired free block: {:?}", free_block_id);

        Ok(free_block_id)
    }

    fn release_block(&mut self, cur_free_block_id: BlockId) -> Result<(), ErrorKind> {
        if cur_free_block_id == BLOCK_ID_NULL {
            return Err(ErrorKind::InconsistentState);
        }

        trace!("Releasing block: {:?}", cur_free_block_id);

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
        prev_free_block.fix_crc();
        cur_free_block.fix_crc();
        next_free_block.fix_crc();
        self.write_free_block(&prev_free_block_id, &prev_free_block)?;
        self.write_free_block(&cur_free_block_id, &cur_free_block)?;
        self.write_free_block(&next_free_block_id, &next_free_block)?;

        Ok(())
    }

    pub fn read(
        &self,
        file_id: &FileId,
        offset: usize,
        data: &mut [u8],
        _now: Timestamp,
    ) -> Result<u64, ErrorKind> {
        let file_block = self.read_file_block(file_id)?;
        let sz = file_block.read(self, offset, data)?;
        /*
         * TODO figure out what to do about atime.
        file_block.atime = now;
        file_block.fix_crc();
        self.write_file_block(file_id, &file_block)?;
        */
        Ok(sz as u64)
    }

    pub fn write(
        &mut self,
        file_id: &FileId,
        offset: usize,
        data: &[u8],
        now: Timestamp,
    ) -> Result<u64, ErrorKind> {
        // We expect this file handle was already allocated.
        let mut file_block = self.read_file_block(file_id)?;
        let sz = file_block.write(self, offset, data)?;
        file_block.mtime = now;
        file_block.fix_crc();
        self.write_file_block(file_id, &file_block)?;
        Ok(sz as u64)
    }

    pub fn unlink(
        &mut self,
        dir_id: &DirectoryId,
        name: &str,
        now: Timestamp,
    ) -> Result<(), ErrorKind> {
        if let Ok(block_id) = self.lookup(dir_id, name) {
            // First remove the block from directory leaving it dangling.
            let mut dir_block = self.read_dir_block(dir_id)?;
            let entry = dir_block
                .entries
                .iter_mut()
                .find(|v| **v == block_id)
                .unwrap();
            *entry = BLOCK_ID_NULL;
            dir_block.mtime = now;
            dir_block.fix_crc();
            self.write_dir_block(&dir_id, &dir_block)?;

            // Erase all the block_id contents.
            // This neesd to move on to next_inode etc file contents.
            let file = File::from_inode(FileId(block_id.0));
            file.unlink(self)?;
        } else {
            return Err(ErrorKind::NoEntry);
        }

        Ok(())
    }
}

impl<T: Storage> IronFs<T> {
    pub(crate) fn cur_timestamp(&self) -> Timestamp {
        (self.get_now_timestamp)()
    }
}

fn block_magic_type(bytes: &[u8]) -> Option<BlockMagicType> {
    let mut magic = [0u8; 4];
    magic.clone_from_slice(&bytes[0..4]);
    match BlockMagic(magic) {
        data_block::DATA_BLOCK_MAGIC => Some(BlockMagicType::DataBlock),
        file_block::FILE_BLOCK_MAGIC => Some(BlockMagicType::FileBlock),
        file_block_ext::FILE_BLOCK_EXT_MAGIC => Some(BlockMagicType::FileBlockExt),
        SUPER_BLOCK_MAGIC => Some(BlockMagicType::SuperBlock),
        dir_block::DIR_BLOCK_MAGIC => Some(BlockMagicType::DirBlock),
        dir_block_ext::DIR_BLOCK_EXT_MAGIC => Some(BlockMagicType::DirBlockExt),
        FREE_BLOCK_MAGIC => Some(BlockMagicType::FreeBlock),
        _ => None,
    }
}

#[cfg(test)]
mod tests_util {
    use super::*;

    pub(crate) fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    pub(crate) struct RamStorage(Vec<u8>);

    impl RamStorage {
        pub(crate) fn new(nbytes: usize) -> Self {
            RamStorage(vec![0u8; nbytes])
        }
    }

    const LBA_SIZE: usize = 512;

    impl Storage for RamStorage {
        fn read(&self, lba: LbaId, data: &mut [u8]) {
            let start_addr = lba.0 * LBA_SIZE;
            data.clone_from_slice(&self.0[start_addr..start_addr + data.len()]);
        }
        fn write(&mut self, lba: LbaId, data: &[u8]) {
            let start_addr = lba.0 * LBA_SIZE;
            trace!(
                "Writing lba id: {:x?} start_addr: {:x} end_addr: {:x}",
                lba,
                start_addr,
                start_addr + data.len()
            );
            self.0[start_addr..start_addr + data.len()].copy_from_slice(data);
        }
        fn erase(&mut self, lba: LbaId, num_lba: usize) {
            let start_addr = lba.0 * LBA_SIZE;
            let end_addr = (lba.0 + num_lba) * LBA_SIZE;
            for i in &mut self.0[start_addr..end_addr] {
                *i = 0xFF;
            }
        }

        fn geometry(&self) -> Geometry {
            Geometry {
                lba_size: 512,
                num_blocks: self.0.len() / 512,
            }
        }
    }

    pub(crate) fn current_timestamp() -> Timestamp {
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        Timestamp {
            secs: since_the_epoch.as_secs() as i64,
            nsecs: since_the_epoch.subsec_nanos() as u64,
        }
    }

    pub(crate) fn make_filesystem<T: Storage>(storage: T) -> IronFs<T> {
        let mut ironfs = IronFs::new(storage, current_timestamp);
        match ironfs.bind() {
            Err(ErrorKind::NotFormatted) => {
                ironfs
                    .format(current_timestamp())
                    .expect("Failure to format ironfs.");
                ironfs.bind().expect("Failure to bind after format.");
            }
            _ => {}
        };
        debug!("Filesystem made and formatted");
        ironfs
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::tests_util::*;
    use log::info;

    #[test]
    fn valid_file_block_size() {
        assert_eq!(core::mem::size_of::<FileBlock>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_file_block_ext_size() {
        assert_eq!(core::mem::size_of::<FileBlockExt>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_super_block_size() {
        assert_eq!(core::mem::size_of::<SuperBlock>(), BLOCK_SIZE);
    }

    #[test]
    fn test_big_file_write() {
        init();
        const NUM_BYTES: usize = 3_000_000;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file = File::create(&mut ironfs, "big_file", 0, 0, 0).unwrap();
        file.write(&mut ironfs, 0, &data[..]).unwrap();

        let mut data2 = vec![0u8; NUM_BYTES];
        file.read(&ironfs, 0, &mut data2).unwrap();

        assert_eq!(data, data2);
    }

    #[test]
    fn test_big_file_small_chunks_write() {
        init();
        const NUM_BYTES: usize = 3_000_000;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file = File::create(&mut ironfs, "big_file", 0, 0, 0).unwrap();
        let mut pos = 0;
        for chunk in data.chunks(16384) {
            file.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += 16384;
        }

        let mut data2 = vec![0u8; NUM_BYTES];
        file.read(&ironfs, 0, &mut data2).unwrap();

        let mut prev = None;
        for i in (0..data.len()).step_by(32) {
            if let Some(prev) = prev {
                info!("inspecting section: {} to {}", prev, i);
                let orig = String::from_utf8_lossy(&data[prev..i]);
                let new = String::from_utf8_lossy(&data2[prev..i]);
                assert_eq!(orig, new);
            }
            prev = Some(i);
        }
    }

    /*
    #[test]
    fn test_write_file_block_ext_small_chunks() {
            init();
        const NUM_BYTES: usize = 1_000_000;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file_block = FileBlock::default();
        let starting_pos = FileBlock::capacity();
        let mut pos = starting_pos;
        for chunk in data.chunks(8112) {
            file_block.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += 8112;
        }

        let mut data2 = vec![0u8; NUM_BYTES];
        file_block.read(&ironfs, starting_pos, &mut data2).unwrap();

        let mut prev = None;
        for i in (0..data.len()).step_by(32) {
            if let Some(prev) = prev {
                let orig = String::from_utf8_lossy(&data[prev..i]);
                let new = String::from_utf8_lossy(&data2[prev..i]);
                assert_eq!(orig, new);
                //assert_eq!(&data[prev..i], &data2[prev..i])
            }

            prev = Some(i);
        }
    }
    */

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]

    }
}
