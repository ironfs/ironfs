#![cfg_attr(not(test), no_std)]

mod data_block;
mod file_block;
mod ext_file_block;
mod error;
mod storage;
mod util;

use ext_file_block::ExtFileBlock;
use file_block::FileBlock;
use data_block::DataBlock;
pub use error::ErrorKind;
pub use util::Timestamp;
use util::BLOCK_ID_NULL;
pub use storage::{Geometry, LbaId, Storage};
use util::{Crc, CRC_INIT, CRC};
pub use util::{BlockId, NAME_NLEN};
use util::BlockMagic;

use log::{debug, error, info, trace, warn};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

const IRONFS_VERSION: u32 = 0;

const SUPER_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"SUPR");
const EXT_SUPER_BLOCK_MAGIC: [u8; 12] = *b" BLK IRON FS";
const DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DIRB");
const EXT_DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EDIR");
const FREE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"FREE");

pub(crate) const BLOCK_SIZE: usize = 4096;

const LBA_SIZE: usize = 512;

/// Representation of the different types of blocks in the filesystem.
enum BlockMagicType {
    DataBlock,
    FileBlock,
    ExtFileBlock,
    SuperBlock,
    DirInode,
    DirInodeExt,
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

const DIR_BLOCK_NUM_ENTRIES: usize = 940;

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
struct DirInode {
    magic: BlockMagic,
    crc: Crc,
    next_dir_block: BlockId,
    name_len: u32,
    name: [u8; NAME_NLEN],
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
    reserved1: u64,
    owner: u16,
    group: u16,
    perms: u32,
    entries: [BlockId; DIR_BLOCK_NUM_ENTRIES],
}

impl TryFrom<&[u8]> for DirInode {
    type Error = ErrorKind;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let block: Option<LayoutVerified<_, DirInode>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        error!("Failure to create dirblock from bytes.");
        return Err(ErrorKind::InconsistentState);
    }
}

impl DirInode {

    fn fix_crc(&mut self) {
        self.crc = CRC_INIT;
        self.crc = Crc(CRC.checksum(self.as_bytes()));
    }

    pub(crate) fn name(&self, name: &mut [u8]) -> Result<(), ErrorKind> {
        if name.len() < self.name_len as usize {
            return Err(ErrorKind::InsufficientSpace);
        }
        let name_len = self.name_len as usize;
        name[..name_len].copy_from_slice(&self.name[..name_len]);
        Ok(())
    }
}

impl DirInode {
    fn from_timestamp(now: Timestamp) -> Self {
        // Todo record current time.
        DirInode {
            magic: DIR_BLOCK_MAGIC,
            crc: CRC_INIT,
            next_dir_block: BLOCK_ID_NULL,
            name_len: 0,
            name: [0u8; NAME_NLEN],
            atime: now,
            mtime: now,
            ctime: now,
            owner: 0,
            group: 0,
            perms: 0,
            reserved1: 0,
            entries: [BLOCK_ID_NULL; DIR_BLOCK_NUM_ENTRIES],
        }
    }
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct DirInodeExt {
    magic: BlockMagic,
    crc: Crc,
    next_dir_block: BlockId,
    reserved: u32,
    data: [BlockId; 1020],
}

struct File {
    top_inode: FileId,
}

impl File {
    fn create_from_timestamp<T: Storage>(ironfs: &mut IronFs<T>, now: Timestamp) -> Result<Self, ErrorKind> {
        let mut inode = FileBlock::default();
        unimplemented!();
    }

    /// Open a file.
    /// TODO make this accept Path as parameter.
    fn open<T: Storage>(ironfs: &mut IronFs<T>, path: &str) -> Result<Self, ErrorKind> {
        let mut inode = FileBlock::default();
        unimplemented!();
    }

    fn unlink<T: Storage>(&self, ironfs: &mut IronFs<T>) -> Result<(), ErrorKind> {
        let file_block = ironfs.read_file_block(&self.top_inode)?;
        file_block.unlink_data(ironfs)?;

        // Now release all ext file blocks and data blocks associated with the file.
        let mut ext_file_id: BlockId = file_block.next_inode.into();
        ironfs.release_block(self.top_inode.into())?;
        while ext_file_id != BLOCK_ID_NULL {
            let ext_file_block = ironfs.read_ext_file_block(&ext_file_id.into())?;
            ext_file_block.unlink_data(ironfs)?;
            let orig_ext_file_id = ext_file_id;
            ext_file_id = ext_file_block.next_inode;
            ironfs.release_block(orig_ext_file_id)?;
        }

        Ok(())
    }

        /*
    fn read<T: Storage>(
        &mut self,
        ironfs: &IronFs<T>,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, ErrorKind> {

        info!("rd file offset: {} data len: {}", offset, data.len());
        let mut pos = 0;

        let inode = ironfs.read_file_block(&self.top_inode)?;
        let end = core::cmp::min(inode.size as usize, data.len());
        if offset < FileBlock::capacity() {
            pos += inode.read(ironfs, offset, &mut data[..FileBlock::capacity()])?;
        }

        if pos == end {
            return Ok(pos);
        }

        assert!((pos + offset) >= FileBlock::capacity());

        // Navigate through existing ext file inode blocks loading each successive id until we
        // reach the place where we intend to read data.
        let end = ((pos + offset - FileBlock::capacity()) / FileBlockExt::capacity()) * FileBlockExt::capacity();
        let begin = FileBlock::capacity() + FileBlockExt::capacity();
        let mut ext_file_block_inode_id = inode.next_inode;
        let mut ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
        for i in begin..end.step_by(FileBlockExt::capacity()) {
                // Iterate through the ext file inode to find the one at our expected index.
                ext_file_block_inode_id = ext_file_block.next_inode;
                assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);
                trace!("rd read block id: 0x{:x}", ext_file_block_inode_id.0);
                ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
        }
        let mut ext_file_block_idx = end / FileBlockExt::capacity();

        // We're now reading data from the extended file inode area.
        while pos < end {
            assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);

            let mut pos_in_ext_file = pos + offset - FileBlock::capacity()
                - ext_file_block_idx * FileBlockExt::capacity();
            trace!(
                "rd pos in ext file: {} pos: {} end: {}",
                pos_in_ext_file,
                pos,
                end
            );

            let num_bytes = ext_file_block.read(ironfs, pos_in_ext_file, &mut data[pos..])?;
            trace!("rd num_bytes: {}", num_bytes);

            pos += num_bytes;
            pos_in_ext_file += num_bytes;
            trace!("rd pos_in_ext_file: {}", pos_in_ext_file);
            if pos_in_ext_file >= (EXT_FILE_BLOCK_NUM_BLOCKS * DataBlock::capacity()) {
                ext_file_block_inode_id = ext_file_block.next_inode;
                trace!("rd read block id: {}", ext_file_block_inode_id.0);
                if ext_file_block_inode_id != BLOCK_ID_NULL {
                    ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
                    ext_file_block_idx += 1;
                } else {
                    // We expected to have further data but did not.
                    return Err(ErrorKind::InconsistentState);
                }
                trace!(
                    "rd nxt inode: {} ext_file_block_idx: {}",
                    ext_file_block_inode_id.0,
                    ext_file_block_idx
                );
            }
        }

        Ok(pos)
    }
        */

            /*
    fn write<T: Storage>(
        &mut self,
        ironfs: &mut IronFs<T>,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, ErrorKind> {
        info!("wr file offset: {} data len: {}", offset, data.len());

        let mut pos = 0;
        let end = data.len();

        let mut file_inode = ironfs.read_file_block(&self.top_inode);

        if offset > FileBlock::capacity() {
            assert!(file_inode.is_some());
        }

        // TODO timestamp
        let timest
        let mut file_inode = file_inode.unwrap_or(FileBlock::from_timestamp());

        if offset < FileBlock::capacity() {
            let nbytes = core::cmp::min(end, file_inode.data.len() - offset);
            file_inode.data[offset..offset + nbytes].copy_from_slice(&data[..nbytes]);
            pos += nbytes;
        }

        if pos == end {
            return Ok(pos);
        }

        assert!((pos + offset) >= FileBlock::capacity());

        while pos < end {
            let idx = (pos + offset - FileBlock::capacity()) / FileBlockExt::capacity();
            let (data_block_id, mut data_block) = if file_inode.blocks[idx] == BLOCK_ID_NULL {
                let id = ironfs.acquire_free_block()?;
                file_inode.blocks[idx] = id;
                (id, DataBlock::default())
            } else {
                let id = file_inode.blocks[idx];
                (id, ironfs.read_data_block(&id)?)
            };
            let pos_in_block = (pos + offset - NUM_BYTES_INITIAL_CONTENTS) % DataBlock::capacity();
            let num_bytes = core::cmp::min(DataBlock::capacity() - pos_in_block, end - pos);
            data_block.write(pos_in_block, &data[pos..pos+num_bytes])?;
            ironfs.write_data_block(&data_block_id, &data_block)?;

            pos += num_bytes;
        }

        if (pos + offset - NUM_BYTES_INITIAL_CONTENTS)
            >= (NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity())
        {
            let mut ext_file_block_idx = (pos + offset
                - NUM_BYTES_INITIAL_CONTENTS
                - NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity())
                / (EXT_FILE_BLOCK_NUM_BLOCKS * DataBlock::capacity());
            let (mut ext_file_block_id, mut ext_file_block) = if file_inode.next_inode == BLOCK_ID_NULL {
                assert!(ext_file_block_idx == 0);
                file_inode.next_inode = ironfs.acquire_free_block()?;
                file_inode.fix_crc();
                (file_inode.next_inode, FileBlockExt::default())
            } else {
                (
                    file_inode.next_inode,
                    ironfs.read_ext_file_block(&file_inode.next_inode)?,
                )
            };
            trace!("wr second inode: {}", file_inode.next_inode.0);
            trace!("wr block_idx: {}", ext_file_block_idx);

            for _ in 0..ext_file_block_idx {
                if ext_file_block.next_inode == BLOCK_ID_NULL {
                    let new_inode_id = ironfs.acquire_free_block()?;
                    ext_file_block.next_inode = new_inode_id;
                    trace!("wr new ext file inode: {}", ext_file_block.next_inode.0);
                    ext_file_block.fix_crc();
                    ironfs.write_ext_file_block(&ext_file_block_id, &ext_file_block)?;
                    ext_file_block_id = new_inode_id;
                    ext_file_block = FileBlockExt::default();
                } else {
                    ext_file_block_id = ext_file_block.next_inode;
                    ext_file_block = ironfs.read_ext_file_block(&ext_file_block_id)?;
                }
            }

            while pos < end {
                let pos_in_ext_file = pos + offset
                    - NUM_BYTES_INITIAL_CONTENTS
                    - NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity()
                    - ext_file_block_idx * EXT_FILE_BLOCK_NUM_BLOCKS * DataBlock::capacity();

                let num_bytes = ext_file_block.write(ironfs, pos_in_ext_file, &data[pos..end])?;
                pos += num_bytes;
                assert_ne!(num_bytes, 0);

                let new_ext_file_block_idx = (pos + offset
                    - NUM_BYTES_INITIAL_CONTENTS
                    - NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity())
                    / (EXT_FILE_BLOCK_NUM_BLOCKS * DataBlock::capacity());

                let needs_more_data = ext_file_block_idx != new_ext_file_block_idx || pos < end;
                let has_more_data = ext_file_block.next_inode != BLOCK_ID_NULL;
                trace!(
                    "wr needs more data: {} has more data: {}",
                    needs_more_data,
                    has_more_data
                );

                if needs_more_data && !has_more_data {
                    ext_file_block.next_inode = ironfs.acquire_free_block()?;
                }

                ext_file_block.fix_crc();
                ironfs.write_ext_file_block(&ext_file_block_id, &ext_file_block)?;
                ext_file_block_id = ext_file_block.next_inode;
                trace!("wr write next inode: 0x{:x}", ext_file_block_id.0);

                if needs_more_data {
                    if !has_more_data {
                        ext_file_block = FileBlockExt::default();
                    } else {
                        ext_file_block = ironfs.read_ext_file_block(&ext_file_block_id)?;
                    }
                }

                ext_file_block_idx = new_ext_file_block_idx;
                trace!("wr block_idx: {}", ext_file_block_idx);
            }
        }

        if file_inode.size < (pos + offset) as u64 {
            file_inode.size = (pos + offset) as u64;
        }

        Ok(pos)
    }
        */
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
}

#[derive(Debug, Clone, Copy)]
pub struct DirectoryId(pub u32);

impl From<DirectoryId> for BlockId {
    fn from(dir_id: DirectoryId) -> Self {
        BlockId(dir_id.0)
    }
}
#[derive(Debug, Clone, Copy)]
pub struct FileId(pub u32);

impl From<FileId> for BlockId {
    fn from(file_id: FileId) -> Self {
        BlockId(file_id.0)
    }
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

                let block: Option<LayoutVerified<_, DirInode>> =
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
        let mut dir_block = DirInode::from_timestamp(now);
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
                    Some(BlockMagicType::DirInode) => {
                        let dir_block = DirInode::try_from(&block[..])
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
            let mut new_directory_block = DirInode::from_timestamp(now);
            new_directory_block.name_len = name.len() as u32;
            new_directory_block.name[..name.len()].copy_from_slice(name.as_bytes());
            let new_directory_block_id = DirectoryId(id.0);
            new_directory_block.fix_crc();
            self.write_dir_block(&new_directory_block_id, &new_directory_block)?;
            trace!("mkdir: wrote new directory");
            *v = BlockId(id.0);
            existing_directory.mtime = now;
            existing_directory.fix_crc();
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
            Some(BlockMagicType::DirInode) => {
                let dir = DirInode::try_from(&bytes[..])
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
                    file_block.name(name)?;
                    return Ok(());
                }
            }
            Some(BlockMagicType::DirInode) => {
                let dir_block: Option<LayoutVerified<_, DirInode>> =
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
            Some(BlockMagicType::DirInode) => Ok(AttrKind::Directory),
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

    fn read_data_block(&self, entry: &BlockId) -> Result<DataBlock, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        DataBlock::try_from(&bytes[..])
    }

    fn read_dir_block(&self, entry: &DirectoryId) -> Result<DirInode, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        DirInode::try_from(&bytes[..])
    }

    fn read_file_block(&self, entry: &FileId) -> Result<FileBlock, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        FileBlock::try_from(&bytes[..])
    }

    fn read_ext_file_block(&self, entry: &BlockId) -> Result<ExtFileBlock, ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(lba_id, &mut bytes);
        ExtFileBlock::try_from(&bytes[..])
    }

    fn read_super_block(&mut self) -> Result<SuperBlock, ErrorKind> {
        let mut bytes = [0u8; BLOCK_SIZE];
        self.storage.read(LbaId(0), &mut bytes);
        let block: Option<LayoutVerified<_, SuperBlock>> = LayoutVerified::new(&bytes[..]);
        if let Some(block) = block {
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

    fn write_data_block(&mut self, entry: &BlockId, data: &DataBlock) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let bytes = data.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn write_dir_block(
        &mut self,
        entry: &DirectoryId,
        directory: &DirInode,
    ) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let bytes = directory.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn write_file_block(&mut self, entry: &FileId, file: &FileBlock) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let bytes = file.as_bytes();
        self.storage.write(lba_id, &bytes);
        Ok(())
    }

    fn write_ext_file_block(
        &mut self,
        entry: &BlockId,
        ext_file: &ExtFileBlock,
    ) -> Result<(), ErrorKind> {
        let lba_id = self.id_to_lba(entry.0);
        let bytes = ext_file.as_bytes();
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

        if free_block.prev_free_id == free_block.next_free_id {
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
        }

        Ok(free_block_id)
    }

    fn release_block(&mut self, cur_free_block_id: BlockId) -> Result<(), ErrorKind> {
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
        now: Timestamp,
    ) -> Result<u64, ErrorKind> {
        let mut file_block = self.read_file_block(file_id)?;
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
            let mut file = File { top_inode: FileId(block_id.0) };
            file.unlink(self)?;
        } else {
            return Err(ErrorKind::NoEntry);
        }

        Ok(())
    }
}

fn block_magic_type(bytes: &[u8]) -> Option<BlockMagicType> {
    let mut magic = [0u8; 4];
    magic.clone_from_slice(&bytes[0..4]);
    match BlockMagic(magic) {
        DATA_BLOCK_MAGIC => Some(BlockMagicType::DataBlock),
        FILE_INODE_MAGIC => Some(BlockMagicType::FileBlock),
        FILE_INODE_EXT_MAGICK => Some(BlockMagicType::ExtFileBlock),
        SUPER_BLOCK_MAGIC => Some(BlockMagicType::SuperBlock),
        DIR_BLOCK_MAGIC => Some(BlockMagicType::DirInode),
        EXT_DIR_BLOCK_MAGIC => Some(BlockMagicType::DirInodeExt),
        FREE_BLOCK_MAGIC => Some(BlockMagicType::FreeBlock),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use unicode_segmentation::UnicodeSegmentation;
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
        assert_eq!(core::mem::size_of::<DirInode>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_ext_dir_block_size() {
        assert_eq!(core::mem::size_of::<DirInodeExt>(), BLOCK_SIZE);
    }

    #[test]
    fn valid_super_block_size() {
        assert_eq!(core::mem::size_of::<SuperBlock>(), BLOCK_SIZE);
    }

    struct RamStorage(Vec<u8>);

    impl RamStorage {
        fn new(nbytes: usize) -> Self {
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

    fn current_timestamp() -> Timestamp {
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

    fn make_filesystem<T: Storage>(storage: T) -> IronFs<T> {
        let mut ironfs = IronFs::from(storage);
        match ironfs.bind() {
            Err(ErrorKind::NotFormatted) => {
                ironfs
                    .format(current_timestamp())
                    .expect("Failure to format ironfs.");
                ironfs.bind().expect("Failure to bind after format.");
            }
            _ => {}
        };
        ironfs
    }

    #[test]
    fn test_ext_file_block_write() {
        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(29)));
        let mut ext_file_block = ExtFileBlock::default();
        let data: Vec<usize> = (0..ExtFileBlock::capacity()).collect();
        let data: Vec<u8> = data.iter().map(|x| *x as u8).collect();
        assert_eq!(data.len(), ExtFileBlock::capacity());
        ext_file_block.write(&mut ironfs, 0, &data[..]).unwrap();
        // Now confirm all of the written data blocks have proper contents.
    }

    #[test]
    fn test_ext_file_block_read() {
        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(29)));
        let mut ext_file_block = ExtFileBlock::default();

        let txt = rust_counter_strings::generate(ExtFileBlock::capacity());
        let data = txt.as_bytes();
        assert_eq!(data.len(), ExtFileBlock::capacity());
        ext_file_block.write(&mut ironfs, 0, &data[..]).unwrap();

        let mut data2 = vec![0u8; ExtFileBlock::capacity()];
        ext_file_block.read(&mut ironfs, 0, &mut data2[..]).unwrap();
        for i in 0..ExtFileBlock::capacity() {
            assert_eq!(data[i], data2[i]);
        }
    }

    #[test]
    fn test_big_file_write() {
        const NUM_BYTES: usize = 3_000_000;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file_block = FileBlock::default();
        file_block.write(&mut ironfs, 0, &data[..]).unwrap();

        let mut data2 = vec![0u8; NUM_BYTES];
        file_block.read(&ironfs, 0, &mut data2).unwrap();

        for i in 0..data.len() {
            assert_eq!(data[i], data2[i]);
        }
    }

    #[test]
    fn test_big_file_small_chunks_write() {
        env_logger::init();

        const NUM_BYTES: usize = 3_000_000;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file_block = FileBlock::default();
        let mut pos = 0;
        for chunk in data.chunks(16384) {
            file_block.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += 16384;
        }

        let mut data2 = vec![0u8; NUM_BYTES];
        file_block.read(&ironfs, 0, &mut data2).unwrap();

        for i in 0..data.len() {
            assert_eq!(data[i], data2[i]);
        }
    }

    /// Test the condition where we cross a portion of an internal boundary and have a failure to
    /// properly write.
    #[test]
    fn test_write_internal_boundary_fail() {
        env_logger::init();

        const CHUNK_SIZE: usize = 8112;
        const NUM_BYTES: usize = 10_000;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file_block = FileBlock::default();
        let starting_pos = FileBlock::capacity();
        trace!("Starting pos is: {}", starting_pos);
        let mut pos = starting_pos;
        for chunk in data.chunks(CHUNK_SIZE) {
            file_block.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += CHUNK_SIZE;
        }

        // Confirm that we have all zeroed data leading up to starting position.
        info!("Confirm that leading data is zeroed.");
        let mut zero_buf = vec![0u8; starting_pos];
        file_block.read(&ironfs, 0, &mut zero_buf[..]);
        for i in 0..zero_buf.len() {
            assert_eq!(0, zero_buf[i]);
        }

        info!("Confirm that we have valid counter string data");
        let mut data2 = vec![0u8; NUM_BYTES];
        file_block.read(&ironfs, starting_pos, &mut data2).unwrap();

        let mut prev = None;
        for i in (0..data.len()).step_by(32) {
            if let Some(prev) = prev {
                let orig = String::from_utf8_lossy(&data[prev..i]);
                let new = String::from_utf8_lossy(&data2[prev..i]);
                assert_eq!(orig, new);
            }

            prev = Some(i);
        }
    }

    #[test]
    fn test_write_ext_file_block_small_chunks() {
        env_logger::init();

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

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]

        #[test]
        fn test_ext_file_block_write_offsets(offset in 0usize..DataBlock::capacity()) {
            let txt = rust_counter_strings::generate(ExtFileBlock::capacity());
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
            let mut block = ExtFileBlock::default();
            block.write(&mut ironfs, offset, &data[..]).unwrap();
            let mut data2 = vec![0u8; ExtFileBlock::capacity()];
            block.read(&ironfs, 0, &mut data2[..]).unwrap();
            for i in 0..offset {
                prop_assert_eq!(data2[i], 0u8);
            }
            for i in offset..ExtFileBlock::capacity() {
                prop_assert_eq!(data2[i], data[i - offset]);
            }
        }

        #[test]
        fn test_ext_file_block_read_offsets(offset in 0usize..DataBlock::capacity()) {
            let txt = rust_counter_strings::generate(ExtFileBlock::capacity());
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
            let mut block = ExtFileBlock::default();
            block.write(&mut ironfs, 0, &data[..]).unwrap();
            let mut data2 = vec![0u8; ExtFileBlock::capacity()];
            block.read(&ironfs, offset, &mut data2[..]).unwrap();
            for i in 0..(ExtFileBlock::capacity() - offset) {
                prop_assert_eq!(data2[i], data[i + offset]);
            }
            for i in (ExtFileBlock::capacity() - offset)..ExtFileBlock::capacity() {
                prop_assert_eq!(data2[i], 0u8);
            }
        }

    }
}
