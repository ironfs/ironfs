use crate::data_block::DataBlock;
use crate::error::ErrorKind;
use crate::storage::Storage;
use crate::util::{BlockId, BlockMagic, Crc, Timestamp, BLOCK_ID_NULL, CRC, CRC_INIT, NAME_NLEN};
use crate::IronFs;
use log::info;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

const FILE_INODE_MAGIC: BlockMagic = BlockMagic(*b"INOD");

const NUM_BYTES_INITIAL_CONTENTS: usize = 1024;

const NUM_DATA_BLOCKS_IN_FILE: usize = 684;

#[derive(AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct FileBlock {
    magic: BlockMagic,
    crc: Crc,
    pub(crate) next_inode: BlockId,
    pub(crate) name_len: u32,
    pub(crate) name: [u8; NAME_NLEN],
    pub(crate) atime: Timestamp,
    pub(crate) mtime: Timestamp,
    pub(crate) ctime: Timestamp,
    pub(crate) owner: u16,
    pub(crate) group: u16,
    pub(crate) perms: u32,
    pub(crate) size: u64,
    data: [u8; NUM_BYTES_INITIAL_CONTENTS],
    blocks: [BlockId; NUM_DATA_BLOCKS_IN_FILE],
}

impl Default for FileBlock {
    fn default() -> Self {
        let zero_time = Timestamp { secs: 0, nsecs: 0 };
        FileBlock {
            magic: FILE_INODE_MAGIC,
            crc: CRC_INIT,
            next_inode: BLOCK_ID_NULL,
            name_len: 0,
            name: [0u8; NAME_NLEN],
            atime: zero_time,
            mtime: zero_time,
            ctime: zero_time,
            owner: 0,
            group: 0,
            perms: 0,
            size: 0,
            data: [0u8; 1024],
            blocks: [BLOCK_ID_NULL; NUM_DATA_BLOCKS_IN_FILE],
        }
    }
}

impl FileBlock {
    pub(crate) const fn capacity() -> usize {
        return NUM_BYTES_INITIAL_CONTENTS + (NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity());
    }

    pub(crate) fn fix_crc(&mut self) {
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

    pub(crate) fn read<T: Storage>(
        &self,
        ironfs: &IronFs<T>,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, ErrorKind> {
        if offset > (NUM_BYTES_INITIAL_CONTENTS + (NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity()))
        {
            return Err(ErrorKind::OutOfBounds);
        }

        let mut pos = 0;
        let end = core::cmp::min(self.size as usize, data.len());

        if offset < NUM_BYTES_INITIAL_CONTENTS {
            // Figure out how much of the data can be written into the initial contents.
            let nbytes = core::cmp::min(end - offset, self.data.len());
            data[..nbytes].copy_from_slice(&self.data[offset..offset + nbytes]);
            pos += nbytes
        }

        while pos < end && (pos + offset) < (NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity()) {
            let idx = (pos + offset - NUM_BYTES_INITIAL_CONTENTS) / DataBlock::capacity();
            let data_block_id = self.blocks[idx];
            let pos_in_block = (pos + offset - NUM_BYTES_INITIAL_CONTENTS) % DataBlock::capacity();
            let num_bytes = core::cmp::min(DataBlock::capacity() - pos_in_block, end - pos);

            if data_block_id == BLOCK_ID_NULL {
                data[pos..pos + num_bytes].fill(0u8);
            } else {
                let data_block = ironfs.read_data_block(&data_block_id)?;
                // TODO verify CRC.
                data_block.read(pos_in_block, &mut data[pos..pos + num_bytes]);
            }

            pos += num_bytes;
        }

        Ok(pos)
    }

    pub(crate) fn write<T: Storage>(
        &mut self,
        ironfs: &mut IronFs<T>,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, ErrorKind> {
        info!("wr file inode offset: {} data len: {}", offset, data.len());
        if offset > (NUM_BYTES_INITIAL_CONTENTS + (NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity()))
        {
            return Err(ErrorKind::OutOfBounds);
        }

        let mut pos = 0;
        let end = data.len();
        if offset < NUM_BYTES_INITIAL_CONTENTS {
            let nbytes = core::cmp::min(end, self.data.len() - offset);
            self.data[offset..offset + nbytes].copy_from_slice(&data[..nbytes]);
            pos += nbytes;
        }

        while pos < end && (pos + offset) < (NUM_DATA_BLOCKS_IN_FILE * DataBlock::capacity()) {
            let idx = (pos + offset - NUM_BYTES_INITIAL_CONTENTS) / DataBlock::capacity();
            let (data_block_id, mut data_block) = if self.blocks[idx] == BLOCK_ID_NULL {
                let id = ironfs.acquire_free_block()?;
                self.blocks[idx] = id;
                (id, DataBlock::default())
            } else {
                let id = self.blocks[idx];
                (id, ironfs.read_data_block(&id)?)
            };
            let pos_in_block = (pos + offset - NUM_BYTES_INITIAL_CONTENTS) % DataBlock::capacity();
            let num_bytes = core::cmp::min(DataBlock::capacity() - pos_in_block, end - pos);
            data_block.write(pos_in_block, &data[pos..pos + num_bytes])?;
            data_block.fix_crc();
            ironfs.write_data_block(&data_block_id, &data_block)?;

            pos += num_bytes;
        }

        self.size = core::cmp::max(self.size as u64, (pos + offset) as u64);

        Ok(pos)
    }

    pub(crate) fn unlink_data<T: Storage>(&self, ironfs: &mut IronFs<T>) -> Result<(), ErrorKind> {
        for id in self.blocks {
            if id != BLOCK_ID_NULL {
                ironfs.release_block(id)?;
            }
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for FileBlock {
    type Error = ErrorKind;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let file_block: Option<LayoutVerified<_, FileBlock>> = LayoutVerified::new(&bytes[..]);
        if let Some(file_block) = file_block {
            if file_block.magic != FILE_INODE_MAGIC {
                return Err(ErrorKind::InconsistentState);
            }

            return Ok((*file_block).clone());
        } else {
            return Err(ErrorKind::InconsistentState);
        }
    }
}

impl FileBlock {
    pub(crate) fn new(timestamp: &Timestamp, name: &[u8], perms: u32) -> Self {
        let timestamp = timestamp.clone();
        let mut file = FileBlock {
            atime: timestamp,
            mtime: timestamp,
            ctime: timestamp,
            perms,
            ..Self::default()
        };
        file.name_len = name.len() as u32;
        file.name[..name.len()].copy_from_slice(name.as_bytes());
        file.fix_crc();
        file
    }

    fn from_timestamp(now: Timestamp) -> Self {
        FileBlock {
            atime: now,
            mtime: now,
            ctime: now,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::storage::{Geometry, LbaId, Storage};
    use crate::tests_util::*;
    use crate::IronFs;

    use proptest::prelude::*;
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]
        #[test]
        fn test_file_block_inline_data(offset in 0usize..NUM_BYTES_INITIAL_CONTENTS) {
            init();
            let txt = rust_counter_strings::generate(NUM_BYTES_INITIAL_CONTENTS - offset);
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(20)));
            let mut block = FileBlock::default();
            block.write(&mut ironfs, offset, &data[..]).unwrap();
            let mut data2 = vec![0u8; NUM_BYTES_INITIAL_CONTENTS];
            block.read(&ironfs, 0, &mut data2[..]).unwrap();
            let empty = vec![0u8; offset];
            prop_assert_eq!(&data2[..offset], &empty[..]);
            prop_assert_eq!(&data2[offset..], &data[..]);
        }

        #[test]
        fn test_file_block_data(offset in 0usize..FileBlock::capacity()) {
            init();
            let txt = rust_counter_strings::generate(FileBlock::capacity());
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
            let mut block = FileBlock::default();
            block.write(&mut ironfs, offset, &data[..]).unwrap();
            let mut data2 = vec![0u8; FileBlock::capacity()];
            block.read(&ironfs, 0, &mut data2[..]).unwrap();
            let empty = vec![0u8; offset];
            prop_assert_eq!(&data2[..offset], &empty[..]);
            for i in offset..FileBlock::capacity() {
                prop_assert_eq!(data2[i], data[i - offset]);
            }
        }
    }
}
