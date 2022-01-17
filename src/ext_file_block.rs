
use crate::storage::Storage;
use crate::IronFs;
use crate::error::ErrorKind;
use crate::data_block::DataBlock;
use crate::util::{BlockMagic, BlockId, BLOCK_ID_NULL, Timestamp, Crc, CRC, CRC_INIT, NAME_NLEN};
use log::{error, info, trace};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

const EXT_FILE_BLOCK_MAGICK: BlockMagic = BlockMagic(*b"EINO");

const EXT_FILE_BLOCK_NUM_BLOCKS: usize = 1020;

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct ExtFileBlock {
    magic: BlockMagic,
    crc: Crc,
    pub(crate) next_inode: BlockId,
    reserved: u32,
    blocks: [BlockId; EXT_FILE_BLOCK_NUM_BLOCKS],
}

impl TryFrom<&[u8]> for ExtFileBlock {
    type Error = ErrorKind;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let block: Option<LayoutVerified<_, ExtFileBlock>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        error!("Failure to create file inode from bytes.");
        return Err(ErrorKind::InconsistentState);
    }
}

impl ExtFileBlock {
    pub(crate) const fn capacity() -> usize {
        EXT_FILE_BLOCK_NUM_BLOCKS * DataBlock::capacity()
    }

    fn fix_crc(&mut self) {
        self.crc = CRC_INIT;
        self.crc = Crc(CRC.checksum(self.as_bytes()));
    }

    pub(crate) fn write<T: Storage>(
        &mut self,
        ironfs: &mut IronFs<T>,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, ErrorKind> {
        assert!(offset < ExtFileBlock::capacity());
        trace!("ext file block write: {} data: {:?}",
            offset, data);

        let mut pos = 0;
        let idx = offset / DataBlock::capacity();
        let mut total_bytes = 0;

        let data_len = core::cmp::min(ExtFileBlock::capacity() - offset, data.len());
        let max_idx = if (data_len % DataBlock::capacity()) == 0 {
            idx + (data_len / DataBlock::capacity())
        } else {
            idx + (data_len / DataBlock::capacity()) + 1
        };

        for i in idx..max_idx {
            let (data_block_id, mut data_block) = if self.blocks[i] == BLOCK_ID_NULL {
                let id = ironfs.acquire_free_block()?;
                self.blocks[i] = id;
                trace!("Acquiring free data block id: {:?} and assigning it to: {}", id, i);
                (id, DataBlock::default())
            } else {
                let id = self.blocks[i];
                (id, ironfs.read_data_block(&id)?)
            };

            let num_bytes =
                data_block.write((pos + offset) % DataBlock::capacity(), &data[pos..])?;
            pos += num_bytes;
            total_bytes += num_bytes;
            data_block.fix_crc();
            trace!("writing data block i: {} (idx: {} of max_idx: {}) id: {:?} with contents: {:?}",
                i, idx, max_idx, data_block_id, data_block);
            ironfs.write_data_block(&data_block_id, &data_block)?;
        }

        Ok(total_bytes)
    }

    pub(crate) fn read<T: Storage>(
        &mut self,
        ironfs: &IronFs<T>,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, ErrorKind> {
        assert!(offset < ExtFileBlock::capacity());
        info!("ext file block read offset: {} data len: {}",
            offset, data.len());

        let mut pos = 0;
        let idx = offset / DataBlock::capacity();
        let mut total_bytes = 0;

        let data_len = core::cmp::min(ExtFileBlock::capacity() - offset, data.len());

        let max_idx = if (data_len % DataBlock::capacity()) == 0 {
            idx + (data_len / DataBlock::capacity())
        } else {
            idx + (data_len / DataBlock::capacity()) + 1
        };
        trace!("read idx: {} and max_idx: {}", idx, max_idx);

        for i in idx..max_idx {
            if self.blocks[i] == BLOCK_ID_NULL {
                trace!("Found NULL block at i: {}", i);
                // No block allocated means that there is a hole in the data likely because someone
                // was writing and seeked forward into the file. 
                // Let's go ahead and populate the data_block with the missing data.
                let num_bytes = DataBlock::capacity() - (offset % DataBlock::capacity());
                trace!("Zeroing data from pos begin: {} to end: {}", pos, pos + num_bytes);
                data[pos..(pos + num_bytes)].fill(0u8);
                pos += num_bytes;
                total_bytes += num_bytes;
            } else {
                let data_block = ironfs.read_data_block(&self.blocks[i])?;
                let num_bytes =
                    data_block.read((pos + offset) % DataBlock::capacity(), &mut data[pos..])?;
                pos += num_bytes;
                total_bytes += num_bytes;
            }
        }

        Ok(total_bytes)
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

impl Default for ExtFileBlock {
    fn default() -> Self {
        ExtFileBlock {
            magic: EXT_FILE_BLOCK_MAGICK,
            crc: CRC_INIT,
            next_inode: BLOCK_ID_NULL,
            reserved: 0,
            blocks: [BLOCK_ID_NULL; EXT_FILE_BLOCK_NUM_BLOCKS],
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::storage::{Geometry, LbaId, Storage};
    use crate::IronFs;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
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
    fn test_ext_file_block_simple() {
        init();
        let limit = 6000;
        let offset = 4089;
        let txt = rust_counter_strings::generate(limit - offset);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
        let mut block = ExtFileBlock::default();
        block.write(&mut ironfs, offset, &data[..]).unwrap();
        let mut data2 = vec![0u8; limit];
        block.read(&ironfs, 0, &mut data2[..]).unwrap();
        let empty = vec![0u8; offset];
        assert_eq!(&data2[..offset], &empty[..]);
        assert_eq!(&data2[offset..], &data[..]);
    }

    #[test]
    fn test_ext_file_block_simple_with_offset() {
        init();
        let limit = 16000;
        let offset = 8193;
        let txt = rust_counter_strings::generate(limit - offset);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
        let mut block = ExtFileBlock::default();
        block.write(&mut ironfs, offset, &data[..]).unwrap();
        let mut data2 = vec![0u8; limit];
        block.read(&ironfs, 4097, &mut data2[4097..]).unwrap();

        let empty = vec![0u8; offset];
        assert_eq!(&data2[..offset], &empty[..]);
        assert_eq!(&data2[offset..], &data[..]);
    }

    use proptest::prelude::*;
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]
        #[test]
        fn test_ext_file_block_basics(offset in 0usize..ExtFileBlock::capacity()) {
            init();
            let txt = rust_counter_strings::generate(ExtFileBlock::capacity() - offset);
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
            let mut block = ExtFileBlock::default();
            block.write(&mut ironfs, offset, &data[..]).unwrap();
            let mut data2 = vec![0u8; ExtFileBlock::capacity()];
            block.read(&ironfs, 0, &mut data2[..]).unwrap();
            let empty = vec![0u8; offset];
            prop_assert_eq!(&data2[..offset], &empty[..]);
            prop_assert_eq!(&data2[offset..], &data[..]);
        }

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

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(23)));
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
