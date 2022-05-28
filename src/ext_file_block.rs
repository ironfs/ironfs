use crate::data_block::DataBlock;
use crate::error::ErrorKind;
use crate::storage::Storage;
use crate::util::{BlockId, BlockMagic, Crc, BLOCK_ID_NULL, CRC, CRC_INIT};
use crate::IronFs;
use log::{debug, error, info, trace};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

pub(crate) const EXT_FILE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EINO");

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
        trace!("ext file block write: {} data.len: {}", offset, data.len());

        let mut data_pos = 0;
        let mut ext_file_pos = offset % ExtFileBlock::capacity();

        while data_pos < data.len() && ext_file_pos < ExtFileBlock::capacity() {
            let data_block_idx = ext_file_pos / DataBlock::capacity();

            let (data_block_id, mut data_block) = if self.blocks[data_block_idx] == BLOCK_ID_NULL {
                let id = ironfs.acquire_free_block()?;
                trace!(
                    "Ext file block acquired free block for data block: {:?}",
                    id
                );
                self.blocks[data_block_idx] = id;
                (id, DataBlock::default())
            } else {
                let id = self.blocks[data_block_idx];
                (id, ironfs.read_data_block(&id)?)
            };
            let pos_in_block = ext_file_pos % DataBlock::capacity();
            let num_bytes =
                core::cmp::min(DataBlock::capacity() - pos_in_block, data.len() - data_pos);
            debug!("Ext Write data from block: {:?} with idx: {} pos_in_block: {} num_bytes: {} file_pos: {} data_pos: {} data.len: {}",
        data_block_id, data_block_idx, pos_in_block, num_bytes, ext_file_pos, data_pos, data.len());
            data_block.write(pos_in_block, &data[data_pos..data_pos + num_bytes])?;
            data_block.fix_crc();
            ironfs.write_data_block(&data_block_id, &data_block)?;

            data_pos += num_bytes;
            ext_file_pos += num_bytes;
        }

        Ok(data_pos)
    }

    pub(crate) fn read<T: Storage>(
        &mut self,
        ironfs: &IronFs<T>,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, ErrorKind> {
        assert!(offset < ExtFileBlock::capacity());
        trace!("ext file block read: {} data.len: {}", offset, data.len());

        let mut ext_file_pos = offset % ExtFileBlock::capacity();
        let mut data_pos = 0;
        debug!(
            "Reading data from ext file block starting at ext file pos: {} with data_pos: {}",
            ext_file_pos, data_pos
        );

        while data_pos < data.len() && ext_file_pos < ExtFileBlock::capacity() {
            let data_block_idx = ext_file_pos / DataBlock::capacity();
            let data_block_id = self.blocks[data_block_idx];
            let pos_in_block = ext_file_pos % DataBlock::capacity();

            let num_bytes =
                core::cmp::min(DataBlock::capacity() - pos_in_block, data.len() - data_pos);

            debug!("Ext Read data from block: {:x?} with idx: {} pos_in_block: {} num_bytes: {} file_pos: {} data_pos: {} data.len: {}",
        data_block_id, data_block_idx, pos_in_block, num_bytes, ext_file_pos, data_pos, data.len());

            if data_block_id == BLOCK_ID_NULL {
                data[data_pos..data_pos + num_bytes].fill(0u8);
                trace!(
                    "Filling data with zero from {} to {}",
                    data_pos,
                    data_pos + num_bytes
                );
            } else {
                // TODO verify CRC.
                ironfs
                    .read_data_block(&data_block_id)?
                    .read(pos_in_block, &mut data[data_pos..data_pos + num_bytes])?;
                trace!(
                    "Read data block starting at: {} to {} with data pos from {} to {}",
                    pos_in_block,
                    pos_in_block + num_bytes,
                    data_pos,
                    data_pos + num_bytes
                );
            }

            data_pos += num_bytes;
            ext_file_pos += num_bytes;
        }

        Ok(data_pos)
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
            magic: EXT_FILE_BLOCK_MAGIC,
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
    use crate::tests_util::*;

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
        info!("Checking if data up to offset is empty.");
        assert_eq!(&data2[..offset], &empty[..]);
        info!("Checking if data after offset is correct");
        let mut prev = None;
        for i in (0..data.len()).step_by(32) {
            if let Some(prev) = prev {
                info!("inspecting section: {} to {}", prev, i);
                assert_eq!(&data2[offset + prev..offset + i], &data[prev..i]);
            }
            prev = Some(i);
        }
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
