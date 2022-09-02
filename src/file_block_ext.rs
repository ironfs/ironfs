use crate::data_block::DataBlock;
use crate::error::ErrorKind;
use crate::storage::Storage;
use crate::util::{BlockId, BlockMagic, Crc, BLOCK_ID_NULL, CRC, CRC_INIT, FILE_ID_NULL};
use crate::FileId;
use crate::IronFs;
use log::{debug, error, trace};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

pub(crate) const FILE_BLOCK_EXT_MAGIC: BlockMagic = BlockMagic(*b"EFLE");

const FILE_BLOCK_EXT_NUM_BLOCKS: usize = 1020;

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct FileBlockExt {
    magic: BlockMagic,
    crc: Crc,
    pub(crate) next_block_id: FileId,
    reserved: u32,
    blocks: [BlockId; FILE_BLOCK_EXT_NUM_BLOCKS],
}

impl TryFrom<&[u8]> for FileBlockExt {
    type Error = ErrorKind;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let block: Option<LayoutVerified<_, FileBlockExt>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        error!("Failure to create file inode from bytes.");
        Err(ErrorKind::InconsistentState)
    }
}

impl FileBlockExt {
    pub(crate) const fn capacity() -> usize {
        FILE_BLOCK_EXT_NUM_BLOCKS * DataBlock::capacity()
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
        assert!(offset < FileBlockExt::capacity());
        trace!("ext file block write: {} data.len: {}", offset, data.len());

        let mut data_pos = 0;
        let mut ext_file_pos = offset % FileBlockExt::capacity();

        while data_pos < data.len() && ext_file_pos < FileBlockExt::capacity() {
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
        assert!(offset < FileBlockExt::capacity());
        trace!("ext file block read: {} data.len: {}", offset, data.len());

        let mut ext_file_pos = offset % FileBlockExt::capacity();
        let mut data_pos = 0;
        debug!(
            "Reading data from ext file block starting at ext file pos: {} with data_pos: {}",
            ext_file_pos, data_pos
        );

        while data_pos < data.len() && ext_file_pos < FileBlockExt::capacity() {
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

impl Default for FileBlockExt {
    fn default() -> Self {
        FileBlockExt {
            magic: FILE_BLOCK_EXT_MAGIC,
            crc: CRC_INIT,
            next_block_id: FILE_ID_NULL,
            reserved: 0,
            blocks: [BLOCK_ID_NULL; FILE_BLOCK_EXT_NUM_BLOCKS],
        }
    }
}

#[cfg(test)]
mod tests {

    use log::info;

    use super::*;
    use crate::tests_util::*;

    #[test]
    fn test_file_block_ext_read() {
        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(29)));
        let mut file_block_ext = FileBlockExt::default();

        let txt = rust_counter_strings::generate(FileBlockExt::capacity());
        let data = txt.as_bytes();
        assert_eq!(data.len(), FileBlockExt::capacity());
        file_block_ext.write(&mut ironfs, 0, &data[..]).unwrap();

        let mut data2 = vec![0u8; FileBlockExt::capacity()];
        file_block_ext.read(&mut ironfs, 0, &mut data2[..]).unwrap();
        for i in 0..FileBlockExt::capacity() {
            assert_eq!(data[i], data2[i]);
        }
    }

    #[test]
    fn test_file_block_ext_write() {
        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(29)));
        let mut file_block_ext = FileBlockExt::default();
        let data: Vec<usize> = (0..FileBlockExt::capacity()).collect();
        let data: Vec<u8> = data.iter().map(|x| *x as u8).collect();
        assert_eq!(data.len(), FileBlockExt::capacity());
        file_block_ext.write(&mut ironfs, 0, &data[..]).unwrap();
        // Now confirm all of the written data blocks have proper contents.
    }

    #[test]
    fn test_file_block_ext_simple() {
        init();
        let limit = 6000;
        let offset = 4089;
        let txt = rust_counter_strings::generate(limit - offset);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
        let mut block = FileBlockExt::default();
        block.write(&mut ironfs, offset, &data[..]).unwrap();
        let mut data2 = vec![0u8; limit];
        block.read(&ironfs, 0, &mut data2[..]).unwrap();
        let empty = vec![0u8; offset];
        assert_eq!(&data2[..offset], &empty[..]);
        assert_eq!(&data2[offset..], &data[..]);
    }

    #[test]
    fn test_file_block_ext_simple_with_offset() {
        init();
        let limit = 16000;
        let offset = 8193;
        let txt = rust_counter_strings::generate(limit - offset);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
        let mut block = FileBlockExt::default();
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
        fn test_file_block_ext_basics(offset in 0usize..FileBlockExt::capacity()) {
            init();
            let txt = rust_counter_strings::generate(FileBlockExt::capacity() - offset);
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
            let mut block = FileBlockExt::default();
            block.write(&mut ironfs, offset, &data[..]).unwrap();
            let mut data2 = vec![0u8; FileBlockExt::capacity()];
            block.read(&ironfs, 0, &mut data2[..]).unwrap();
            let empty = vec![0u8; offset];
            prop_assert_eq!(&data2[..offset], &empty[..]);
            prop_assert_eq!(&data2[offset..], &data[..]);
        }

        #[test]
        fn test_file_block_ext_write_offsets(offset in 0usize..DataBlock::capacity()) {
            let txt = rust_counter_strings::generate(FileBlockExt::capacity());
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(22)));
            let mut block = FileBlockExt::default();
            block.write(&mut ironfs, offset, &data[..]).unwrap();
            let mut data2 = vec![0u8; FileBlockExt::capacity()];
            block.read(&ironfs, 0, &mut data2[..]).unwrap();
            for i in 0..offset {
                prop_assert_eq!(data2[i], 0u8);
            }
            for i in offset..FileBlockExt::capacity() {
                prop_assert_eq!(data2[i], data[i - offset]);
            }
        }

        #[test]
        fn test_file_block_ext_read_offsets(offset in 0usize..DataBlock::capacity()) {
            let txt = rust_counter_strings::generate(FileBlockExt::capacity());
            let data = txt.as_bytes();

            let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(23)));
            let mut block = FileBlockExt::default();
            block.write(&mut ironfs, 0, &data[..]).unwrap();
            let mut data2 = vec![0u8; FileBlockExt::capacity()];
            block.read(&ironfs, offset, &mut data2[..]).unwrap();
            for i in 0..(FileBlockExt::capacity() - offset) {
                prop_assert_eq!(data2[i], data[i + offset]);
            }
            for i in (FileBlockExt::capacity() - offset)..FileBlockExt::capacity() {
                prop_assert_eq!(data2[i], 0u8);
            }
        }
    }
}
