
use log::{debug, error, info, trace, warn};

use crate::error::ErrorKind;
use crate::util::{BlockMagic, Crc, CRC, CRC_INIT};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

const DATA_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DATA");

const DATA_BLOCK_NUM_BYTES: usize = 4088;

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct DataBlock {
    magic: BlockMagic,
    crc: Crc,
    data: [u8; DATA_BLOCK_NUM_BYTES],
}

impl Default for DataBlock {
    fn default() -> Self {
        DataBlock {
            magic: DATA_BLOCK_MAGIC,
            crc: CRC_INIT,
            data: [0u8; 4088],
        }
    }
}

impl DataBlock {
    pub(crate) const fn capacity() -> usize {
        DATA_BLOCK_NUM_BYTES
    }

    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<Self, ErrorKind> {
        let block: Option<LayoutVerified<_, DataBlock>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        error!("Failure to create data block from bytes.");
        return Err(ErrorKind::InconsistentState);
    }

    pub(crate) fn fix_crc(&mut self) {
        self.crc = CRC_INIT;
        self.crc = Crc(CRC.checksum(self.as_bytes()));
    }

    pub(crate) fn read(&self, offset: usize, data: &mut [u8]) -> Result<usize, ErrorKind> {
        let num_bytes = core::cmp::min(DATA_BLOCK_NUM_BYTES - offset, data.len());
        data[..num_bytes].copy_from_slice(&self.data[offset..offset + num_bytes]);
        Ok(num_bytes)
    }

    pub(crate) fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize, ErrorKind> {
        let num_bytes = core::cmp::min(DATA_BLOCK_NUM_BYTES - offset, data.len());
        self.data[offset..offset + num_bytes].copy_from_slice(&data[..num_bytes]);
        self.fix_crc();
        Ok(num_bytes)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn valid_data_block_size() {
        assert_eq!(core::mem::size_of::<DataBlock>(), crate::BLOCK_SIZE);
    }

    #[test]
    fn test_data_block_read() {
        let mut data_block = DataBlock::default();
        let txt = rust_counter_strings::generate(DataBlock::capacity());
        let data = txt.as_bytes();
        data_block.write(0, &data[..]).unwrap();

        let mut data2 = [0u8; DataBlock::capacity()];
        data_block.read(0, &mut data2).unwrap();

        for i in 0..data.len() {
            assert_eq!(data[i], data2[i]);
        }
    }

    #[test]
    fn test_data_block_write_all_offset() {
        let txt = rust_counter_strings::generate(DataBlock::capacity());
        let data = txt.as_bytes();
        for i in 0..data.len() {
            let mut data_block = DataBlock::default();
            data_block.write(i, &data[..]).unwrap();
            let mut data2 = vec![0u8; DataBlock::capacity()];
            data_block.read(0, &mut data2[..]).unwrap();
            for j in 0..i {
                assert_eq!(data2[j], 0u8);
            }
            for j in i..DataBlock::capacity() {
                assert_eq!(data2[j], data[j - i]);
            }
        }
    }

    #[test]
    fn test_data_block_write() {
        let mut data_block = DataBlock::default();
        let txt = rust_counter_strings::generate(DataBlock::capacity());
        let data = txt.as_bytes();
        data_block.write(0, &data[..]).unwrap();
        // Now confirm all of the written data blocks have proper contents.
        for i in 0..data.len() {
            assert_eq!(data_block.data[i], data[i]);
        }
    }
}
