
use crate::storage::Storage;
use crate::IronFs;
use crate::error::ErrorKind;
use crate::data_block::DataBlock;
use crate::util::{BlockMagic, BlockId, BLOCK_ID_NULL, Timestamp, Crc, CRC, CRC_INIT, NAME_NLEN};
use log::{error, info};
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
            if self.blocks[idx] == BLOCK_ID_NULL {
                // This should not happen; ever.
                error!("Block idx: {} was NULL", idx);
                return Err(ErrorKind::InconsistentState);
            }

            if self.blocks[i] == BLOCK_ID_NULL {
                break;
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
