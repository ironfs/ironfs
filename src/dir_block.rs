use crate::error::ErrorKind;
use crate::util::{
    BlockId, BlockMagic, Crc, Timestamp, BLOCK_ID_NULL, CRC, CRC_INIT, DIR_ID_NULL, NAME_NLEN,
};
use crate::DirectoryId;
use log::error;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

pub(crate) const DIR_BLOCK_NUM_ENTRIES: usize = 940;

pub(crate) const DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DIRB");

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct DirBlock {
    pub(crate) magic: BlockMagic,
    pub(crate) crc: Crc,
    pub(crate) next_dir_block: DirectoryId,
    pub(crate) name_len: u32,
    pub(crate) name: [u8; NAME_NLEN],
    pub(crate) atime: Timestamp,
    pub(crate) mtime: Timestamp,
    pub(crate) ctime: Timestamp,
    pub(crate) reserved1: u64,
    pub(crate) owner: u16,
    pub(crate) group: u16,
    pub(crate) perms: u32,
    pub(crate) entries: [BlockId; DIR_BLOCK_NUM_ENTRIES],
}

impl TryFrom<&[u8]> for DirBlock {
    type Error = ErrorKind;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let block: Option<LayoutVerified<_, DirBlock>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        error!("Failure to create dirblock from bytes.");
        Err(ErrorKind::InconsistentState)
    }
}

impl DirBlock {
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
}

impl DirBlock {
    pub(crate) fn from_timestamp(now: Timestamp) -> Self {
        // Todo record current time.
        DirBlock {
            magic: DIR_BLOCK_MAGIC,
            crc: CRC_INIT,
            next_dir_block: DIR_ID_NULL,
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

    /// Return true if any empty slot exists in this directory entries.
    pub(crate) fn has_empty_slot(&self) -> bool {
        self.entries.iter().any(|x| *x == BLOCK_ID_NULL)
    }

    /// Add an entry to the directory block.
    pub(crate) fn add_entry(&mut self, entry_block_id: BlockId) -> Result<(), ErrorKind> {
        if let Some(v) = self.entries.iter_mut().find(|v| **v == BLOCK_ID_NULL) {
            *v = BlockId(entry_block_id.0);
            Ok(())
        } else {
            Err(ErrorKind::NoEntry)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn valid_dir_block_size() {
        assert_eq!(core::mem::size_of::<DirBlock>(), crate::BLOCK_SIZE);
    }
}
