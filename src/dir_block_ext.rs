use crate::error::ErrorKind;
use crate::util::{BlockId, BlockMagic, Crc, BLOCK_ID_NULL, CRC, CRC_INIT, DIR_ID_NULL};
use crate::DirectoryId;
use log::error;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

pub(crate) const DIR_BLOCK_EXT_NUM_ENTRIES: usize = 1020;

pub(crate) const DIR_BLOCK_EXT_MAGIC: BlockMagic = BlockMagic(*b"EDIR");

#[derive(Debug, AsBytes, FromBytes, Clone)]
#[repr(C)]
pub(crate) struct DirBlockExt {
    pub(crate) magic: BlockMagic,
    pub(crate) crc: Crc,
    pub(crate) next_dir_block: DirectoryId,
    pub(crate) reserved: u32,
    pub(crate) entries: [BlockId; 1020],
}

impl Default for DirBlockExt {
    fn default() -> Self {
        DirBlockExt {
            magic: DIR_BLOCK_EXT_MAGIC,
            crc: CRC_INIT,
            next_dir_block: DIR_ID_NULL,
            reserved: 0,
            entries: [BLOCK_ID_NULL; DIR_BLOCK_EXT_NUM_ENTRIES],
        }
    }
}

impl TryFrom<&[u8]> for DirBlockExt {
    type Error = ErrorKind;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let block: Option<LayoutVerified<_, DirBlockExt>> = LayoutVerified::new(bytes);
        if let Some(block) = block {
            return Ok((*block).clone());
        }

        error!("Failure to create dirblock from bytes.");
        return Err(ErrorKind::InconsistentState);
    }
}

impl DirBlockExt {
    pub(crate) fn fix_crc(&mut self) {
        self.crc = CRC_INIT;
        self.crc = Crc(CRC.checksum(self.as_bytes()));
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
    fn valid_ext_dir_block_size() {
        assert_eq!(core::mem::size_of::<DirBlockExt>(), crate::BLOCK_SIZE);
    }
}
