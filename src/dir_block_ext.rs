use crate::data_block::DataBlock;
use crate::error::ErrorKind;
use crate::storage::Storage;
use crate::util::{BlockId, BlockMagic, Crc, Timestamp, BLOCK_ID_NULL, CRC, CRC_INIT, NAME_NLEN};
use crate::IronFs;
use log::{debug, error, info, trace};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

#[derive(AsBytes, FromBytes)]
#[repr(C)]
pub(crate) struct DirBlockExt {
    pub(crate) magic: BlockMagic,
    pub(crate) crc: Crc,
    pub(crate) next_dir_block: BlockId,
    pub(crate) reserved: u32,
    pub(crate) data: [BlockId; 1020],
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::tests_util::*;

    #[test]
    fn valid_ext_dir_block_size() {
        assert_eq!(core::mem::size_of::<DirBlockExt>(), BLOCK_SIZE);
    }
}
