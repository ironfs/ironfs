#![no_std]

use zerocopy::{AsBytes, FromBytes};

const DATA_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DATA");
const INODE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"INOD");
const EXT_INODE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EINO");
const SUPER_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"SUPR");
const EXT_SUPER_BLOCK_MAGIC: [u8; 12] = *b" BLK IRON FS";
const DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"DIRB");
const EXT_DIR_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"EDIR");
const FREE_BLOCK_MAGIC: BlockMagic = BlockMagic(*b"FREE");

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct BlockMagic([u8; 4]);

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct BlockId(u32);

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct Crc(u32);

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct SuperBlock {
    magic: BlockMagic,
    ext_magic: [u8; 12],
    version: u32,
    root_dir_block: BlockId,
    num_blocks: u32,
    block_size: u32,
    created_on: u32,
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct DirBlock {
    magic: BlockMagic,
    next_dir_block: BlockId,
    name: [u8; 256],
    owner: u16,
    group: u16,
    perms: u16,
    reserved: u16,
    content_blocks: [BlockId; 955],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct ExtDirBlock {
    magic: BlockMagic,
    next_dir_block: BlockId,
    data: [BlockId; 1021],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct DataBlock {
    magic: BlockMagic,
    data: [u8; 4088],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct InodeBlock {
    magic: BlockMagic,
    next_inode: BlockId,
    name: [u8; 256],
    owner: u16,
    group: u16,
    perms: u16,
    reserved: u16,
    data: [u8; 1024],
    blocks: [BlockId; 699],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct ExtInodeBlock {
    magic: BlockMagic,
    next_inode: BlockId,
    blocks: [BlockId; 1021],
    crc: Crc,
}

#[derive(AsBytes, FromBytes)]
#[repr(C)]
struct FreeBlock {
    magic: BlockMagic,
    next_free: BlockId,
    crc: Crc,
}

pub trait Storage {
    fn read(&self, lba: u32, data: &mut [u8]);
    fn write(&mut self, lba: u32, data: &[u8]);
    fn erase(&mut self, lba: u32, num_lba: u32);
}

pub struct IronFs;

impl IronFs {
    pub fn new(storage: impl Storage) -> Self {
        IronFs
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
