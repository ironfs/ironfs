use crate::{
    ext_file_block::ExtFileBlock, util::BLOCK_ID_NULL, BlockId, ErrorKind, FileBlock, FileId,
    IronFs, Storage, Timestamp,
};
use log::{info, trace};

pub(crate) struct File {
    top_inode: FileId,
}

impl File {
    pub(crate) fn from_inode(top_inode: FileId) -> Self {
        File { top_inode }
    }
}

impl File {
    pub(crate) fn create_from_timestamp<T: Storage>(
        _ironfs: &mut IronFs<T>,
        _now: Timestamp,
    ) -> Result<Self, ErrorKind> {
        let _inode = FileBlock::default();
        unimplemented!();
    }

    pub fn create<T: Storage>(
        ironfs: &mut IronFs<T>,
        name: &str,
        perms: u32,
        _owner: u16,
        _group: u16,
    ) -> Result<Self, ErrorKind> {
        let file_block_id = ironfs.acquire_free_block()?;
        let file_block_id = FileId(file_block_id.0);
        let file_block = FileBlock::new(&ironfs.cur_timestamp(), name.as_bytes(), perms);
        ironfs.write_file_block(&file_block_id, &file_block)?;
        Ok(File {
            top_inode: file_block_id,
        })
    }

    /// Open a file.
    /// TODO make this accept Path as parameter.
    pub fn open<T: Storage>(_ironfs: &mut IronFs<T>, _path: &str) -> Result<Self, ErrorKind> {
        let _inode = FileBlock::default();
        unimplemented!();
    }

    pub(crate) fn unlink<T: Storage>(&self, ironfs: &mut IronFs<T>) -> Result<(), ErrorKind> {
        let file_block = ironfs.read_file_block(&self.top_inode)?;
        file_block.unlink_data(ironfs)?;

        // Now release all ext file blocks and data blocks associated with the file.
        let mut ext_file_id: BlockId = file_block.next_inode.into();
        ironfs.release_block(self.top_inode.into())?;
        while ext_file_id != BLOCK_ID_NULL {
            let ext_file_block = ironfs.read_ext_file_block(&ext_file_id.into())?;
            ext_file_block.unlink_data(ironfs)?;
            let orig_ext_file_id = ext_file_id;
            ext_file_id = ext_file_block.next_inode;
            ironfs.release_block(orig_ext_file_id)?;
        }

        Ok(())
    }

    pub(crate) fn read<T: Storage>(
        &mut self,
        ironfs: &IronFs<T>,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, ErrorKind> {
        info!("file rd offset: {} data len: {}", offset, data.len());

        let mut pos = 0;
        let inode = ironfs.read_file_block(&self.top_inode)?;
        let end = core::cmp::min(inode.size as usize, data.len());
        if offset < FileBlock::capacity() {
            pos += inode.read(ironfs, offset, &mut data[..FileBlock::capacity()])?;
        }

        if pos == end {
            return Ok(pos);
        }

        assert!((pos + offset) >= FileBlock::capacity());

        // Navigate through existing ext file inode blocks loading each successive id until we
        // reach the place where we intend to read data.
        let end_idx: usize = (pos + offset - FileBlock::capacity()) / ExtFileBlock::capacity();
        let mut ext_file_block_inode_id = inode.next_inode;
        let mut ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
        for i in 0..end_idx {
            // Iterate through the ext file inode to find the one at our expected index.
            ext_file_block_inode_id = ext_file_block.next_inode;
            assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);
            trace!(
                "rd read block idx: {} id: 0x{:x}",
                i,
                ext_file_block_inode_id.0
            );
            ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
        }
        let mut ext_file_block_idx = end_idx;

        // We're now reading data from the extended file inode area.
        while pos < end {
            assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);

            let mut pos_in_ext_file = pos + offset
                - FileBlock::capacity()
                - (ext_file_block_idx * ExtFileBlock::capacity());
            trace!(
                "rd pos in ext file: {} pos: {} end: {}",
                pos_in_ext_file,
                pos,
                end
            );

            let num_bytes = ext_file_block.read(ironfs, pos_in_ext_file, &mut data[pos..])?;
            trace!("rd num_bytes: {}", num_bytes);

            pos += num_bytes;
            pos_in_ext_file += num_bytes;
            trace!("rd pos_in_ext_file: {}", pos_in_ext_file);

            if pos != end {
                ext_file_block_inode_id = ext_file_block.next_inode;
                trace!("rd read block id: {:?}", ext_file_block_inode_id);
                assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);

                ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
                ext_file_block_idx += 1;
                trace!(
                    "rd nxt inode: {} ext_file_block_idx: {}",
                    ext_file_block_inode_id.0,
                    ext_file_block_idx
                );
            }
        }

        Ok(pos)
    }

    pub(crate) fn write<T: Storage>(
        &mut self,
        ironfs: &mut IronFs<T>,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, ErrorKind> {
        info!(
            "wr file offset: {} data len: {} top_inode: {}",
            offset,
            data.len(),
            self.top_inode.0
        );

        let mut pos = 0;
        let end = data.len();

        let mut file_block = ironfs.read_file_block(&self.top_inode)?;
        // We assume the top-level file block has already been created via ::open() or ::create().

        if offset < FileBlock::capacity() {
            let nbytes = core::cmp::min(end, FileBlock::capacity() - offset);
            let written_bytes = file_block.write(ironfs, offset, &data)?;
            assert_eq!(written_bytes, nbytes);
            pos += written_bytes;
        }

        if pos == end {
            return Ok(pos);
        }

        assert!((pos + offset) >= FileBlock::capacity());

        // We need to write additional data into extended file blocks.

        // Navigate through existing ext file inode blocks loading each successive id until we
        // reach the place where we intend to read data.
        let end_idx: usize = (pos + offset - FileBlock::capacity()) / ExtFileBlock::capacity();
        let mut ext_file_block_inode_id = file_block.next_inode;
        let mut ext_file_block = if file_block.next_inode == BLOCK_ID_NULL {
            ext_file_block_inode_id = ironfs.acquire_free_block()?;
            file_block.next_inode = ext_file_block_inode_id;
            ironfs.write_file_block(&self.top_inode, &file_block)?;
            ExtFileBlock::default()
        } else {
            ironfs.read_ext_file_block(&ext_file_block_inode_id)?
        };
        for i in 0..end_idx {
            // Iterate through the ext file inode to find the one at our expected index.
            ext_file_block_inode_id = ext_file_block.next_inode;
            // Its possible that user is trying to write data into file offset far past the place
            // where existing data lives. We need to create new ext_file_block for this case.
            trace!(
                "rd read block idx: {} id: 0x{:x}",
                i,
                ext_file_block_inode_id.0
            );
            if ext_file_block_inode_id == BLOCK_ID_NULL {
                let new_ext_file_block_inode_id = ironfs.acquire_free_block()?;
                let new_ext_file_block = ExtFileBlock::default();
                ext_file_block.next_inode = new_ext_file_block_inode_id;
                ironfs.write_ext_file_block(&ext_file_block_inode_id, &ext_file_block)?;
                ext_file_block_inode_id = new_ext_file_block_inode_id;
                ext_file_block = new_ext_file_block;
            } else {
                ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
            }
        }
        let mut ext_file_block_idx = end_idx;

        while pos < end {
            assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);
            trace!(
                "wr pos: {} offset: {} capacity: {} block_idx: {} block_idx * capacity: {}",
                pos,
                offset,
                FileBlock::capacity(),
                ext_file_block_idx,
                ext_file_block_idx * ExtFileBlock::capacity()
            );

            let mut pos_in_ext_file =
                (pos + offset - FileBlock::capacity()) % ExtFileBlock::capacity();
            trace!(
                "wr pos in ext file: {} pos: {} end: {}",
                pos_in_ext_file,
                pos,
                end
            );

            let num_bytes = ext_file_block.write(ironfs, pos_in_ext_file, &data[pos..])?;
            trace!("wr num_bytes: {}", num_bytes);

            pos += num_bytes;
            pos_in_ext_file += num_bytes;
            trace!("wr pos_in_ext_file: {}", pos_in_ext_file);

            if pos == end {
                ironfs.write_ext_file_block(&ext_file_block_inode_id, &ext_file_block)?;
            } else {
                trace!("wr read block id: {:x?}", ext_file_block_inode_id);
                if ext_file_block.next_inode == BLOCK_ID_NULL {
                    let new_ext_file_block_inode_id = ironfs.acquire_free_block()?;
                    trace!(
                        "Acquired new ext file block inode id: {:x}",
                        new_ext_file_block_inode_id.0
                    );
                    let new_ext_file_block = ExtFileBlock::default();
                    ext_file_block.next_inode = new_ext_file_block_inode_id;
                    ironfs.write_ext_file_block(&ext_file_block_inode_id, &ext_file_block)?;
                    ext_file_block_inode_id = new_ext_file_block_inode_id;
                    ext_file_block = new_ext_file_block;
                } else {
                    ext_file_block = ironfs.read_ext_file_block(&ext_file_block_inode_id)?;
                }
            }

            ext_file_block_idx += 1;
        }

        if file_block.size < (pos + offset) as u64 {
            file_block.size = (pos + offset) as u64;
            ironfs.write_file_block(&self.top_inode, &file_block)?;
        }

        Ok(pos)
    }
}
