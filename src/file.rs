use crate::{
    ext_file_block::ExtFileBlock, util::BLOCK_ID_NULL, BlockId, ErrorKind, FileBlock, FileId,
    IronFs, Storage, Timestamp,
};
use log::{debug, info, trace};

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
        debug!("Acquired free block for creating file: {:?}", file_block_id);
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

        let mut data_pos = 0;
        let file_block = ironfs.read_file_block(&self.top_inode)?;
        let mut file_pos = offset;
        let file_size = file_block.size as usize;
        info!(
            "Reading file data_pos: {} data_len: {} file_pos: {} file_size: {} capacity: {}",
            data_pos,
            data.len(),
            file_pos,
            file_size,
            FileBlock::capacity(),
        );
        if file_pos < FileBlock::capacity() {
            let nbytes = core::cmp::min(FileBlock::capacity(), data.len());
            // Check if our position is within the first file block or if we are reading out extending file block.
            let nbytes = file_block.read(ironfs, file_pos, &mut data[..nbytes])?;
            data_pos += nbytes;
            file_pos += nbytes;
        }

        if data_pos == data.len() || file_pos == file_size {
            return Ok(data_pos);
        }

        // Navigate forward through the ext file blocks until we find the one we're writing into.
        let end_idx: usize = (file_pos - FileBlock::capacity()) / ExtFileBlock::capacity();
        let mut ext_file_block_inode_id = file_block.next_inode;
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
        while file_pos < file_size && data_pos < data.len() {
            assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);

            let mut pos_in_ext_file =
                file_pos - FileBlock::capacity() - (ext_file_block_idx * ExtFileBlock::capacity());
            trace!(
                "rd pos in ext file: {} file_pos: {} end: {} data_pos: {} data_len: {}",
                pos_in_ext_file,
                file_pos,
                file_size,
                data_pos,
                data.len(),
            );

            let num_bytes = ext_file_block.read(ironfs, pos_in_ext_file, &mut data[data_pos..])?;
            trace!("rd num_bytes: {}", num_bytes);

            data_pos += num_bytes;
            file_pos += num_bytes;
            pos_in_ext_file += num_bytes;
            trace!("rd pos_in_ext_file: {}", pos_in_ext_file);

            if file_pos != file_size {
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

        Ok(data_pos)
    }

    pub(crate) fn write<T: Storage>(
        &mut self,
        ironfs: &mut IronFs<T>,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, ErrorKind> {
        let mut data_pos = 0;
        let mut file_pos = offset;

        let mut file_block = ironfs.read_file_block(&self.top_inode)?;
        let file_size = file_block.size as usize;

        debug!(
            "wr file_pos: {} file_block::capacity: {} ext_file_block::capacity: {} file_size: {} data len: {} top_inode: {}",
            file_pos,
            FileBlock::capacity(),
            ExtFileBlock::capacity(),
            file_size,
            data.len(),
            self.top_inode.0
        );

        // We assume the top-level file block has already been created via ::open() or ::create().

        if file_pos < FileBlock::capacity() {
            let nbytes = core::cmp::min(data.len(), FileBlock::capacity() - file_pos);
            let written_bytes = file_block.write(ironfs, offset, &data)?;
            trace!(
                "Wrote file data into file block file_pos: {} nbytes: {} written_bytes: {}",
                file_pos,
                nbytes,
                written_bytes
            );
            assert_eq!(written_bytes, nbytes);
            file_pos += written_bytes;
            data_pos += written_bytes;
        }

        if data_pos == data.len() {
            return Ok(data_pos);
        }

        assert!(file_pos >= FileBlock::capacity());

        // We need to write additional data into extended file blocks.

        // Navigate through existing ext file inode blocks loading each successive id until we
        // reach the place where we intend to read data.
        let end_idx: usize = (file_pos - FileBlock::capacity()) / ExtFileBlock::capacity();
        let mut ext_file_block_inode_id = file_block.next_inode;
        let mut ext_file_block = if file_block.next_inode == BLOCK_ID_NULL {
            ext_file_block_inode_id = ironfs.acquire_free_block()?;
            debug!(
                "Acquired free block for ext file block: {:?}",
                ext_file_block_inode_id
            );
            file_block.next_inode = ext_file_block_inode_id;
            ironfs.write_file_block(&self.top_inode, &file_block)?;
            trace!("Created new ext block: {:?}", ext_file_block_inode_id);
            ExtFileBlock::default()
        } else {
            trace!("Read existing ext block: {:?}", ext_file_block_inode_id);
            ironfs.read_ext_file_block(&ext_file_block_inode_id)?
        };
        for i in 0..end_idx {
            trace!("Navigating forward through ext file block: {}", i);
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
                debug!(
                    "Acquired free block for new ext file block: {:?}",
                    new_ext_file_block_inode_id
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
        let mut ext_file_block_idx = end_idx;

        while data_pos < data.len() {
            assert_ne!(ext_file_block_inode_id, BLOCK_ID_NULL);

            let mut pos_in_ext_file = (file_pos - FileBlock::capacity()) % ExtFileBlock::capacity();
            trace!(
                "wr data_pos: {} data_len: {} file_pos: {} file_len: {} offset: {} ext_file_block_inode_id: {:?} ext_file_block_idx: {} pos_in_ext_file: {} capacity: {} block_idx: {} block_idx * capacity: {}",
                data_pos,
                data.len(),
                file_pos,
                file_size,
                offset,
                ext_file_block_inode_id,
                ext_file_block_idx,
                pos_in_ext_file,
                FileBlock::capacity(),
                ext_file_block_idx,
                ext_file_block_idx * ExtFileBlock::capacity()
            );

            let num_bytes = ext_file_block.write(ironfs, pos_in_ext_file, &data[data_pos..])?;
            trace!("wr num_bytes: {}", num_bytes);

            file_pos += num_bytes;
            data_pos += num_bytes;
            pos_in_ext_file += num_bytes;
            trace!("wr pos_in_ext_file: {}", pos_in_ext_file);

            if pos_in_ext_file < ExtFileBlock::capacity() {
                ironfs.write_ext_file_block(&ext_file_block_inode_id, &ext_file_block)?;
            } else {
                debug!("We've reached end of ext file block and need to carve a new block.");
                trace!("wr read block id: {:x?}", ext_file_block_inode_id);
                if ext_file_block.next_inode == BLOCK_ID_NULL {
                    let new_ext_file_block_inode_id = ironfs.acquire_free_block()?;
                    debug!(
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

        if (file_block.size as usize) < file_pos {
            file_block.size = file_pos as u64;
            ironfs.write_file_block(&self.top_inode, &file_block)?;
        }

        Ok(data_pos)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::tests_util::*;
    use log::info;
    use proptest::strategy::W;

    #[test]
    fn test_small_write_across_file_block_boundary() {
        init();

        const CHUNK_SIZE: usize = 4;
        const NUM_BYTES: usize = 8;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file = File::create(&mut ironfs, "big_file", 0, 0, 0).unwrap();
        let starting_pos = FileBlock::capacity() - 2;

        info!("Writing small amount of data in small increments.");
        let mut pos = starting_pos;
        for chunk in data.chunks(CHUNK_SIZE) {
            file.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += CHUNK_SIZE;
        }

        info!("Read back data we didn't write.");
        let mut zero_buf = vec![0u8; starting_pos];
        file.read(&ironfs, 0, &mut zero_buf[..]).unwrap();

        info!("Confirm that leading data is zeroed.");
        assert_eq!(zero_buf, vec![0u8; starting_pos]);

        info!("Read out data we did write");
        let mut data2 = vec![0u8; NUM_BYTES];
        file.read(&ironfs, starting_pos, &mut data2).unwrap();

        info!("Confirm that we have valid counter string data");
        assert_eq!(data, data2);
    }

    #[test]
    fn test_write_first_ext_boundary_fail() {
        init();
        const CHUNK_SIZE: usize = 4;
        const NUM_BYTES: usize = 9;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file = File::create(&mut ironfs, "big_file", 0, 0, 0).unwrap();
        let starting_pos = FileBlock::capacity() - 3;

        info!("Writing small amount of data in small increments.");
        let mut pos = starting_pos;
        for chunk in data.chunks(CHUNK_SIZE) {
            file.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += CHUNK_SIZE;
        }

        info!("Read back data we didn't write.");
        let mut data2 = vec![0u8; starting_pos];
        file.read(&ironfs, 0, &mut data2[..]).unwrap();

        info!("Confirm that leading data is zeroed.");
        let zero_buf = vec![0u8; starting_pos];
        let mut prev = None;
        for i in (0..data2.len()).step_by(32) {
            if let Some(prev) = prev {
                info!(
                    "inspecting FileBlock.capacity: {} ExtFileBlock.capacity: {} section: {} to {}",
                    FileBlock::capacity(),
                    ExtFileBlock::capacity(),
                    prev,
                    i
                );
                assert_eq!(&data2[prev..i], &zero_buf[prev..i]);
            }
            prev = Some(i);
        }

        info!("Read out data we did write");
        let mut data2 = vec![0u8; NUM_BYTES];
        file.read(&ironfs, starting_pos, &mut data2).unwrap();

        info!("Confirm that we have valid counter string data");
        assert_eq!(data, data2);
    }

    #[test]
    fn test_write_ext_boundary_fail() {
        init();
        const CHUNK_SIZE: usize = 4;
        const NUM_BYTES: usize = 8;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file = File::create(&mut ironfs, "big_file", 0, 0, 0).unwrap();
        let starting_pos = FileBlock::capacity() + ExtFileBlock::capacity() - 2;

        info!("Writing small amount of data in small increments.");
        let mut pos = starting_pos;
        for chunk in data.chunks(CHUNK_SIZE) {
            file.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += CHUNK_SIZE;
        }

        info!("Read back data we didn't write.");
        let mut data2 = vec![0u8; starting_pos];
        file.read(&ironfs, 0, &mut data2[..]).unwrap();

        let zero_buf = vec![0u8; starting_pos];
        info!("Check for issue where we accidentally wrote to start of previous ext file block {} to {}",
    FileBlock::capacity(), FileBlock::capacity() + 32);
        assert_eq!(
            &data2[FileBlock::capacity()..FileBlock::capacity() + 32],
            &zero_buf[..32]
        );

        info!("Confirm that leading data is zeroed.");
        let mut prev = None;
        for i in (0..data2.len()).step_by(32) {
            if let Some(prev) = prev {
                info!(
                    "inspecting FileBlock.capacity: {} ExtFileBlock.capacity: {} section: {} to {}",
                    FileBlock::capacity(),
                    ExtFileBlock::capacity(),
                    prev,
                    i
                );
                assert_eq!(&data2[prev..i], &zero_buf[prev..i]);
            }
            prev = Some(i);
        }

        info!("Read out data we did write");
        let mut data2 = vec![0u8; NUM_BYTES];
        file.read(&ironfs, starting_pos, &mut data2).unwrap();

        info!("Confirm that we have valid counter string data");
        assert_eq!(data, data2);
    }

    /// Test the condition where we cross a portion of an internal boundary and have a failure to
    /// properly write.
    #[test]
    fn test_write_internal_boundary_fail() {
        init();
        const CHUNK_SIZE: usize = 8112;
        const NUM_BYTES: usize = 10_000;
        let txt = rust_counter_strings::generate(NUM_BYTES);
        let data = txt.as_bytes();

        let mut ironfs = make_filesystem(RamStorage::new(2_usize.pow(26)));
        let mut file = File::create(&mut ironfs, "big_file", 0, 0, 0).unwrap();
        let starting_pos = FileBlock::capacity();
        info!("Starting pos is: {}", starting_pos);
        let mut pos = starting_pos;
        for chunk in data.chunks(CHUNK_SIZE) {
            file.write(&mut ironfs, pos, &chunk[..]).unwrap();
            pos += CHUNK_SIZE;
        }

        // Confirm that we have all zeroed data leading up to starting position.
        info!("Confirm that leading data is zeroed.");
        let mut zero_buf = vec![0u8; starting_pos];
        file.read(&ironfs, 0, &mut zero_buf[..]).unwrap();
        assert_eq!(zero_buf, vec![0u8; starting_pos]);

        info!("Read out file data.");
        let mut data2 = vec![0u8; NUM_BYTES];
        file.read(&ironfs, starting_pos, &mut data2).unwrap();

        info!("Confirm that we have valid counter string data");
        let mut prev = None;
        for i in (0..data.len()).step_by(32) {
            if let Some(prev) = prev {
                info!("inspecting section: {} to {}", prev, i);
                let orig = String::from_utf8_lossy(&data[prev..i]);
                let new = String::from_utf8_lossy(&data2[prev..i]);
                assert_eq!(orig, new);
            }

            prev = Some(i);
        }
    }
}
