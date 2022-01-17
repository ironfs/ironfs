
pub struct LbaId(pub usize);

pub struct Geometry {
    pub lba_size: usize,
    pub num_blocks: usize,
}

pub trait Storage {
    fn read(&self, lba: LbaId, data: &mut [u8]);
    fn write(&mut self, lba: LbaId, data: &[u8]);
    fn erase(&mut self, lba: LbaId, num_lba: usize);
    fn geometry(&self) -> Geometry;
}
