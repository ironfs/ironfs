use fuser::{
    Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    FUSE_ROOT_ID,
};
use ironfs::IronFs;
use log::LevelFilter;
use log::{debug, info, warn};
use std::ffi::OsStr;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Inode = u32;

/*
struct FileAttr {
    inode: Inode,
    open_file_handles: u32,
    size: u32,
    atime: (i64, u32),
    mtime: (i64, u32),
    ctime: (i64, u32),
    perm: u16,
    nlink: u32,
    uid: u32,
    gid: u32,
}

impl From<ironfs::FileAttr> for fuser::FileAttr {
    fn from(attr: FileAttr) -> Self {
        fuser::FileAttr {
            ino: attr.inode as u64,
            size: attr.size as u64,
            blocks: (attr.size as u64 + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: UNIX_EPOCH + Duration::new(attr.atime.0 as u64, attr.atime.1),
            mtime: UNIX_EPOCH + Duration::new(attr.mtime.0 as u64, attr.mtime.1),
            ctime: UNIX_EPOCH + Duration::new(attr.ctime.0 as u64, attr.ctime.1),
            crtime: SystemTime::UNIX_EPOCH,
            kind: fuser::FileType::RegularFile,
            perm: attr.perm,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }
}
*/

struct FuseIronFs(IronFs);

fn ironfs_error_to_libc(err_kind: ironfs::ErrorKind) -> i32 {
    match err_kind {
        ironfs::ErrorKind::NoEntry => libc::ENOENT,
        _ => libc::EIO,
    }
}

impl Filesystem for FuseIronFs {
    fn init(
        &mut self,
        _req: &Request,
        #[allow(unused_variables)] config: &mut KernelConfig,
    ) -> Result<(), c_int> {
        Ok(())
    }

    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        debug!("lookup");
        let dir_id = ironfs::DirectoryId(parent);
        match self.0.dirents(&dir_id) {
            Ok(entries) => {
                if let Some(entry) = entries.get(name.to_str().unwrap_or("")) {
                    /*
                     * TODO
                    let attrs = self.attrs(entry);
                    reply.entry(&Duration::new(0, 0), &attrs.into(), 0);
                    */
                } else {
                    reply.error(libc::ENOENT);
                }
            }
            Err(kind) => {
                    reply.error(libc::ENOENT);
            }
        }
    }

    fn forget(&mut self, _req: &Request, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request, inode: u64, reply: ReplyAttr) {
        debug!("getattr");
        reply.error(libc::ENOSYS);
    }

    fn setattr(
        &mut self,
        req: &Request,
        inode: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        debug!("setattr");
        reply.error(libc::ENOSYS);
    }

    fn readlink(&mut self, _req: &Request, inode: u64, reply: ReplyData) {
        debug!("readlink");
        reply.error(libc::ENOSYS);
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        debug!("mknod() called for {:?}", parent);
        reply.error(libc::ENOSYS);
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        debug!("mkdir() called for {:?}", parent);
        //self.mkdir(parent as u32, name);
        // TODO attrs
        //reply.entry(&Duration::new(0, 0),
        reply.error(libc::ENOSYS);
    }

    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!("unlink");
        reply.error(libc::ENOSYS);
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!("rmmdir");
        reply.error(libc::ENOSYS);
    }

    fn symlink(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        debug!("symlink");
        reply.error(libc::ENOSYS);
    }

    fn rename(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        debug!("rename");
        reply.error(libc::ENOSYS);
    }

    fn link(
        &mut self,
        req: &Request,
        inode: u64,
        new_parent: u64,
        new_name: &OsStr,
        reply: ReplyEntry,
    ) {
        debug!("link");
        reply.error(libc::ENOSYS);
    }

    fn open(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("open() called for {:?}", inode);
        reply.error(libc::ENOSYS);
    }

    fn read(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        debug!("read() called for {:?}", inode);
        reply.error(libc::ENOSYS);
    }

    fn write(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        #[allow(unused_variables)] flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        debug!("write() called for {:?}", inode);
        reply.error(libc::ENOSYS);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        debug!("release");
        reply.error(libc::ENOSYS);
    }

    fn opendir(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("opendir");
        reply.error(libc::ENOSYS);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        inode: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir");
        reply.error(libc::ENOSYS);
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        debug!("releasedir");
        reply.error(libc::ENOSYS);
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        debug!("statfs");
        reply.error(libc::ENOSYS);
    }

    fn setxattr(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        debug!("setxattr");
        reply.error(libc::ENOSYS);
    }

    fn getxattr(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        debug!("getxattr");
        reply.error(libc::ENOSYS);
    }

    fn listxattr(&mut self, _req: &Request<'_>, inode: u64, size: u32, reply: ReplyXattr) {
        debug!("listxattr");
        reply.error(libc::ENOSYS);
    }

    fn removexattr(&mut self, request: &Request<'_>, inode: u64, key: &OsStr, reply: ReplyEmpty) {
        debug!("removexattr");
        reply.error(libc::ENOSYS);
    }

    fn access(&mut self, req: &Request, inode: u64, mask: i32, reply: ReplyEmpty) {
        debug!("access");
        reply.error(libc::ENOSYS);
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        debug!("create");
        reply.error(libc::ENOSYS);
    }

    #[cfg(target_os = "linux")]
    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        debug!("fallocate");
        reply.error(libc::ENOSYS);
    }

    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        src_inode: u64,
        src_fh: u64,
        src_offset: i64,
        dest_inode: u64,
        dest_fh: u64,
        dest_offset: i64,
        size: u64,
        _flags: u32,
        reply: ReplyWrite,
    ) {
        debug!("copy_file_range");
        reply.error(libc::ENOSYS);
    }
}

/*
#[derive(Serialize, Deserialize)]
struct InodeAttributes {
    pub inode: Inode,
    pub open_file_handles: u64, // Ref count of open file handles to this inode
    pub size: u64,
    pub last_accessed: (i64, u32),
    pub last_modified: (i64, u32),
    pub last_metadata_changed: (i64, u32),
    pub kind: FileKind,
    // Permissions and special mode bits
    pub mode: u16,
    pub hardlinks: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl From<InodeAttributes> for fuser::FileAttr {
    fn from(attrs: InodeAttributes) -> Self {
        fuser::FileAttr {
            ino: attrs.inode,
            size: attrs.size,
            blocks: (attrs.size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: system_time_from_time(attrs.last_accessed.0, attrs.last_accessed.1),
            mtime: system_time_from_time(attrs.last_modified.0, attrs.last_modified.1),
            ctime: system_time_from_time(
                attrs.last_metadata_changed.0,
                attrs.last_metadata_changed.1,
            ),
            crtime: SystemTime::UNIX_EPOCH,
            kind: attrs.kind.into(),
            perm: attrs.mode,
            nlink: attrs.hardlinks,
            uid: attrs.uid,
            gid: attrs.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }
}
*/

struct RamStorage(Vec<u8>);

impl RamStorage {
    fn new(nbytes: usize) -> Self {
        RamStorage(Vec::with_capacity(nbytes))
    }
}

const LBA_SIZE: usize = 512;

impl ironfs::Storage for RamStorage {
    fn read(&self, lba: u32, data: &mut [u8]) {
        let start_addr = lba as usize * LBA_SIZE;
        data.clone_from_slice(&self.0[start_addr..start_addr + data.len()]);
    }
    fn write(&mut self, lba: u32, data: &[u8]) {
        let start_addr = lba as usize * LBA_SIZE;
        self.0[start_addr..start_addr + data.len()].copy_from_slice(data);
    }
    fn erase(&mut self, lba: u32, num_lba: u32) {
        let start_addr = lba as usize * LBA_SIZE;
        let end_addr = (lba + num_lba) as usize * LBA_SIZE;
        for i in &mut self.0[start_addr..end_addr] {
            *i = 0xFF;
        }
    }
}

use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
    mount_point: String,
}

fn main() {
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(LevelFilter::Trace)
        .init();

    let opt = Opt::from_args();

    let mut options = vec![MountOption::FSName("fuser".to_string())];

    let storage = RamStorage::new(33554432);
    let ironfs = IronFs::new(storage);
    fuser::mount2(FuseIronFs(ironfs), opt.mount_point, &options).unwrap();
}
