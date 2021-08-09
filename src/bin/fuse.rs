use fuser::{
    Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    FUSE_ROOT_ID,
};
use ironfs::IronFs;
use log::LevelFilter;
use log::{debug, info, trace, warn};
use std::ffi::OsStr;
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct FileAttr(ironfs::Attrs);

const BLOCK_SIZE: u64 = 4096;

fn current_timestamp() -> ironfs::Timestamp {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    ironfs::Timestamp {
        secs: since_the_epoch.as_secs() as i64,
        nsecs: since_the_epoch.subsec_nanos() as u64,
    }
}

impl From<FileAttr> for fuser::FileAttr {
    fn from(attr: FileAttr) -> Self {
        let attr = attr.0;
        let kind = match attr.kind {
            ironfs::AttrKind::File => fuser::FileType::RegularFile,
            ironfs::AttrKind::Directory => fuser::FileType::Directory,
        };
        fuser::FileAttr {
            ino: attr.block_id.0 as u64,
            size: attr.size as u64,
            blocks: (attr.size as u64 + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: UNIX_EPOCH + Duration::new(attr.atime.secs as u64, attr.atime.nsecs as u32),
            mtime: UNIX_EPOCH + Duration::new(attr.mtime.secs as u64, attr.mtime.nsecs as u32),
            ctime: UNIX_EPOCH + Duration::new(attr.ctime.secs as u64, attr.ctime.nsecs as u32),
            crtime: SystemTime::UNIX_EPOCH,
            kind: kind,
            perm: attr.perms,
            nlink: 2,
            uid: attr.owner as u32,
            gid: attr.group as u32,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }
}

struct FuseIronFs(IronFs<RamStorage>);

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
        debug!("lookup parent: {}", parent);
        let dir_id = ironfs::DirectoryId(parent as u32);
        if let Ok(entry) = self.0.lookup(&dir_id, name.to_str().unwrap()) {
            info!("found entry {:?} for parent {:?}", name.to_str(), parent);
            match self.0.attrs(&entry) {
                Ok(attr) => {
                    reply.entry(&Duration::new(0, 0), &FileAttr(attr).into(), 0);
                }
                Err(e) => {
                    unreachable!();
                    // TODO
                }
            }
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn forget(&mut self, _req: &Request, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request, inode: u64, reply: ReplyAttr) {
        debug!("getattr for inode: {}", inode);
        match self.0.attrs(&ironfs::BlockId(inode as u32)) {
            Ok(attr) => {
                reply.attr(&Duration::new(0, 0), &FileAttr(attr).into());
            }
            Err(_) => {
                reply.error(libc::EIO);
            }
        }
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

        let dir_id = ironfs::DirectoryId(parent as u32);
        // TODO
        self.0
            .mkdir(&dir_id, name.to_str().unwrap(), current_timestamp())
            .unwrap();

        let attr = fuser::FileAttr {
            ino: dir_id.0 as u64,
            size: BLOCK_SIZE,
            blocks: 1,
            atime: UNIX_EPOCH + Duration::new(0, 0),
            mtime: UNIX_EPOCH + Duration::new(0, 0),
            ctime: UNIX_EPOCH + Duration::new(0, 0),
            crtime: SystemTime::UNIX_EPOCH,
            kind: fuser::FileType::Directory,
            perm: 0,
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        };
        reply.entry(&Duration::new(0, 0), &attr, 0);
        //reply.error(libc::ENOSYS);
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
        let directory_listing = self.0.readdir(ironfs::DirectoryId(inode as u32)).unwrap();
        for (index, block_id) in directory_listing.skip(offset as usize).enumerate() {
            let mut name = [0u8; ironfs::NAME_NLEN];
            // TODO fix unwrap() usage.
            self.0.block_name(&block_id, &mut name[..]).unwrap();
            let inode_type = match self.0.block_file_type(&block_id).unwrap() {
                ironfs::AttrKind::File => fuser::FileType::RegularFile,
                ironfs::AttrKind::Directory => fuser::FileType::Directory,
            };

            let buffer_full: bool = reply.add(
                block_id.0 as u64,
                offset + index as i64 + 1,
                inode_type,
                OsStr::from_bytes(&name[..]),
            );
            if buffer_full {
                break;
            }
        }
        reply.ok();
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

struct RamStorage(Vec<u8>);

impl RamStorage {
    fn new(nbytes: usize) -> Self {
        RamStorage(vec![0u8; nbytes])
    }
}

const LBA_SIZE: usize = 512;

impl ironfs::Storage for RamStorage {
    fn read(&self, lba: ironfs::LbaId, data: &mut [u8]) {
        let start_addr = lba.0 * LBA_SIZE;
        data.clone_from_slice(&self.0[start_addr..start_addr + data.len()]);
    }
    fn write(&mut self, lba: ironfs::LbaId, data: &[u8]) {
        let start_addr = lba.0 * LBA_SIZE;
        self.0[start_addr..start_addr + data.len()].copy_from_slice(data);
    }
    fn erase(&mut self, lba: ironfs::LbaId, num_lba: usize) {
        let start_addr = lba.0 * LBA_SIZE;
        let end_addr = (lba.0 + num_lba) * LBA_SIZE;
        for i in &mut self.0[start_addr..end_addr] {
            *i = 0xFF;
        }
    }

    fn geometry(&self) -> ironfs::Geometry {
        ironfs::Geometry {
            lba_size: 512,
            num_blocks: self.0.len() / 512,
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

    let fuse_options = vec![
        MountOption::FSName("fuser".to_string()),
        MountOption::AutoUnmount,
        MountOption::NoDev,
        MountOption::NoAtime,
    ];

    //let storage = RamStorage::new(33554432);
    let mut ironfs = IronFs::from(RamStorage::new(33554432));
    debug!("First bind");
    match ironfs.bind() {
        Err(ironfs::ErrorKind::NotFormatted) => {
            debug!("Formatting.");
            ironfs
                .format(current_timestamp())
                .expect("Failure to format ironfs.");
            debug!("Binding.");
            ironfs.bind().expect("Failure to bind after format.");
        }
        _ => {}
    };
    fuser::mount2(FuseIronFs(ironfs), opt.mount_point, &fuse_options).unwrap();
}
