//! Descriptor-bound private writes and explicit inheritance of the tool lock.
use anyhow::{Context, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::{AsFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};
use xcsc::fs_safety::EntryName;

#[allow(unsafe_code)] // F_DUPFD_CLOEXEC atomically returns a new owned valid FD.
pub fn inherited(descriptor: i32) -> anyhow::Result<File> {
    ensure!(
        (3..1_048_576).contains(&descriptor),
        "invalid inherited tool lock descriptor"
    );
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 64) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

pub fn tool_lock(root: &Path, descriptor: i32) -> anyhow::Result<File> {
    let lock = inherited(descriptor)?;
    let path = root.join("maintenance/tool.lock");
    crate::contracts::normalized(&path)?;
    let expected = fs::symlink_metadata(path)?;
    let held = lock.metadata()?;
    ensure!(
        held.is_file()
            && held.nlink() == 1
            && held.uid() == 0
            && held.mode() & 0o7777 == 0o600
            && held.dev() == expected.dev()
            && held.ino() == expected.ino(),
        "inherited tool lock differs from administrator-owned named inode"
    );
    rustix::fs::flock(
        lock.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )?;
    Ok(lock)
}

pub fn private_directory(path: &Path) -> anyhow::Result<()> {
    crate::contracts::normalized(path)?;
    if !path.try_exists()? {
        let parent = path.parent().context("private directory has no parent")?;
        if !parent.try_exists()? {
            private_directory(parent)?;
        }
        fs::DirBuilder::new().mode(0o700).create(path)?;
        crate::creation::record(path, &fs::symlink_metadata(path)?)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        File::open(parent)?.sync_all()?;
    }
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir() && info.mode() & 0o7777 == 0o700,
        "private directory mode differs"
    );
    Ok(())
}

pub fn create(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    private_directory(path.parent().context("private file parent missing")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    crate::creation::record(path, &file.metadata()?)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("file parent missing")?)?.sync_all()?;
    Ok(())
}

pub fn assign(path: &Path, uid: u32, gid: u32, directory: bool) -> anyhow::Result<()> {
    crate::contracts::normalized(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_dir() == directory
            && (info.is_file() || info.is_dir())
            && (directory || info.nlink() == 1),
        "assignment resource type differs"
    );
    rustix::fs::fchown(
        &file,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )?;
    file.set_permissions(fs::Permissions::from_mode(if directory {
        0o700
    } else {
        0o600
    }))?;
    file.sync_all()?;
    Ok(())
}

pub fn new_database(path: &Path) -> anyhow::Result<()> {
    private_directory(path.parent().context("database parent missing")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    crate::creation::record(path, &file.metadata()?)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.flush()?;
    file.sync_all()?;
    File::open(path.parent().context("database parent missing")?)?.sync_all()?;
    Ok(())
}

/// Publish service-readable configuration through the shared protected atomic primitive.
pub fn configuration(path: &Path, bytes: &[u8], gid: u32) -> anyhow::Result<()> {
    crate::contracts::normalized(path)?;
    let parent = path.parent().context("configuration parent missing")?;
    let existed = match fs::symlink_metadata(path) {
        Ok(info) => {
            ensure!(
                info.is_file() && info.nlink() == 1,
                "configuration type or links differs"
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !existed && crate::creation::active() {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        crate::creation::record(path, &file.metadata()?)?;
        file.write_all(bytes)?;
        rustix::fs::fchown(
            &file,
            Some(rustix::process::Uid::from_raw(0)),
            Some(rustix::process::Gid::from_raw(gid)),
        )?;
        file.set_permissions(fs::Permissions::from_mode(0o640))?;
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
        return Ok(());
    }
    let directory = xcsc::fs_safety::ConfigurationDirectory::open(parent)?;
    directory.replace(
        &EntryName::new(path.file_name().context("configuration name missing")?)?,
        bytes,
    )?;
    if !existed {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        rustix::fs::fchown(
            &file,
            Some(rustix::process::Uid::from_raw(0)),
            Some(rustix::process::Gid::from_raw(gid)),
        )?;
        file.set_permissions(fs::Permissions::from_mode(0o640))?;
        file.sync_all()?;
    }
    Ok(())
}

/// Keep all declared current runtime locks held. Inherited descriptors retain
/// the same open-file description; products never participate in this protocol.
struct HeldInstance {
    path: std::path::PathBuf,
    file: File,
    directory: bool,
    uid: u32,
    gid: u32,
    mode: u32,
}
pub struct InstanceLocks {
    held: Vec<HeldInstance>,
}
impl InstanceLocks {
    pub fn empty() -> Self {
        Self { held: Vec::new() }
    }
    pub fn verify(&self) -> anyhow::Result<()> {
        for held in &self.held {
            verify_instance(&held.path, &held.file, held.uid, held.gid, held.directory)?;
            ensure!(
                held.file.metadata()?.mode() & 0o7777 == held.mode,
                "held instance permissions changed"
            );
        }
        Ok(())
    }
}
fn verify_instance(
    path: &Path,
    file: &File,
    uid: u32,
    gid: u32,
    directory: bool,
) -> anyhow::Result<()> {
    crate::contracts::normalized(path)?;
    let info = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        (if directory {
            info.is_dir()
        } else {
            info.is_file() && info.nlink() == 1 && info.mode() & 0o7777 == 0o600
        }) && info.uid() == uid
            && info.gid() == gid
            && info.dev() == named.dev()
            && info.ino() == named.ino()
            && !named.file_type().is_symlink(),
        "instance lock type, owner or named inode differs"
    );
    Ok(())
}
pub fn instances(
    context: &crate::contracts::ContextData,
    uid: u32,
    gid: u32,
    arguments: &[String],
    initialize: bool,
) -> anyhow::Result<InstanceLocks> {
    let paths = context
        .contract
        .resources
        .runtime_locks
        .iter()
        .map(|spec| -> anyhow::Result<_> {
            ensure!(
                matches!(spec.kind.as_str(), "file" | "directory"),
                "unknown runtime lock kind"
            );
            let path = context.path(&spec.path)?;
            if spec.kind == "directory" {
                ensure!(
                    context
                        .contract
                        .resources
                        .business_paths
                        .iter()
                        .chain(&context.contract.resources.shared_paths)
                        .any(|root| context.path(root).is_ok_and(|root| root == path)),
                    "directory lock must be an exact declared business root"
                );
            }
            Ok((path, spec.kind == "directory"))
        })
        .collect::<anyhow::Result<std::collections::BTreeMap<_, _>>>()?;
    ensure!(
        !paths.is_empty() && paths.len() == context.contract.resources.runtime_locks.len(),
        "runtime lock declarations repeat or are missing"
    );
    let mut inherited = std::collections::BTreeMap::new();
    for argument in arguments {
        let (path, descriptor) = argument
            .rsplit_once('=')
            .context("instance descriptor mapping must be PATH=FD")?;
        let path = std::path::PathBuf::from(path);
        crate::contracts::normalized(&path)?;
        ensure!(
            paths.contains_key(&path)
                && inherited.insert(path, descriptor.parse::<i32>()?).is_none(),
            "instance descriptor names an extra or repeated path"
        );
    }
    ensure!(
        inherited.is_empty() || inherited.len() == paths.len(),
        "inherited instance descriptors must cover the complete declared set"
    );
    // Inspect every existing identity before creating the first missing lock.
    for (path, directory) in &paths {
        if path.try_exists()? {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                )
                .open(path)?;
            let info = file.metadata()?;
            verify_instance(
                path,
                &file,
                if *directory { info.uid() } else { uid },
                if *directory { info.gid() } else { gid },
                *directory,
            )?;
        } else {
            ensure!(
                initialize && !*directory,
                "declared instance lock is missing"
            );
        }
    }
    let mut locks = Vec::new();
    for (path, directory) in paths {
        let file = if let Some(descriptor) = inherited.get(&path) {
            inherited_file(*descriptor)?
        } else if directory {
            OpenOptions::new()
                .read(true)
                .custom_flags(
                    (rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NONBLOCK)
                        .bits() as i32,
                )
                .open(&path)?
        } else {
            crate::contracts::normalized(&path)?;
            if initialize && !path.try_exists()? {
                let parent = path.parent().context("instance lock parent missing")?;
                crate::contracts::normalized(parent)?;
                if !parent.try_exists()? {
                    ensure!(
                        context
                            .contract
                            .resources
                            .private_directories
                            .iter()
                            .any(|spec| context.path(spec).is_ok_and(
                                |private| parent == private || parent.starts_with(private)
                            )),
                        "uncreated external instance lock parent is not a private directory"
                    );
                    private_directory(parent)?;
                }
                ensure!(
                    fs::symlink_metadata(parent)?.is_dir(),
                    "instance lock parent is not a physical directory"
                );
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                    .open(&path)?;
                crate::creation::record(&path, &file.metadata()?)?;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                rustix::fs::fchown(
                    &file,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(gid)),
                )?;
                file.sync_all()?;
                File::open(path.parent().context("lock parent missing")?)?.sync_all()?;
                file
            } else {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                    )
                    .open(&path)?
            }
        };
        let info = file.metadata()?;
        let owner_uid = if directory { info.uid() } else { uid };
        let owner_gid = if directory { info.gid() } else { gid };
        verify_instance(&path, &file, owner_uid, owner_gid, directory)?;
        rustix::fs::flock(
            file.as_fd(),
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )?;
        locks.push(HeldInstance {
            path,
            file,
            directory,
            uid: owner_uid,
            gid: owner_gid,
            mode: info.mode() & 0o7777,
        });
    }
    let locks = InstanceLocks { held: locks };
    locks.verify()?;
    Ok(locks)
}
fn inherited_file(descriptor: i32) -> anyhow::Result<File> {
    inherited(descriptor)
}

pub fn business_directory(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    crate::contracts::normalized(path)?;
    if path.try_exists()? {
        ensure!(
            fs::symlink_metadata(path)?.is_dir(),
            "business layout path is not a directory"
        );
        return Ok(());
    }
    ensure!(
        fs::symlink_metadata(path.parent().context("business parent missing")?)?.is_dir(),
        "business layout parent is missing"
    );
    fs::DirBuilder::new().mode(0o700).create(path)?;
    crate::creation::record(path, &fs::symlink_metadata(path)?)?;
    assign(path, uid, gid, true)?;
    File::open(path.parent().context("business parent missing")?)?.sync_all()?;
    Ok(())
}
