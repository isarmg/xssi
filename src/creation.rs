//! Authority for files created by one still unpublished installation.
use crate::contracts::ContextData;
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{self, File, Metadata},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    path: PathBuf,
    directory: bool,
    retained: bool,
    parent_device: u64,
    parent_inode: u64,
    device: u64,
    inode: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    operation_id: String,
    root: PathBuf,
    contract_sha256: String,
    config_sha256: String,
    uid: u32,
    gid: u32,
    username: String,
    password_hash: String,
    complete: bool,
    objects: Vec<Object>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkAuthority {
    version: u32,
    operation_id: String,
    root: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    directory_device: Option<u64>,
    directory_inode: Option<u64>,
}
fn save_control(
    parent: &Path,
    name: &str,
    value: &impl Serialize,
    exists: bool,
) -> anyhow::Result<()> {
    let directory = xcsc::fs_safety::PrivateDirectory::open_for_administration(parent)?;
    let bytes = serde_json::to_vec(value)?;
    if exists {
        xcsc::fs_safety::AtomicFile::replace(
            &directory,
            &xcsc::fs_safety::RelativePath::new(name)?,
            &bytes,
        )?;
    } else {
        xcsc::fs_safety::AtomicFile::create(
            &directory,
            &xcsc::fs_safety::EntryName::new(name)?,
            &bytes,
        )?;
    }
    Ok(())
}
fn work_directory(parent: &Path, root: &Path, operation: &str) -> anyhow::Result<PathBuf> {
    private(parent)?;
    let parent_info = fs::symlink_metadata(parent)?;
    let work = parent.join(operation);
    let name = format!("{operation}.json");
    let intent = parent.join(&name);
    if intent.try_exists()? {
        let info = fs::symlink_metadata(&intent)?;
        ensure!(
            info.uid() == 0 && info.mode() & 0o7777 == 0o600,
            "creation work intent ownership differs"
        );
        let mut authority: WorkAuthority =
            crate::strict_json::decode(&crate::contracts::read(&intent, 65536)?)?;
        ensure!(
            authority.version == 1
                && authority.operation_id == operation
                && authority.root == root
                && authority.parent_device == parent_info.dev()
                && authority.parent_inode == parent_info.ino(),
            "creation work intent differs"
        );
        if authority.directory_device.is_none() && authority.directory_inode.is_none() {
            ensure!(
                !work.try_exists()?,
                "creation work inode is unknown; preserve the original operation"
            );
            fs::DirBuilder::new().mode(0o700).create(&work)?;
            let info = fs::symlink_metadata(&work)?;
            authority.directory_device = Some(info.dev());
            authority.directory_inode = Some(info.ino());
            save_control(parent, &name, &authority, true)?;
            File::open(parent)?.sync_all()?;
        }
        let device = authority
            .directory_device
            .context("creation work inode is unknown; preserve the original operation")?;
        let inode = authority
            .directory_inode
            .context("creation work inode is unknown")?;
        let info = fs::symlink_metadata(&work)?;
        ensure!(
            info.is_dir()
                && info.uid() == 0
                && info.dev() == device
                && info.ino() == inode
                && matches!(info.mode() & 0o7777, 0 | 0o700),
            "recorded creation work directory changed"
        );
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700))?;
        return Ok(work);
    }
    ensure!(
        !work.try_exists()?,
        "unrecorded creation work directory must be preserved"
    );
    let mut authority = WorkAuthority {
        version: 1,
        operation_id: operation.into(),
        root: root.to_owned(),
        parent_device: parent_info.dev(),
        parent_inode: parent_info.ino(),
        directory_device: None,
        directory_inode: None,
    };
    save_control(parent, &name, &authority, false)?;
    fs::DirBuilder::new().mode(0o700).create(&work)?;
    let info = fs::symlink_metadata(&work)?;
    authority.directory_device = Some(info.dev());
    authority.directory_inode = Some(info.ino());
    save_control(parent, &name, &authority, true)?;
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))?;
    File::open(parent)?.sync_all()?;
    Ok(work)
}
struct Active {
    path: PathBuf,
    journal: Journal,
    files: BTreeMap<PathBuf, bool>,
    directories: Vec<PathBuf>,
    imported: std::collections::BTreeSet<PathBuf>,
}
thread_local! {static ACTIVE:RefCell<Option<Active>>=const{RefCell::new(None)};}
pub struct Session;
impl Drop for Session {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.borrow_mut().take();
        });
    }
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn save(active: &Active) -> anyhow::Result<()> {
    let parent = xcsc::fs_safety::PrivateDirectory::open_for_administration(
        active.path.parent().context("creation parent missing")?,
    )?;
    let bytes = serde_json::to_vec(&active.journal)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "creation journal exceeds limit"
    );
    let name = xcsc::fs_safety::EntryName::new("created.json")?;
    if active.path.try_exists()? {
        xcsc::fs_safety::AtomicFile::replace(
            &parent,
            &xcsc::fs_safety::RelativePath::new("created.json")?,
            &bytes,
        )?;
    } else {
        xcsc::fs_safety::AtomicFile::create(&parent, &name, &bytes)?;
    }
    Ok(())
}
fn private(path: &Path) -> anyhow::Result<()> {
    crate::contracts::normalized(path)?;
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir() && info.uid() == 0 && info.mode() & 0o7777 == 0o700,
        "creation control directory is not private to administrator"
    );
    Ok(())
}
impl Session {
    pub fn begin(
        context: &ContextData,
        operation: &str,
        uid: u32,
        gid: u32,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Self> {
        let parsed = uuid::Uuid::parse_str(operation)?;
        ensure!(
            parsed.get_version_num() == 4 && parsed.to_string() == operation,
            "creation operation must be canonical UUIDv4"
        );
        let install_info = fs::symlink_metadata(context.root.join("maintenance/install.json"))?;
        ensure!(
            install_info.uid() == 0 && install_info.mode() & 0o7777 == 0o600,
            "installation journal is not administrator controlled"
        );
        let install: serde_json::Value = crate::strict_json::decode(&crate::contracts::read(
            &context.root.join("maintenance/install.json"),
            4 * 1024 * 1024,
        )?)?;
        ensure!(
            install["version"] == 4
                && install["operation_id"] == operation
                && install["product"] == context.contract.identity.product
                && install["root"] == context.root.to_string_lossy().as_ref(),
            "creation operation differs from installation authority"
        );
        ensure!(
            matches!(
                install["phase"].as_str(),
                Some(
                    "initialize-intent"
                        | "initialized"
                        | "publish-intent"
                        | "published"
                        | "units-intent"
                        | "units-installed"
                )
            ),
            "installation has not authorized initialization"
        );
        let manifest =
            crate::contracts::read(&context.package.join("share/package.json"), 1024 * 1024)?;
        ensure!(
            install["package_sha256"] == hash(&manifest),
            "creation package identity differs"
        );
        let mut files = BTreeMap::new();
        for database in &context.contract.databases {
            ensure!(
                files.insert(context.path(&database.path)?, false).is_none(),
                "creation targets overlap"
            );
        }
        for secret in &context.contract.secrets {
            ensure!(
                files.insert(context.path(&secret.path)?, false).is_none(),
                "creation targets overlap"
            );
        }
        if let Some(media) = &context.contract.media {
            files.insert(context.path(&media.configuration_path)?, false);
            for algorithm in &media.validation {
                if algorithm.kind == "environment-v1" {
                    let spec = serde_json::from_value(algorithm.parameters["env_path"].clone())?;
                    files.insert(context.path(&spec)?, false);
                }
            }
        }
        for lock in &context.contract.resources.runtime_locks {
            if lock.kind == "file" {
                ensure!(
                    files.insert(context.path(&lock.path)?, true).is_none(),
                    "creation lock overlaps data"
                );
            }
        }
        let directories = context
            .contract
            .resources
            .private_directories
            .iter()
            .chain(&context.contract.resources.business_directories)
            .map(|spec| context.path(spec))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let parent = context.root.join("maintenance/install");
        private(parent.parent().context("maintenance missing")?)?;
        if !parent.try_exists()? {
            fs::DirBuilder::new().mode(0o700).create(&parent)?;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
            File::open(parent.parent().context("parent missing")?)?.sync_all()?;
        }
        private(&parent)?;
        let work = work_directory(&parent, &context.root, operation)?;
        let path = work.join("created.json");
        let contract_sha256 = hash(&serde_json::to_vec(&context.contract)?);
        let config_sha256 = hash(&serde_json::to_vec(&context.value)?);
        let journal = if path.try_exists()? {
            let info = fs::symlink_metadata(&path)?;
            ensure!(
                info.uid() == 0 && info.mode() & 0o7777 == 0o600,
                "creation journal is not administrator controlled"
            );
            let journal: Journal =
                crate::strict_json::decode(&crate::contracts::read(&path, 4 * 1024 * 1024)?)?;
            ensure!(
                journal.version == 1
                    && journal.operation_id == operation
                    && journal.root == context.root
                    && journal.contract_sha256 == contract_sha256
                    && journal.config_sha256 == config_sha256
                    && journal.uid == uid
                    && journal.gid == gid
                    && journal.username == username,
                "creation context differs from original operation"
            );
            crate::credentials::verify_password(&journal.password_hash, password)?;
            ensure!(
                journal.complete || install["phase"] == "initialize-intent",
                "partial creation cannot be replayed after publication"
            );
            journal
        } else {
            ensure!(
                install["phase"] == "initialize-intent",
                "new creation record requires initialization intent"
            );
            Journal {
                version: 1,
                operation_id: operation.into(),
                root: context.root.clone(),
                contract_sha256,
                config_sha256,
                uid,
                gid,
                username: username.into(),
                password_hash: crate::credentials::hash_password(
                    &context.contract.credentials,
                    password,
                )?,
                complete: false,
                objects: Vec::new(),
            }
        };
        let mut imported = std::collections::BTreeSet::new();
        for (name, record) in install["configuration_files"]
            .as_object()
            .context("installation import records missing")?
        {
            let path = context.root.join("config").join(name);
            crate::contracts::normalized(&path)?;
            ensure!(
                path.starts_with(context.root.join("config")),
                "configuration import escaped root"
            );
            let info = fs::symlink_metadata(&path)?;
            ensure!(
                record["written"] == true
                    && record["device"] == info.dev()
                    && record["inode"] == info.ino()
                    && record["sha256"] == hash(&crate::contracts::read(&path, 4 * 1024 * 1024)?),
                "configuration import authority differs"
            );
            imported.insert(path);
        }
        let active = Active {
            path,
            journal,
            files,
            directories,
            imported,
        };
        validate(&active)?;
        save(&active)?;
        ACTIVE.with(|slot| -> anyhow::Result<()> {
            ensure!(slot.borrow().is_none(), "creation scope already active");
            *slot.borrow_mut() = Some(active);
            Ok(())
        })?;
        Ok(Self)
    }
    pub fn complete(&self) -> anyhow::Result<bool> {
        ACTIVE.with(|slot| {
            Ok(slot
                .borrow()
                .as_ref()
                .context("creation scope missing")?
                .journal
                .complete)
        })
    }
    pub fn clean_partial(&self) -> anyhow::Result<()> {
        ACTIVE.with(|slot| -> anyhow::Result<()> {
            let mut active = slot.borrow_mut();
            let active = active.as_mut().context("creation scope missing")?;
            ensure!(
                !active.journal.complete,
                "completed creation cannot be removed"
            );
            validate(active)?;
            for object in active
                .journal
                .objects
                .iter()
                .filter(|object| !object.directory && !object.retained)
            {
                verify_object(active, object)?;
                if object.path.try_exists()? {
                    fs::remove_file(&object.path)?;
                    File::open(object.path.parent().context("object parent missing")?)?
                        .sync_all()?;
                }
            }
            active
                .journal
                .objects
                .retain(|object| object.directory || object.retained);
            save(active)
        })
    }
    pub fn finish(&self) -> anyhow::Result<()> {
        ACTIVE.with(|slot| -> anyhow::Result<()> {
            let mut active = slot.borrow_mut();
            let active = active.as_mut().context("creation scope missing")?;
            validate(active)?;
            active.journal.complete = true;
            save(active)
        })
    }
}
fn verify_object(active: &Active, object: &Object) -> anyhow::Result<()> {
    crate::contracts::normalized(&object.path)?;
    let parent = fs::symlink_metadata(object.path.parent().context("created parent missing")?)?;
    ensure!(
        parent.is_dir()
            && parent.dev() == object.parent_device
            && parent.ino() == object.parent_inode,
        "created object's parent identity changed"
    );
    match fs::symlink_metadata(&object.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                !object.directory && !object.retained,
                "required creation directory or lock disappeared"
            );
            return Ok(());
        }
        Err(error) => return Err(error.into()),
        Ok(info) => {
            ensure!(
                info.dev() == object.device
                    && info.ino() == object.inode
                    && info.is_dir() == object.directory
                    && (info.is_dir() || info.is_file())
                    && (object.directory || info.nlink() == 1),
                "created inode changed"
            );
            ensure!(
                info.uid() == 0 || info.uid() == active.journal.uid,
                "created owner changed"
            );
            ensure!(info.mode() & 0o7022 == 0, "created permissions changed");
        }
    }
    Ok(())
}
fn validate(active: &Active) -> anyhow::Result<()> {
    ensure!(
        active.journal.objects.len() <= 8192,
        "creation object count exceeds limit"
    );
    let mut paths = std::collections::BTreeSet::new();
    for path in active.files.keys() {
        if fs::symlink_metadata(path).is_ok() {
            ensure!(
                active
                    .journal
                    .objects
                    .iter()
                    .any(|object| object.path == *path)
                    || active.imported.contains(path),
                "unrecorded initialization file must be preserved"
            );
        }
    }
    for object in &active.journal.objects {
        ensure!(paths.insert(&object.path), "creation records repeat");
        ensure!(
            if object.directory {
                active
                    .directories
                    .iter()
                    .any(|root| object.path == *root || object.path.starts_with(root))
            } else {
                active.files.get(&object.path) == Some(&object.retained)
            },
            "creation record names an undeclared resource"
        );
        verify_object(active, object)?;
    }
    Ok(())
}
pub fn record(path: &Path, info: &Metadata) -> anyhow::Result<()> {
    ACTIVE.with(|slot| -> anyhow::Result<()> {
        let mut active = slot.borrow_mut();
        let Some(active) = active.as_mut() else {
            return Ok(());
        };
        let directory = info.is_dir();
        let retained = active.files.get(path).copied();
        let declared_dir = active
            .directories
            .iter()
            .any(|root| path == root || path.starts_with(root));
        if retained.is_none() && !declared_dir {
            return Ok(());
        }
        ensure!(
            directory || retained.is_some(),
            "undeclared private file creation"
        );
        ensure!(
            active.journal.objects.len() < 8192,
            "creation object count exceeds limit"
        );
        ensure!(
            !active.journal.complete
                && info.uid() == 0
                && (info.is_dir() || info.is_file())
                && (directory || info.nlink() == 1),
            "new creation lacks administrator authority"
        );
        ensure!(
            !active
                .journal
                .objects
                .iter()
                .any(|object| object.path == path),
            "creation path already recorded"
        );
        let parent = fs::symlink_metadata(path.parent().context("creation parent missing")?)?;
        File::open(path.parent().context("creation parent missing")?)?.sync_all()?;
        active.journal.objects.push(Object {
            path: path.to_owned(),
            directory,
            retained: retained.unwrap_or(false),
            parent_device: parent.dev(),
            parent_inode: parent.ino(),
            device: info.dev(),
            inode: info.ino(),
        });
        save(active)
    })
}

pub fn active() -> bool {
    ACTIVE.with(|slot| slot.borrow().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Active) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().to_path_buf();
        let state = root.join("state");
        let control = root.join("control");
        for path in [&state, &control] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        let files = BTreeMap::from([
            (state.join("database.sqlite3"), false),
            (state.join("secret.json"), false),
            (state.join("instance.lock"), true),
        ]);
        let journal = Journal {
            version: 1,
            operation_id: uuid::Uuid::new_v4().to_string(),
            root: root.clone(),
            contract_sha256: "a".repeat(64),
            config_sha256: "b".repeat(64),
            uid: 0,
            gid: 0,
            username: "admin".into(),
            password_hash: String::new(),
            complete: false,
            objects: Vec::new(),
        };
        (
            temporary,
            Active {
                path: control.join("created.json"),
                journal,
                files,
                directories: vec![state],
                imported: Default::default(),
            },
        )
    }
    fn attach(active: Active) -> Session {
        validate(&active).unwrap();
        save(&active).unwrap();
        ACTIVE.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(active)
        });
        Session
    }
    #[test]
    fn partial_files_are_recorded_before_bytes_and_cleanup_preserves_original_lock_inode() {
        use std::os::fd::AsFd;
        let (temporary, active) = fixture();
        let state = temporary.path().join("state");
        let journal_path = active.path.clone();
        let session = attach(active);
        crate::filesystem::new_database(&state.join("database.sqlite3")).unwrap();
        let journal: Journal = crate::strict_json::decode(
            &crate::contracts::read(&journal_path, 4 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(journal.objects.len(), 1);
        assert_eq!(fs::metadata(&journal.objects[0].path).unwrap().len(), 0);
        fs::write(
            state.join("database.sqlite3"),
            b"interrupted SQLite generation",
        )
        .unwrap();
        crate::filesystem::create(&state.join("secret.json"), b"new secret fixture").unwrap();
        crate::filesystem::create(&state.join("instance.lock"), b"").unwrap();
        let held = File::open(state.join("instance.lock")).unwrap();
        let inode = held.metadata().unwrap().ino();
        rustix::fs::flock(
            held.as_fd(),
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        session.clean_partial().unwrap();
        session.clean_partial().unwrap();
        assert!(!state.join("database.sqlite3").exists());
        assert!(!state.join("secret.json").exists());
        assert_eq!(
            fs::metadata(state.join("instance.lock")).unwrap().ino(),
            inode
        );
        assert!(
            rustix::fs::flock(
                File::open(state.join("instance.lock")).unwrap().as_fd(),
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            )
            .is_err()
        );
    }
    #[test]
    fn replaced_file_or_unrecorded_creation_window_is_never_deleted() {
        let (temporary, active) = fixture();
        let state = temporary.path().join("state");
        let session = attach(active);
        let path = state.join("database.sqlite3");
        crate::filesystem::new_database(&path).unwrap();
        let replacement = state.join("replacement");
        fs::write(&replacement, b"unknown data").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(session.clean_partial().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"unknown data");
        drop(session);
        let (temporary, active) = fixture();
        let path = temporary.path().join("state/database.sqlite3");
        fs::write(&path, b"unrecorded orphan").unwrap();
        assert!(validate(&active).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"unrecorded orphan");
    }
    #[test]
    fn completed_generation_cannot_be_cleaned_as_partial() {
        let (temporary, active) = fixture();
        let path = temporary.path().join("state/database.sqlite3");
        let session = attach(active);
        crate::filesystem::new_database(&path).unwrap();
        session.finish().unwrap();
        assert!(session.complete().unwrap());
        assert!(session.clean_partial().is_err());
        assert!(path.exists());
    }
    #[test]
    fn durable_work_intent_only_creates_when_no_unknown_directory_exists() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().join("install");
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let operation = uuid::Uuid::new_v4().to_string();
        let info = fs::metadata(&parent).unwrap();
        let authority = WorkAuthority {
            version: 1,
            operation_id: operation.clone(),
            root: temporary.path().to_owned(),
            parent_device: info.dev(),
            parent_inode: info.ino(),
            directory_device: None,
            directory_inode: None,
        };
        let name = format!("{operation}.json");
        save_control(&parent, &name, &authority, false).unwrap();
        let work = work_directory(&parent, temporary.path(), &operation).unwrap();
        let inode = fs::metadata(&work).unwrap().ino();
        assert_eq!(
            work_directory(&parent, temporary.path(), &operation).unwrap(),
            work
        );
        assert_eq!(fs::metadata(&work).unwrap().ino(), inode);
        let other = uuid::Uuid::new_v4().to_string();
        let mut authority = authority;
        authority.operation_id = other.clone();
        save_control(&parent, &format!("{other}.json"), &authority, false).unwrap();
        let unknown = parent.join(&other);
        fs::DirBuilder::new().mode(0o700).create(&unknown).unwrap();
        let unknown_inode = fs::metadata(&unknown).unwrap().ino();
        assert!(work_directory(&parent, temporary.path(), &other).is_err());
        assert_eq!(fs::metadata(&unknown).unwrap().ino(), unknown_inode);
    }
}
