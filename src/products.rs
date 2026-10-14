//! Product operations consume owner-generated definitions and independent code.
use crate::{
    contracts::{ContextData, Secret},
    credentials, filesystem,
};
use anyhow::{Context, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::Value;
use std::{fs, path::Path};

pub fn context(
    product: &str,
    root: &Path,
    config: &Path,
    missing: bool,
) -> anyhow::Result<ContextData> {
    let context = ContextData::load(product, root, config, missing)?;
    credentials::verify_examples(&context.contract.credentials)?;
    context.report(false)?;
    for secret in &context.contract.secrets {
        secret_examples(secret)?;
    }
    for database in &context.contract.databases {
        for algorithm in &database.validation {
            crate::validation::examples(&context, algorithm)?;
        }
    }
    if let Some(media) = &context.contract.media {
        crate::media::examples(&context, media)?;
    }
    Ok(context)
}

pub async fn check(context: &ContextData, uid: u32, gid: u32) -> anyhow::Result<Value> {
    check_ownership(context, uid, gid)?;
    for spec in &context.contract.resources.business_directories {
        let path = context.path(spec)?;
        crate::contracts::normalized(&path)?;
        ensure!(
            fs::symlink_metadata(&path)?.is_dir(),
            "required business directory is missing"
        );
    }
    for secret in &context.contract.secrets {
        check_secret(context, secret)?;
    }
    for database in &context.contract.databases {
        crate::database::check(context, database).await?;
    }
    if let Some(media) = &context.contract.media {
        crate::validation::media(context, media)?;
    }
    context.report(true)
}

pub async fn initialize(
    context: &ContextData,
    username: &str,
    password: &str,
    uid: u32,
    gid: u32,
) -> anyhow::Result<()> {
    let username = credentials::normalize(&context.contract.credentials, username)?;
    let hash = credentials::hash_password(&context.contract.credentials, password)?;
    precheck_initialize(context)?;
    for path in &context.contract.resources.private_directories {
        filesystem::private_directory(&context.path(path)?)?;
    }
    ensure!(
        context.config_path.exists(),
        "installer configuration is missing"
    );
    for path in &context.contract.resources.business_directories {
        filesystem::business_directory(&context.path(path)?, uid, gid)?;
    }
    for secret in &context.contract.secrets {
        let path = context.path(&secret.path)?;
        let bytes = generate_secret(secret)?;
        filesystem::create(&path, &bytes)?;
        filesystem::assign(&path, uid, gid, false)?;
    }
    for database in &context.contract.databases {
        crate::database::initialize(context, database, &username, &hash).await?;
        filesystem::assign(&context.path(&database.path)?, uid, gid, false)?;
    }
    if let Some(media) = &context.contract.media {
        crate::validation::generate_media(context, media, uid, gid)?;
    }
    // Known private roots are shallowly assigned; existing business trees are
    // outside this loop and are never recursively chowned.
    for path in &context.contract.resources.private_directories {
        filesystem::assign(&context.path(path)?, uid, gid, true)?;
    }
    Ok(())
}

pub async fn reset(
    context: &ContextData,
    username: &str,
    password: &str,
    uid: u32,
    gid: u32,
) -> anyhow::Result<()> {
    check(context, uid, gid).await?;
    let username = credentials::normalize(&context.contract.credentials, username)?;
    let hash = credentials::hash_password(&context.contract.credentials, password)?;
    for database in &context.contract.databases {
        if !database.reset_administrator.is_empty() {
            crate::database::reset(context, database, &username, &hash).await?;
        }
    }
    Ok(())
}

fn generate_secret(secret: &Secret) -> anyhow::Result<Vec<u8>> {
    secret_examples(secret)?;
    ensure!(
        secret.validation.is_empty(),
        "required secret semantics are not implemented"
    );
    let mut value = secret
        .constants
        .as_object()
        .context("secret constants must be an object")?
        .clone();
    let mut raw = None;
    for field in &secret.fields {
        let bytes = credentials::random(field.bytes)?;
        let encoded = match field.encoding.as_str() {
            "base64url-no-pad" => Value::String(URL_SAFE_NO_PAD.encode(bytes)),
            "base64" => Value::String(STANDARD.encode(bytes)),
            "hex" => Value::String(bytes.iter().map(|byte| format!("{byte:02x}")).collect()),
            "byte-array" => Value::Array(bytes.into_iter().map(Value::from).collect()),
            "raw" => {
                ensure!(
                    secret.fields.len() == 1 && secret.format == "raw",
                    "raw secret must have one field"
                );
                raw = Some(bytes);
                Value::Null
            }
            _ => anyhow::bail!("unknown secret encoding"),
        };
        ensure!(
            value.insert(field.name.clone(), encoded).is_none(),
            "secret constant and generated field collide"
        );
    }
    match secret.format.as_str() {
        "json" => Ok(serde_json::to_vec_pretty(&value)?),
        "raw" => raw.context("raw secret bytes missing"),
        _ => anyhow::bail!("unknown secret format"),
    }
}

fn secret_bytes(secret: &Secret, bytes: &[u8]) -> anyhow::Result<()> {
    ensure!(
        secret.validation.is_empty(),
        "required secret semantics are not implemented"
    );
    ensure!(bytes.len() <= 64 * 1024, "secret exceeds byte bound");
    let mut names = std::collections::BTreeSet::new();
    ensure!(
        secret.fields.iter().all(|field| names.insert(&field.name)),
        "secret field names repeat"
    );
    if secret.format == "raw" {
        ensure!(
            secret.fields.len() == 1
                && secret.fields[0].encoding == "raw"
                && secret
                    .constants
                    .as_object()
                    .is_some_and(|value| value.is_empty())
                && bytes.len() == secret.fields[0].bytes,
            "raw secret shape differs"
        );
        return Ok(());
    }
    ensure!(secret.format == "json", "unknown secret format");
    let value: Value = crate::strict_json::decode(bytes)?;
    let fields = value.as_object().context("secret must be a JSON object")?;
    let constants = secret
        .constants
        .as_object()
        .context("secret constants must be an object")?;
    ensure!(
        fields.len() == constants.len() + secret.fields.len()
            && constants
                .iter()
                .all(|(key, value)| fields.get(key) == Some(value))
            && secret
                .fields
                .iter()
                .all(|field| !constants.contains_key(&field.name)),
        "secret field set or constants differ"
    );
    for field in &secret.fields {
        let decoded = decode_value(
            &field.encoding,
            fields.get(&field.name).context("secret field is missing")?,
        )?;
        ensure!(decoded.len() == field.bytes, "secret field length differs");
    }
    Ok(())
}
fn secret_examples(secret: &Secret) -> anyhow::Result<()> {
    ensure!(
        !secret.cases.is_empty() && secret.cases.iter().any(|case| case.valid),
        "secret lacks positive validation examples"
    );
    for case in &secret.cases {
        let bytes = if secret.format == "raw" {
            decode(
                "base64",
                case.input
                    .as_str()
                    .context("raw secret example must be base64 bytes")?,
            )?
        } else {
            serde_json::to_vec(&case.input)?
        };
        ensure!(
            secret_bytes(secret, &bytes).is_ok() == case.valid,
            "secret implementation disagrees with example {}",
            case.name
        );
    }
    Ok(())
}
pub fn check_secret(context: &ContextData, secret: &Secret) -> anyhow::Result<()> {
    secret_examples(secret)?;
    secret_bytes(
        secret,
        &crate::contracts::read(&context.path(&secret.path)?, 64 * 1024)?,
    )
}
pub fn precheck_initialize(context: &ContextData) -> anyhow::Result<()> {
    let business = context
        .contract
        .resources
        .business_paths
        .iter()
        .map(|path| context.path(path))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let runtime = context
        .contract
        .resources
        .runtime_locks
        .iter()
        .filter(|lock| lock.kind == "file")
        .map(|lock| context.path(&lock.path))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let private = context
        .contract
        .resources
        .private_directories
        .iter()
        .map(|path| context.path(path))
        .collect::<anyhow::Result<Vec<_>>>()?;
    require_empty_private(&context.data_dir, &business, &runtime, &private, 0)?;
    for database in &context.contract.databases {
        ensure!(
            !context.path(&database.path)?.try_exists()?,
            "initialization refuses existing database"
        );
    }
    for secret in &context.contract.secrets {
        ensure!(
            !context.path(&secret.path)?.try_exists()?,
            "initialization refuses existing secret"
        );
    }
    Ok(())
}
fn require_empty_private(
    path: &Path,
    business: &[std::path::PathBuf],
    runtime: &[std::path::PathBuf],
    private: &[std::path::PathBuf],
    depth: usize,
) -> anyhow::Result<()> {
    ensure!(depth <= 128, "private initialization nesting exceeds limit");
    if business.iter().any(|declared| declared == path) {
        crate::contracts::normalized(path)?;
        ensure!(
            fs::symlink_metadata(path)?.is_dir(),
            "business root must be a directory"
        );
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(info) => ensure!(
            info.is_dir() && !info.file_type().is_symlink(),
            "private state path is not a directory"
        ),
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        if runtime.contains(&child) {
            continue;
        }
        ensure!(
            business
                .iter()
                .chain(runtime.iter())
                .chain(private.iter())
                .any(|declared| declared.starts_with(&child)),
            "initialization refuses existing private state"
        );
        require_empty_private(&child, business, runtime, private, depth + 1)?;
    }
    Ok(())
}

pub fn decode(encoding: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    match encoding {
        "base64url-no-pad" => {
            let bytes = URL_SAFE_NO_PAD.decode(value)?;
            ensure!(
                URL_SAFE_NO_PAD.encode(&bytes) == value,
                "secret encoding is not canonical"
            );
            Ok(bytes)
        }
        "base64" => {
            let bytes = STANDARD.decode(value)?;
            ensure!(
                STANDARD.encode(&bytes) == value,
                "secret encoding is not canonical"
            );
            Ok(bytes)
        }
        "hex" => {
            ensure!(
                value.len().is_multiple_of(2)
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "secret hex must be canonical"
            );
            value
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
                .collect()
        }
        _ => anyhow::bail!("unknown secret encoding"),
    }
}

pub fn decode_value(encoding: &str, value: &Value) -> anyhow::Result<Vec<u8>> {
    if encoding == "byte-array" {
        return value
            .as_array()
            .context("secret byte array is missing")?
            .iter()
            .map(|byte| {
                Ok(u8::try_from(
                    byte.as_u64().context("secret array item must be a byte")?,
                )?)
            })
            .collect();
    }
    decode(
        encoding,
        value.as_str().context("secret field must be text")?,
    )
}

fn check_ownership(context: &ContextData, uid: u32, gid: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let private = |path: &Path, directory: bool| -> anyhow::Result<()> {
        crate::contracts::normalized(path)?;
        let info = fs::symlink_metadata(path)?;
        ensure!(
            info.is_dir() == directory
                && (info.is_dir() || info.is_file())
                && (directory || info.nlink() == 1)
                && info.uid() == uid
                && info.gid() == gid
                && info.mode() & 0o7777 == if directory { 0o700 } else { 0o600 },
            "private resource ownership or mode differs from service identity"
        );
        Ok(())
    };
    for directory in &context.contract.resources.private_directories {
        private(&context.path(directory)?, true)?;
    }
    for secret in &context.contract.secrets {
        private(&context.path(&secret.path)?, false)?;
    }
    for database in &context.contract.databases {
        let path = context.path(&database.path)?;
        private(&path, false)?;
        for suffix in ["-wal", "-shm"] {
            let part = path.with_file_name(format!(
                "{}{suffix}",
                path.file_name()
                    .context("database name missing")?
                    .to_string_lossy()
            ));
            match fs::symlink_metadata(&part) {
                Ok(_) => private(&part, false)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}
