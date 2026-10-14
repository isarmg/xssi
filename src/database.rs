//! Bounded SQLite checks and writes driven by current DDL/statements.
use crate::{
    contracts::{ContextData, Database, Parameter, Statement},
    credentials, filesystem,
};
use anyhow::{Context, ensure};
use serde_json::Value;
use sqlx::{
    ConnectOptions, Connection, Executor, Row, SqliteConnection, sqlite::SqliteConnectOptions,
};
use std::{
    fs::File,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

async fn open(path: &Path, readonly: bool) -> anyhow::Result<SqliteConnection> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(readonly)
        .create_if_missing(false)
        .busy_timeout(std::time::Duration::from_secs(5))
        .disable_statement_logging();
    let mut connection = SqliteConnection::connect_with(&options).await?;
    connection
        .execute("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF")
        .await?;
    xcsc::sqlite::enable_defensive(&mut connection).await?;
    Ok(connection)
}

pub async fn check(context: &ContextData, database: &Database) -> anyhow::Result<()> {
    let original = context.path(&database.path)?;
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::Builder::new()
        .prefix("xssi-sqlite-check-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let target = temporary.path().join("check.db");
    // Open the stopped file group first, copy with bounded memory, and recheck
    // every original descriptor after all copies. SQLite only writes the view.
    let mut group = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let source = original.with_file_name(format!(
            "{}{suffix}",
            original
                .file_name()
                .context("database name missing")?
                .to_string_lossy()
        ));
        crate::contracts::normalized(&source)?;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&source)
        {
            Ok(file) => {
                let info = file.metadata()?;
                ensure!(
                    info.is_file() && info.nlink() == 1 && info.len() <= 1024_u64.pow(4),
                    "database group type, links or size exceeds limit"
                );
                group.push((suffix, source, file, info));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() => {}
            Err(error) => return Err(error.into()),
        }
    }
    for (suffix, _, file, before) in &mut group {
        let destination = target.with_file_name(format!("check.db{suffix}"));
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)?;
        use std::io::Read;
        ensure!(
            std::io::copy(&mut file.take(before.len() + 1), &mut output)? == before.len(),
            "database changed while copying"
        );
        output.sync_all()?;
    }
    for (_, source, file, before) in &group {
        let after = file.metadata()?;
        let named = std::fs::symlink_metadata(source)?;
        ensure!(
            before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.dev() == named.dev()
                && before.ino() == named.ino()
                && before.len() == after.len()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "database group changed while creating its read view"
        );
    }
    let mut connection = open(&target, false).await?;
    let result = check_connection(context, database, &mut connection).await;
    connection.close().await?;
    result
}

async fn check_connection(
    context: &ContextData,
    database: &Database,
    connection: &mut SqliteConnection,
) -> anyhow::Result<()> {
    ensure!(
        database.fingerprint_algorithm == "sqlite-schema-v1",
        "unsupported schema fingerprint algorithm"
    );
    let fingerprint = xcsc::sqlite::schema_fingerprint(&mut *connection).await?;
    database.schema_identity.verify_fingerprint(&fingerprint)?;
    if let Some(stamp) = &database.schema_stamp {
        xcsc::sqlite::require_current_schema(connection, stamp).await?;
    }
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check(1)")
        .fetch_one(&mut *connection)
        .await?;
    ensure!(integrity == "ok", "database integrity check failed");
    ensure!(
        sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(&mut *connection)
            .await?
            .is_none(),
        "database foreign key check failed"
    );
    for check in &database.checks {
        let mut query = sqlx::query(sqlx::AssertSqlSafe(check.sql.as_str()));
        let values = Parameters::readonly(database);
        for value in &check.parameters {
            ensure!(
                matches!(
                    value.source.as_str(),
                    "literal"
                        | "schema.application"
                        | "schema.application_version"
                        | "schema.schema_revision"
                        | "schema.schema_sha256"
                        | "resource_device_be"
                        | "resource_inode_be"
                        | "resource_path"
                        | "root"
                        | "data_dir"
                        | "metadata_policy_revision"
                ),
                "read-only SQL parameter cannot access mutation inputs"
            );
            query = match parameter(context, value, &values)? {
                Bound::Text(value) => query.bind(value),
                Bound::Integer(value) => query.bind(value),
                Bound::Boolean(value) => query.bind(value),
                Bound::Null => query.bind(None::<String>),
                Bound::Blob(value) => query.bind(value),
            };
        }
        use futures_util::TryStreamExt;
        let mut rows = query.fetch(&mut *connection);
        let first = rows.try_next().await?;
        let second = rows.try_next().await?;
        ensure!(
            match check.expect.as_str() {
                "no-rows" => first.is_none(),
                "one-row" => first.is_some() && second.is_none(),
                "true" =>
                    first
                        .as_ref()
                        .is_some_and(|row| row.try_get::<i64, _>(0).ok() == Some(1))
                        && second.is_none(),
                "integrity-ok" => first.as_ref().is_some_and(|row| row
                    .try_get::<String, _>(0)
                    .ok()
                    .as_deref()
                    == Some("ok"))
                    && second.is_none(),
                _ => false,
            },
            "generated database semantic check failed"
        );
    }
    if !database.reset_administrator.is_empty() {
        check_administrator(context, connection).await?;
    }
    for algorithm in &database.validation {
        crate::validation::database(context, connection, algorithm).await?;
    }
    Ok(())
}

async fn check_administrator(
    context: &ContextData,
    connection: &mut SqliteConnection,
) -> anyhow::Result<()> {
    use futures_util::TryStreamExt;
    let policy = &context.contract.credentials;
    let mut rows = sqlx::query(sqlx::AssertSqlSafe(policy.administrator_query.as_str()))
        .fetch(&mut *connection);
    let row = rows.try_next().await?.context("administrator is missing")?;
    ensure!(
        rows.try_next().await?.is_none(),
        "expected one administrator"
    );
    let username: String = row.try_get("username")?;
    ensure!(
        credentials::normalize(policy, &username)? == username
            && row.try_get::<i64, _>("active")? == 1
            && row.try_get::<i64, _>("session_version")? > 0,
        "administrator fields violate current policy"
    );
    let id: String = row.try_get("administrator_id")?;
    ensure!(
        !id.is_empty()
            && id.len() <= policy.identifier_max_bytes
            && id.is_ascii()
            && !id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
        "administrator identifier violates policy"
    );
    credentials::check_hash(policy, &row.try_get::<String, _>("password_hash")?)?;
    let created: i64 = row.try_get("created_at_micros")?;
    let updated: i64 = row.try_get("updated_at_micros")?;
    let last: Option<i64> = row.try_get("last_login_at_micros")?;
    ensure!(
        created >= 0 && updated >= created && last.is_none_or(|last| last >= 0),
        "administrator timestamps violate current policy"
    );
    drop(rows);
    let mut sessions =
        sqlx::query(sqlx::AssertSqlSafe(policy.session_query.as_str())).fetch(&mut *connection);
    let mut count = 0u64;
    while let Some(row) = sessions.try_next().await? {
        count += 1;
        ensure!(
            count <= policy.maximum_session_rows,
            "session inventory exceeds its declared bound"
        );
        for column in ["session_id", "administrator_id"] {
            let id: String = row.try_get(column)?;
            ensure!(
                !id.is_empty()
                    && id.len() <= policy.identifier_max_bytes
                    && id.is_ascii()
                    && !id
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
                "session identifier violates policy"
            );
        }
        for column in ["token_hash", "csrf_hash"] {
            ensure!(
                row.try_get::<Vec<u8>, _>(column)?.len() == policy.session_digest_bytes,
                "session digest size differs"
            );
        }
        let created: i64 = row.try_get("created_at_micros")?;
        let last: i64 = row.try_get("last_seen_at_micros")?;
        let idle: i64 = row.try_get("idle_expires_at_micros")?;
        let absolute: i64 = row.try_get("absolute_expires_at_micros")?;
        let revoked: Option<i64> = row.try_get("revoked_at_micros")?;
        ensure!(
            created >= 0
                && last >= created
                && idle > created
                && absolute >= idle
                && revoked.is_none_or(|value| value >= 0)
                && row.try_get::<i64, _>("administrator_session_version")? > 0,
            "session record violates current semantics"
        );
    }
    Ok(())
}

#[derive(Clone)]
struct Parameters {
    username: String,
    password_hash: String,
    administrator_id: String,
    event_id: String,
    now: i64,
    schema: xcsc::contracts::SchemaIdentity,
    uuid: String,
}
impl Parameters {
    fn readonly(database: &Database) -> Self {
        Self {
            username: String::new(),
            password_hash: String::new(),
            administrator_id: String::new(),
            event_id: String::new(),
            now: 0,
            uuid: String::new(),
            schema: database
                .schema_stamp
                .as_ref()
                .unwrap_or(&database.schema_identity)
                .clone(),
        }
    }
    fn new(
        context: &ContextData,
        database: &Database,
        username: &str,
        hash: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            schema: database
                .schema_stamp
                .as_ref()
                .unwrap_or(&database.schema_identity)
                .clone(),
            uuid: uuid::Uuid::new_v4().to_string(),
            username: username.into(),
            password_hash: hash.into(),
            administrator_id: credentials::identifier(&context.contract.credentials)?,
            event_id: credentials::identifier(&context.contract.credentials)?,
            now: i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_micros(),
            )?,
        })
    }
}

enum Bound {
    Text(String),
    Integer(i64),
    Boolean(bool),
    Null,
    Blob(Vec<u8>),
}
fn parameter(
    context: &ContextData,
    parameter: &Parameter,
    values: &Parameters,
) -> anyhow::Result<Bound> {
    let text = |value: String| -> anyhow::Result<Bound> {
        ensure!(parameter.r#type == "text", "parameter type differs");
        Ok(Bound::Text(value))
    };
    let integer = |value: i64| -> anyhow::Result<Bound> {
        ensure!(parameter.r#type == "integer", "parameter type differs");
        Ok(Bound::Integer(value))
    };
    match parameter.source.as_str() {
        "username" => text(values.username.clone()),
        "username_sha256" => {
            use sha2::{Digest, Sha256};
            ensure!(parameter.r#type == "blob", "username digest must be BLOB");
            Ok(Bound::Blob(
                Sha256::digest(values.username.as_bytes()).to_vec(),
            ))
        }
        "uuid-v4" => text(values.uuid.clone()),
        "password_hash" => text(values.password_hash.clone()),
        "administrator_id" => text(values.administrator_id.clone()),
        "event_id" => text(values.event_id.clone()),
        "now_micros" => integer(values.now),
        "schema.application" => text(values.schema.application.clone()),
        "schema.application_version" => text(values.schema.application_version.clone()),
        "schema.schema_revision" => integer(i64::try_from(values.schema.schema_revision)?),
        "schema.schema_sha256" => text(values.schema.schema_sha256.clone()),
        "root" => text(context.root.to_str().context("root is not UTF-8")?.into()),
        "data_dir" => text(
            context
                .data_dir
                .to_str()
                .context("data path is not UTF-8")?
                .into(),
        ),
        "resource_path" | "resource_device_be" | "resource_inode_be" => {
            let raw = serde_json::to_value(&context.contract)?;
            let spec = serde_json::from_value(
                raw.pointer(
                    parameter
                        .value
                        .as_str()
                        .context("resource parameter must be a contract pointer")?,
                )
                .context("resource pointer is missing")?
                .clone(),
            )?;
            let path = context.path(&spec)?;
            if parameter.source == "resource_path" {
                return text(path.to_str().context("resource path is not UTF-8")?.into());
            }
            ensure!(
                parameter.r#type == "blob",
                "resource identity must be a BLOB"
            );
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(path)?;
            let info = file.metadata()?;
            Ok(Bound::Blob(
                if parameter.source == "resource_device_be" {
                    info.dev()
                } else {
                    info.ino()
                }
                .to_be_bytes()
                .to_vec(),
            ))
        }
        "secret" => {
            let reference = parameter
                .value
                .as_str()
                .context("secret parameter must name a declared field")?;
            ensure!(
                parameter.r#type == "blob",
                "secret SQL parameter must be BLOB"
            );
            Ok(Bound::Blob(crate::validation::secret_value(
                context, reference,
            )?))
        }
        "literal" | "metadata_policy_revision" => match (&parameter.r#type[..], &parameter.value) {
            ("text", Value::String(value)) => Ok(Bound::Text(value.clone())),
            ("integer", Value::Number(value)) => Ok(Bound::Integer(
                value.as_i64().context("integer exceeds SQLite range")?,
            )),
            ("boolean", Value::Bool(value)) => Ok(Bound::Boolean(*value)),
            ("null", Value::Null) => Ok(Bound::Null),
            _ => anyhow::bail!("literal parameter type differs"),
        },
        _ => anyhow::bail!("required SQL parameter source is not implemented"),
    }
}

async fn statements(
    context: &ContextData,
    connection: &mut SqliteConnection,
    statements: &[Statement],
    values: &Parameters,
) -> anyhow::Result<()> {
    for statement in statements {
        let mut values = values.clone();
        values.event_id = credentials::identifier(&context.contract.credentials)?;
        values.uuid = uuid::Uuid::new_v4().to_string();
        let mut query = sqlx::query(sqlx::AssertSqlSafe(statement.sql.as_str()));
        for value in &statement.parameters {
            query = match parameter(context, value, &values)? {
                Bound::Text(value) => query.bind(value),
                Bound::Integer(value) => query.bind(value),
                Bound::Boolean(value) => query.bind(value),
                Bound::Null => query.bind(None::<String>),
                Bound::Blob(value) => query.bind(value),
            };
        }
        let result = query.execute(&mut *connection).await?;
        ensure!(
            statement
                .expected_changes
                .is_none_or(|count| result.rows_affected() == count),
            "statement changed an unexpected number of rows"
        );
    }
    Ok(())
}

pub async fn initialize(
    context: &ContextData,
    database: &Database,
    username: &str,
    hash: &str,
) -> anyhow::Result<()> {
    let path = context.path(&database.path)?;
    filesystem::new_database(&path)?;
    let mut connection = open(&path, false).await?;
    connection.execute("PRAGMA journal_mode=MEMORY").await?;
    connection.execute("BEGIN IMMEDIATE").await?;
    let values = Parameters::new(context, database, username, hash)?;
    let result = async {
        let ddl = String::from_utf8(context.asset(&database.ddl)?)?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(ddl.as_str()))
            .execute(&mut connection)
            .await?;
        statements(context, &mut connection, &database.initialize, &values).await?;
        check_connection(context, database, &mut connection).await?;
        connection.execute("COMMIT").await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = connection.execute("ROLLBACK").await;
    }
    connection.close().await?;
    File::open(path)?.sync_all()?;
    result
}

pub async fn reset(
    context: &ContextData,
    database: &Database,
    username: &str,
    hash: &str,
) -> anyhow::Result<()> {
    let mut connection = open(&context.path(&database.path)?, false).await?;
    connection.execute("BEGIN IMMEDIATE").await?;
    let mut values = Parameters::new(context, database, username, hash)?;
    let row = sqlx::query(sqlx::AssertSqlSafe(
        context.contract.credentials.administrator_query.as_str(),
    ))
    .fetch_one(&mut connection)
    .await?;
    ensure!(
        row.try_get::<String, _>("username")? == username,
        "administrator username does not match"
    );
    values.administrator_id = row.try_get("administrator_id")?;
    let result = async {
        statements(
            context,
            &mut connection,
            &database.reset_administrator,
            &values,
        )
        .await?;
        check_connection(context, database, &mut connection).await?;
        connection.execute("COMMIT").await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = connection.execute("ROLLBACK").await;
    }
    connection.close().await?;
    result
}
