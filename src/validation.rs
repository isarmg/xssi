//! Explicit current semantic checks. Unsupported required algorithms fail closed.
use crate::contracts::{Algorithm, ContextData, Media};
use anyhow::{Context, ensure};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};

fn text<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .context("semantic parameter is missing")
}
fn number(value: &Value, key: &str) -> anyhow::Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .context("semantic bound is missing")
}

pub fn examples(context: &ContextData, algorithm: &Algorithm) -> anyhow::Result<()> {
    ensure!(
        !algorithm.description.is_empty()
            && !algorithm.cases.is_empty()
            && algorithm.cases.iter().any(|case| case.valid),
        "required semantic definition lacks verifiable examples"
    );
    let p = &algorithm.parameters;
    let allowed: &[&str] = match algorithm.kind.as_str() {
        "sqlite-json-schema-v1" => &["query", "schema", "rules", "maximum_bytes", "maximum_rows"],
        "sgev-authorization-v1" => &[
            "query",
            "binding",
            "digest_encoding",
            "domain",
            "revision",
            "key_secret",
            "maximum_ciphertext_bytes",
            "maximum_rows",
            "plaintext_bytes",
            "nullable",
            "ciphertext_encoding",
            "ciphertext_prefix",
            "digest_nullable",
        ],
        "wrapped-sgev-operation-v1" => &[
            "query",
            "action_pointer",
            "binding_components",
            "binding_device_pointer",
            "binding_installation_pointer",
            "ciphertext_encoding",
            "ciphertext_prefix",
            "commands",
            "domain",
            "fingerprint",
            "key_secret",
            "maximum_payload_bytes",
            "maximum_plaintext_bytes",
            "maximum_rows",
            "namespace_prefix",
            "request_schema",
            "revision",
        ],
        _ => anyhow::bail!("required database semantic algorithm is not implemented"),
    };
    ensure!(
        p.as_object()
            .context("semantic parameters must be an object")?
            .keys()
            .all(|key| allowed.contains(&key.as_str())),
        "unknown required semantic parameter"
    );
    match algorithm.kind.as_str() {
        "sqlite-json-schema-v1" => {
            let maximum = number(p, "maximum_bytes")?;
            let rows = number(p, "maximum_rows")?;
            ensure!(
                maximum > 0 && maximum <= 4 * 1024 * 1024 && rows > 0 && rows <= 2_000_000,
                "semantic bounds exceed tool limits"
            );
            text(p, "query")?;
            let validator = jsonschema::options()
                .should_validate_formats(true)
                .build(p.get("schema").context("JSON semantic schema is missing")?)?;
            let rules: Vec<crate::contracts::Rule> = serde_json::from_value(
                p.get("rules")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            )?;
            for case in &algorithm.cases {
                let valid = validator.is_valid(&case.input)
                    && rules.iter().all(|rule| {
                        crate::contracts::validate_rule(rule, &case.input, &context.root).is_ok()
                    });
                ensure!(
                    valid == case.valid,
                    "JSON semantic implementation disagrees with example"
                );
            }
        }
        "sgev-authorization-v1" => {
            text(p, "query")?;
            text(p, "key_secret")?;
            let rows = number(p, "maximum_rows")?;
            let bytes = number(p, "maximum_ciphertext_bytes")?;
            ensure!(
                rows > 0 && rows <= 2_000_000 && bytes > 0 && bytes <= 1024 * 1024,
                "authorization bounds exceed tool limits"
            );
            authorization_examples(algorithm)?;
        }
        "wrapped-sgev-operation-v1" => {
            text(p, "query")?;
            text(p, "key_secret")?;
            let rows = number(p, "maximum_rows")?;
            let bytes = number(p, "maximum_payload_bytes")?;
            ensure!(
                rows > 0
                    && rows <= 2_000_000
                    && bytes > 0
                    && bytes <= 4 * 1024 * 1024
                    && number(p, "maximum_plaintext_bytes")? <= 1024 * 1024,
                "operation bounds exceed tool limits"
            );
            for case in &algorithm.cases {
                let row: OperationExample = serde_json::from_value(case.input.clone())?;
                let valid = (|| operation_row(p, &example_key(&row.key_hex)?, &row))().is_ok();
                ensure!(
                    valid == case.valid,
                    "operation implementation disagrees with its example"
                );
            }
        }
        _ => anyhow::bail!("required database semantic algorithm is not implemented"),
    }
    Ok(())
}

pub async fn database(
    context: &ContextData,
    connection: &mut SqliteConnection,
    algorithm: &Algorithm,
) -> anyhow::Result<()> {
    ensure!(
        !algorithm.description.is_empty() && !algorithm.cases.is_empty(),
        "required semantic definition lacks verifiable examples"
    );
    match algorithm.kind.as_str() {
        "sqlite-json-schema-v1" => {
            let p = &algorithm.parameters;
            let maximum = number(p, "maximum_bytes")?;
            let rows = number(p, "maximum_rows")?;
            ensure!(
                maximum <= 4 * 1024 * 1024 && rows <= 2_000_000,
                "semantic bounds exceed tool limits"
            );
            let schema = p.get("schema").context("JSON semantic schema is missing")?;
            let validator = jsonschema::options()
                .should_validate_formats(true)
                .build(schema)?;
            let rules: Vec<crate::contracts::Rule> = serde_json::from_value(
                p.get("rules")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            )?;
            let valid = |value: &Value| {
                validator.is_valid(value)
                    && rules.iter().all(|rule| {
                        crate::contracts::validate_rule(rule, value, &context.root).is_ok()
                    })
            };
            for case in &algorithm.cases {
                ensure!(
                    valid(&case.input) == case.valid,
                    "JSON semantic implementation disagrees with example"
                );
            }
            let query = format!(
                "SELECT CASE WHEN length(CAST(value AS BLOB))<=? THEN CAST(value AS BLOB) END AS value, length(CAST(value AS BLOB)) AS bytes FROM ({}) LIMIT ?",
                text(p, "query")?.trim_end_matches(';')
            );
            use futures_util::TryStreamExt;
            let mut stream = sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
                .bind(i64::try_from(maximum)?)
                .bind(i64::try_from(rows + 1)?)
                .fetch(connection);
            let mut count = 0;
            while let Some(row) = stream.try_next().await? {
                count += 1;
                ensure!(count <= rows, "semantic row count exceeds bound");
                let bytes = row
                    .try_get::<Option<Vec<u8>>, _>("value")?
                    .context("JSON row is missing or exceeds bound")?;
                let value: Value = crate::strict_json::decode(&bytes)?;
                ensure!(valid(&value), "persisted JSON violates current semantics");
            }
        }
        "sgev-authorization-v1" => authorization(context, connection, algorithm).await?,
        "wrapped-sgev-operation-v1" => operations(context, connection, algorithm).await?,
        _ => anyhow::bail!("required database semantic algorithm is not implemented"),
    };
    Ok(())
}

pub fn secret_value(context: &ContextData, reference: &str) -> anyhow::Result<Vec<u8>> {
    let (name, field) = reference
        .split_once('.')
        .context("secret reference must name a declared field")?;
    let secret = context
        .contract
        .secrets
        .iter()
        .find(|secret| secret.name == name)
        .context("secret definition is missing")?;
    let definition = secret
        .fields
        .iter()
        .find(|definition| definition.name == field)
        .context("secret field definition is missing")?;
    let raw = crate::contracts::read(&context.path(&secret.path)?, 64 * 1024)?;
    let bytes = if secret.format == "raw" {
        raw
    } else {
        let value: Value = crate::strict_json::decode(&raw)?;
        crate::products::decode_value(
            &definition.encoding,
            value.get(field).context("secret field is missing")?,
        )?
    };
    ensure!(
        bytes.len() == definition.bytes,
        "secret field length differs"
    );
    Ok(bytes)
}

fn uuid_binding(kind: &str, identity: &[u8]) -> anyhow::Result<Vec<u8>> {
    let uuid = if identity.len() == 16 {
        uuid::Uuid::from_slice(identity)?
    } else {
        uuid::Uuid::parse_str(std::str::from_utf8(identity)?)?
    };
    match kind {
        "uuid-bytes" => Ok(uuid.as_bytes().to_vec()),
        "uuid-text" => Ok(uuid.to_string().into_bytes()),
        "length-prefixed-uuid-text" => {
            let text = uuid.to_string();
            let mut result = (text.len() as u64).to_be_bytes().to_vec();
            result.extend(text.as_bytes());
            Ok(result)
        }
        _ => anyhow::bail!("unknown authorization object binding"),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationExample {
    key_hex: String,
    identity_hex: String,
    ciphertext_base64: Option<String>,
    digest_hex: Option<String>,
}
fn example_key(value: &str) -> anyhow::Result<xcsc::secret::SecretKey<32>> {
    let key: [u8; 32] = crate::products::decode("hex", value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("example key length differs"))?;
    Ok(xcsc::secret::SecretKey::new(key))
}
fn authorization_row(
    p: &Value,
    master: &xcsc::secret::SecretKey<32>,
    identity: &[u8],
    cipher: Option<&[u8]>,
    digest: Option<&[u8]>,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    ensure!(
        identity.len() <= 64
            && cipher
                .is_none_or(|value| value.len() as u64
                    <= number(p, "maximum_ciphertext_bytes").unwrap_or(0))
            && digest.is_none_or(|value| value.len() <= 128),
        "authorization column exceeds bound"
    );
    let binding = uuid_binding(text(p, "binding")?, identity)?;
    if cipher.is_none() && digest.is_none() && p.get("nullable") == Some(&Value::Bool(true)) {
        return Ok(());
    }
    let mut cipher = cipher
        .context("authorization ciphertext is missing")?
        .to_vec();
    if let Some(prefix) = p.get("ciphertext_prefix").and_then(Value::as_str) {
        cipher = cipher
            .strip_prefix(prefix.as_bytes())
            .context("ciphertext prefix differs")?
            .to_vec();
    }
    if let Some(encoding) = p.get("ciphertext_encoding").and_then(Value::as_str) {
        cipher = crate::products::decode(encoding, std::str::from_utf8(&cipher)?)?;
    }
    let plaintext = xcsc::secret_envelope::open_with_domain(
        master,
        text(p, "domain")?.as_bytes(),
        u16::try_from(number(p, "revision")?)?,
        &binding,
        &cipher,
    )?;
    let code = plaintext.expose();
    ensure!(
        code.len() == usize::try_from(number(p, "plaintext_bytes")?)?
            && code
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
        "authorization plaintext violates declared shape"
    );
    if digest.is_none() && p.get("digest_nullable") == Some(&Value::Bool(true)) {
        return Ok(());
    }
    let digest = digest.context("authorization digest is missing")?;
    let actual = Sha256::digest(code);
    ensure!(
        match text(p, "digest_encoding")? {
            "raw" => digest == actual.as_slice(),
            "hex" =>
                digest
                    == actual
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                        .as_bytes(),
            _ => false,
        },
        "authorization ciphertext and digest disagree"
    );
    Ok(())
}
fn authorization_examples(algorithm: &Algorithm) -> anyhow::Result<()> {
    for case in &algorithm.cases {
        let example: AuthorizationExample = serde_json::from_value(case.input.clone())?;
        let valid = (|| {
            let key = example_key(&example.key_hex)?;
            let identity = crate::products::decode("hex", &example.identity_hex)?;
            let cipher = example
                .ciphertext_base64
                .as_ref()
                .map(|value| crate::products::decode("base64", value))
                .transpose()?;
            let digest = example
                .digest_hex
                .as_ref()
                .map(|value| crate::products::decode("hex", value))
                .transpose()?;
            authorization_row(
                &algorithm.parameters,
                &key,
                &identity,
                cipher.as_deref(),
                digest.as_deref(),
            )
        })()
        .is_ok();
        ensure!(
            valid == case.valid,
            "authorization implementation disagrees with its example"
        );
    }
    Ok(())
}
async fn authorization(
    context: &ContextData,
    connection: &mut SqliteConnection,
    algorithm: &Algorithm,
) -> anyhow::Result<()> {
    use futures_util::TryStreamExt;
    let p = &algorithm.parameters;
    let master: [u8; 32] = secret_value(context, text(p, "key_secret")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("authorization key size differs"))?;
    let master = xcsc::secret::SecretKey::new(master);
    let rows = number(p, "maximum_rows")?;
    let bytes = number(p, "maximum_ciphertext_bytes")?;
    ensure!(
        rows > 0 && rows <= 2_000_000 && bytes > 0 && bytes <= 1024 * 1024,
        "authorization bounds exceed tool limits"
    );
    authorization_examples(algorithm)?;
    let query = format!(
        "SELECT CASE WHEN length(CAST(identity AS BLOB))<=64 THEN CAST(identity AS BLOB) END AS identity, CASE WHEN length(CAST(ciphertext AS BLOB))<=? THEN CAST(ciphertext AS BLOB) END AS ciphertext, CASE WHEN length(CAST(digest AS BLOB))<=128 THEN CAST(digest AS BLOB) END AS digest, length(CAST(ciphertext AS BLOB)) AS cipher_bytes, length(CAST(digest AS BLOB)) AS digest_bytes FROM ({}) LIMIT ?",
        text(p, "query")?.trim_end_matches(';')
    );
    let mut stream = sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
        .bind(i64::try_from(bytes)?)
        .bind(i64::try_from(rows + 1)?)
        .fetch(connection);
    let mut count = 0;
    while let Some(row) = stream.try_next().await? {
        count += 1;
        ensure!(count <= rows, "authorization row count exceeds bound");
        let identity = row
            .try_get::<Option<Vec<u8>>, _>("identity")?
            .context("authorization identity missing or oversized")?;
        ensure!(
            row.try_get::<Option<i64>, _>("cipher_bytes")?
                .is_none_or(|value| value >= 0 && value as u64 <= bytes)
                && row
                    .try_get::<Option<i64>, _>("digest_bytes")?
                    .is_none_or(|value| (0..=128).contains(&value)),
            "authorization column exceeds bound"
        );
        let cipher: Option<Vec<u8>> = row.try_get("ciphertext")?;
        let digest: Option<Vec<u8>> = row.try_get("digest")?;
        authorization_row(p, &master, &identity, cipher.as_deref(), digest.as_deref())?;
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationExample {
    key_hex: String,
    operation_id: String,
    action: String,
    target_key: String,
    resource_namespace: String,
    payload_json: String,
    request_fingerprint_hex: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationPayload {
    actor: String,
    request_ciphertext: String,
}
fn operation_row(
    p: &Value,
    key: &xcsc::secret::SecretKey<32>,
    row: &OperationExample,
) -> anyhow::Result<()> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    ensure!(
        row.payload_json.len() as u64 <= number(p, "maximum_payload_bytes")?
            && [
                &row.operation_id,
                &row.action,
                &row.target_key,
                &row.resource_namespace
            ]
            .iter()
            .all(|value| value.len() <= 1024),
        "operation column exceeds bound"
    );
    let payload: OperationPayload = crate::strict_json::decode(row.payload_json.as_bytes())?;
    let _ = &payload.actor;
    let prefix = text(p, "ciphertext_prefix")?;
    let encrypted = crate::products::decode(
        text(p, "ciphertext_encoding")?,
        payload
            .request_ciphertext
            .strip_prefix(prefix)
            .context("request envelope prefix differs")?,
    )?;
    let mut binding = Vec::new();
    for component in p["binding_components"]
        .as_array()
        .context("operation binding components missing")?
    {
        let value = match text(component, "source")? {
            "literal" => text(component, "value")?,
            "operation_id" => &row.operation_id,
            "action" => &row.action,
            _ => anyhow::bail!("unknown operation binding source"),
        };
        binding.extend_from_slice(&(value.len() as u64).to_be_bytes());
        binding.extend_from_slice(value.as_bytes());
    }
    let plaintext = xcsc::secret_envelope::open_with_domain(
        key,
        text(p, "domain")?.as_bytes(),
        u16::try_from(number(p, "revision")?)?,
        &binding,
        &encrypted,
    )?;
    ensure!(
        plaintext.expose().len() as u64 <= number(p, "maximum_plaintext_bytes")?,
        "request plaintext exceeds bound"
    );
    let _ = std::str::from_utf8(plaintext.expose())?;
    let fingerprint = &p["fingerprint"];
    ensure!(
        text(fingerprint, "algorithm")? == "hmac-sha256",
        "unsupported request fingerprint"
    );
    let mut derived = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(
        Some(text(fingerprint, "hkdf_salt")?.as_bytes()),
        key.expose(),
    )
    .expand(text(fingerprint, "hkdf_info")?.as_bytes(), &mut derived)
    .map_err(|_| anyhow::anyhow!("fingerprint key derivation failed"))?;
    let derived = xcsc::secret::SecretKey::new(derived);
    let mut mac = Hmac::<Sha256>::new_from_slice(derived.expose())
        .map_err(|_| anyhow::anyhow!("fingerprint key rejected"))?;
    mac.update(plaintext.expose());
    mac.verify_slice(&crate::products::decode(
        "hex",
        &row.request_fingerprint_hex,
    )?)
    .map_err(|_| anyhow::anyhow!("request fingerprint differs"))?;
    let request: Value = crate::strict_json::decode(plaintext.expose())?;
    ensure!(
        jsonschema::options()
            .should_validate_formats(true)
            .build(p.get("request_schema").context("request schema missing")?)?
            .is_valid(&request),
        "operation request violates generated schema"
    );
    let kind = request
        .pointer(text(p, "action_pointer")?)
        .and_then(Value::as_str)
        .context("command kind missing")?;
    let command = p["commands"]
        .get(kind)
        .context("current command mapping missing")?;
    ensure!(
        text(command, "action")? == row.action,
        "command and stored action disagree"
    );
    let device = request
        .pointer(text(p, "binding_device_pointer")?)
        .and_then(Value::as_str)
        .context("device binding missing")?;
    let installation = request
        .pointer(text(p, "binding_installation_pointer")?)
        .and_then(Value::as_str)
        .context("installation binding missing")?;
    let device = uuid::Uuid::parse_str(device)?.to_string();
    let installation = uuid::Uuid::parse_str(installation)?.to_string();
    ensure!(
        row.target_key == device,
        "operation target and request binding disagree"
    );
    ensure!(
        row.resource_namespace
            == format!(
                "{}.{}.{}.{}",
                text(p, "namespace_prefix")?,
                device,
                installation,
                text(command, "resource_class")?
            ),
        "operation namespace and request binding disagree"
    );
    Ok(())
}
async fn operations(
    context: &ContextData,
    connection: &mut SqliteConnection,
    algorithm: &Algorithm,
) -> anyhow::Result<()> {
    use futures_util::TryStreamExt;
    let p = &algorithm.parameters;
    let rows = number(p, "maximum_rows")?;
    let bytes = number(p, "maximum_payload_bytes")?;
    ensure!(
        rows > 0
            && rows <= 2_000_000
            && bytes > 0
            && bytes <= 4 * 1024 * 1024
            && number(p, "maximum_plaintext_bytes")? <= 1024 * 1024,
        "operation bounds exceed tool limits"
    );
    for case in &algorithm.cases {
        let row: OperationExample = serde_json::from_value(case.input.clone())?;
        let valid = (|| operation_row(p, &example_key(&row.key_hex)?, &row))().is_ok();
        ensure!(
            valid == case.valid,
            "operation implementation disagrees with its example"
        );
    }
    let key = secret_value(context, text(p, "key_secret")?)?;
    let key = xcsc::secret::SecretKey::new(
        <[u8; 32]>::try_from(key).map_err(|_| anyhow::anyhow!("operation key size differs"))?,
    );
    let query = format!(
        "SELECT CASE WHEN length(CAST(operation_id AS BLOB))<=1024 THEN operation_id END AS operation_id, CASE WHEN length(CAST(action AS BLOB))<=1024 THEN action END AS action, CASE WHEN length(CAST(target_key AS BLOB))<=1024 THEN target_key END AS target_key, CASE WHEN length(CAST(resource_namespace AS BLOB))<=1024 THEN resource_namespace END AS resource_namespace, CASE WHEN length(CAST(payload_json AS BLOB))<=? THEN payload_json END AS payload_json, CASE WHEN length(CAST(request_fingerprint AS BLOB))<=64 THEN request_fingerprint END AS request_fingerprint FROM ({}) LIMIT ?",
        text(p, "query")?.trim_end_matches(';')
    );
    let mut stream = sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
        .bind(i64::try_from(bytes)?)
        .bind(i64::try_from(rows + 1)?)
        .fetch(connection);
    let mut count = 0;
    while let Some(row) = stream.try_next().await? {
        count += 1;
        ensure!(count <= rows, "operation row count exceeds bound");
        let row = OperationExample {
            key_hex: String::new(),
            operation_id: row
                .try_get::<Option<String>, _>("operation_id")?
                .context("operation identity missing or oversized")?,
            action: row
                .try_get::<Option<String>, _>("action")?
                .context("operation action missing or oversized")?,
            target_key: row
                .try_get::<Option<String>, _>("target_key")?
                .context("operation target missing or oversized")?,
            resource_namespace: row
                .try_get::<Option<String>, _>("resource_namespace")?
                .context("operation namespace missing or oversized")?,
            payload_json: row
                .try_get::<Option<String>, _>("payload_json")?
                .context("operation payload missing or oversized")?,
            request_fingerprint_hex: row
                .try_get::<Option<String>, _>("request_fingerprint")?
                .context("operation fingerprint missing or oversized")?,
        };
        operation_row(p, &key, &row)?;
    }
    Ok(())
}

pub fn generate_media(
    context: &ContextData,
    media: &Media,
    uid: u32,
    gid: u32,
) -> anyhow::Result<()> {
    crate::media::generate(context, media, uid, gid)
}
pub fn media(context: &ContextData, media: &Media) -> anyhow::Result<()> {
    crate::media::check(context, media)
}
