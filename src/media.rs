//! Finite generated companion definitions, using mature PEM and process tools.
use crate::contracts::{Algorithm, ContextData, Media, PathSpec};
use anyhow::{Context, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    kind: String,
    value: String,
    prefix: String,
    suffix: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Substitution {
    source: Source,
    encoding: String,
}
fn text<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .context("companion parameter text missing")
}
fn number(value: &Value, key: &str) -> anyhow::Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .context("companion bound missing")
}
fn source(context: &ContextData, spec: &Source) -> anyhow::Result<String> {
    let scalar = |pointer: &str| -> anyhow::Result<String> {
        match context
            .value
            .pointer(pointer)
            .context("companion config source missing")?
        {
            Value::String(value) => Ok(value.clone()),
            Value::Number(_) | Value::Bool(_) => {
                Ok(context.value.pointer(pointer).unwrap().to_string())
            }
            _ => anyhow::bail!("companion config source must be scalar"),
        }
    };
    let value = match spec.kind.as_str() {
        "root" => {
            ensure!(
                spec.value.is_empty(),
                "root source cannot have an extra value"
            );
            context
                .root
                .to_str()
                .context("root must be UTF8")?
                .to_owned()
        }
        "literal" => spec.value.clone(),
        "config" => scalar(&spec.value)?,
        "url-host" => url::Url::parse(&scalar(&spec.value)?)?
            .host_str()
            .context("companion URL host missing")?
            .to_owned(),
        "resource" => {
            let raw = serde_json::to_value(&context.contract)?;
            let path: PathSpec = serde_json::from_value(
                raw.pointer(&spec.value)
                    .context("companion resource pointer missing")?
                    .clone(),
            )?;
            context
                .path(&path)?
                .to_str()
                .context("resource must be UTF8")?
                .to_owned()
        }
        "secret" => {
            let (name, field) = spec
                .value
                .split_once('.')
                .context("secret source must name field")?;
            let definition = context
                .contract
                .secrets
                .iter()
                .find(|secret| secret.name == name)
                .context("secret definition missing")?;
            ensure!(
                definition.format == "json",
                "text secret source must use JSON"
            );
            let raw: Value = crate::strict_json::decode(&crate::contracts::read(
                &context.path(&definition.path)?,
                64 * 1024,
            )?)?;
            raw.get(field)
                .and_then(Value::as_str)
                .context("text secret source missing")?
                .to_owned()
        }
        _ => anyhow::bail!("unknown companion source"),
    };
    Ok(format!("{}{}{}", spec.prefix, value, spec.suffix))
}
fn expected(context: &ContextData, value: &Value) -> anyhow::Result<String> {
    if let Some(value) = value.as_str() {
        Ok(value.into())
    } else {
        source(context, &serde_json::from_value(value.clone())?)
    }
}
pub fn render(context: &ContextData, media: &Media) -> anyhow::Result<Vec<u8>> {
    let template = String::from_utf8(context.asset(&media.template)?)?;
    render_content(context, media, &template, true)
}
fn render_content(
    context: &ContextData,
    media: &Media,
    template: &str,
    require_all: bool,
) -> anyhow::Result<Vec<u8>> {
    let definitions = media
        .substitutions
        .as_object()
        .context("companion substitutions must be map")?;
    let token = regex::Regex::new(r"@@[A-Z0-9_]+@@")?;
    let mut values = BTreeMap::new();
    for (name, raw) in definitions {
        ensure!(
            token
                .find(name)
                .is_some_and(|matched| matched.start() == 0 && matched.end() == name.len()),
            "companion token is not canonical"
        );
        ensure!(
            template.matches(name).count() <= 1
                && (!require_all || template.matches(name).count() == 1),
            "companion token must occur exactly once"
        );
        let definition: Substitution = serde_json::from_value(raw.clone())?;
        let value = source(context, &definition.source)?;
        ensure!(
            !value.contains("@@"),
            "companion value cannot inject a template token"
        );
        let value = match definition.encoding.as_str() {
            "plain" => value,
            "json-string" => serde_json::to_string(&value)?,
            _ => anyhow::bail!("unknown companion substitution encoding"),
        };
        values.insert(name.as_str(), value);
    }
    let mut output = String::new();
    let mut position = 0;
    for matched in token.find_iter(template) {
        output.push_str(&template[position..matched.start()]);
        output.push_str(
            values
                .get(matched.as_str())
                .context("undeclared companion token")?,
        );
        position = matched.end();
    }
    output.push_str(&template[position..]);
    ensure!(
        !output.contains("@@"),
        "companion template contains an unexpanded token"
    );
    Ok(output.into_bytes())
}
fn yaml(context: &ContextData, p: &Value, content: &str) -> anyhow::Result<()> {
    let values = |key: &str| -> Vec<&str> {
        let prefix = format!("{key}:");
        content
            .lines()
            .filter_map(|line| line.trim().strip_prefix(&prefix).map(str::trim))
            .collect()
    };
    for (key, value) in p["scalars"]
        .as_object()
        .context("managed companion scalars missing")?
    {
        let values = values(key);
        ensure!(values.len() == 1, "managed scalar missing or duplicated");
        ensure!(
            values[0].trim_matches(['\'', '"']) == expected(context, value)?,
            "managed scalar differs"
        );
    }
    let record = &p["record_path"];
    let configured = values(text(record, "key")?);
    ensure!(configured.len() == 1, "record path missing or duplicated");
    let decoded: String = if configured[0].starts_with('"') {
        crate::strict_json::decode(configured[0].as_bytes())?
    } else {
        configured[0].trim_matches('\'').into()
    };
    let separator = text(record, "separator")?;
    let (root, suffix) = decoded
        .split_once(separator)
        .context("record path placeholder missing")?;
    ensure!(
        !suffix.is_empty()
            && !suffix.contains("%path")
            && suffix
                .split('/')
                .all(|part| !matches!(part, "" | "." | "..")),
        "record path suffix invalid"
    );
    let raw = serde_json::to_value(&context.contract)?;
    let spec: PathSpec = serde_json::from_value(
        raw.pointer(text(record, "resource")?)
            .context("record resource missing")?
            .clone(),
    )?;
    ensure!(
        Path::new(root) == context.path(&spec)?,
        "record path root differs"
    );
    Ok(())
}
fn environment_values(content: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (key, input) = line
            .split_once('=')
            .context("environment requires key=value")?;
        let value =
            if let Some(quoted) = input.strip_prefix('"') {
                let quoted = quoted
                    .strip_suffix('"')
                    .context("environment quote unterminated")?;
                let mut value = String::new();
                let mut chars = quoted.chars();
                while let Some(character) = chars.next() {
                    if character == '\\' {
                        let escaped = chars.next().context("environment escape incomplete")?;
                        ensure!(matches!(escaped, '\\' | '"'), "unknown environment escape");
                        value.push(escaped);
                    } else {
                        ensure!(character != '"', "environment quote unescaped");
                        value.push(character);
                    }
                }
                value
            } else {
                ensure!(
                    !input.chars().any(|character| character.is_whitespace()
                        || matches!(character, '"' | '\\' | '\'')),
                    "invalid unquoted environment value"
                );
                input.to_owned()
            };
        ensure!(
            result.insert(key.to_owned(), value).is_none(),
            "environment key duplicated"
        );
    }
    Ok(result)
}
fn duration(p: &Value, value: &str) -> anyhow::Result<()> {
    let allow_plus = p.get("allow_plus").map_or(Ok(false), |value| {
        value
            .as_bool()
            .context("duration plus policy must be boolean")
    })?;
    let value = if allow_plus {
        value.strip_prefix('+').unwrap_or(value)
    } else {
        value
    };
    if value == "0" {
        return Ok(());
    }
    ensure!(
        !value.is_empty() && value.len() <= 256,
        "duration text exceeds bound"
    );
    let mut remaining = value;
    let mut first = true;
    let mut total = 0u128;
    let units = p["units"].as_array().context("duration units missing")?;
    ensure!(units.len() <= 32, "duration units exceed bound");
    while !remaining.is_empty() {
        let end = remaining
            .char_indices()
            .find(|(_, character)| !character.is_ascii_digit() && *character != '.')
            .map_or(remaining.len(), |(index, _)| index);
        let number = &remaining[..end];
        remaining = &remaining[end..];
        ensure!(!number.is_empty(), "duration component missing");
        let unit = units
            .iter()
            .find(|unit| {
                unit.get("unit")
                    .and_then(Value::as_str)
                    .is_some_and(|unit| remaining.starts_with(unit))
            })
            .context("unknown duration unit")?;
        let suffix = text(unit, "unit")?;
        ensure!(!suffix.is_empty(), "duration unit empty");
        remaining = &remaining[suffix.len()..];
        if unit.get("days") == Some(&Value::Bool(true)) {
            ensure!(
                first && !number.contains('.'),
                "day duration must be first integer"
            );
        }
        first = false;
        let scale = u128::from(number_value(unit, "scale_ns")?);
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        ensure!(
            !whole.is_empty() || !fraction.is_empty(),
            "duration number missing"
        );
        ensure!(
            fraction.bytes().all(|byte| byte.is_ascii_digit()),
            "duration fraction invalid"
        );
        let whole = if whole.is_empty() {
            0
        } else {
            whole.parse::<u128>()?
        };
        let fraction = &fraction[..fraction.len().min(18)];
        let part = if fraction.is_empty() {
            0
        } else {
            fraction
                .parse::<u128>()?
                .checked_mul(scale)
                .context("duration overflow")?
                / 10u128.pow(u32::try_from(fraction.len())?)
        };
        total = total
            .checked_add(whole.checked_mul(scale).context("duration overflow")?)
            .and_then(|value| value.checked_add(part))
            .context("duration overflow")?;
        ensure!(
            total <= text(p, "maximum_ns")?.parse::<u128>()?,
            "duration exceeds native range"
        );
    }
    ensure!(
        total == 0 || total >= text(p, "minimum_nonzero_ns")?.parse::<u128>()?,
        "duration shorter than supported segment"
    );
    Ok(())
}
fn number_value(value: &Value, key: &str) -> anyhow::Result<u64> {
    number(value, key)
}
fn environment(context: &ContextData, p: &Value, content: &str) -> anyhow::Result<()> {
    ensure!(
        content.len() as u64 <= number(p, "maximum_bytes")?,
        "environment exceeds bound"
    );
    let values = environment_values(content)?;
    validate_environment_values(context, p, &values)
}
fn validate_environment_values(
    context: &ContextData,
    p: &Value,
    values: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let definitions = p["keys"]
        .as_object()
        .context("environment key definitions missing")?;
    ensure!(
        values.len() == definitions.len() && definitions.keys().all(|key| values.contains_key(key)),
        "environment key set differs"
    );
    for (key, definition) in definitions {
        let value = &values[key];
        ensure!(
            !value.is_empty() && !value.chars().any(char::is_control),
            "environment text invalid"
        );
        match text(definition, "kind")? {
            "text" => {}
            "literal" | "path" => ensure!(
                *value
                    == expected(
                        context,
                        definition
                            .get("value")
                            .context("environment expected source missing")?
                    )?,
                "environment value differs"
            ),
            "socket" => {
                let value = if value.starts_with(':') {
                    format!("0.0.0.0{value}")
                } else {
                    value.clone()
                };
                let socket: std::net::SocketAddr = value.parse()?;
                ensure!(socket.port() != 0, "environment socket port missing");
            }
            "host-list" => {
                let case_insensitive =
                    definition
                        .get("case_insensitive")
                        .map_or(Ok(false), |value| {
                            value
                                .as_bool()
                                .context("hostname case policy must be boolean")
                        })?;
                for host in value.split(',') {
                    ensure!(
                        !host.is_empty() && !host.chars().any(char::is_whitespace),
                        "environment host invalid"
                    );
                    if host.parse::<std::net::IpAddr>().is_err() {
                        let url = url::Url::parse(&format!("https://{host}"))?;
                        ensure!(
                            url.host_str().is_some_and(|actual| if case_insensitive {
                                actual.eq_ignore_ascii_case(host)
                            } else {
                                actual == host
                            }) && url.username().is_empty()
                                && url.password().is_none()
                                && url.port().is_none()
                                && url.path() == "/"
                                && url.query().is_none()
                                && url.fragment().is_none(),
                            "environment hostname invalid"
                        );
                    }
                }
            }
            "duration" => duration(&p["duration"], value)?,
            _ => anyhow::bail!("unknown environment validator"),
        }
    }
    Ok(())
}
fn contract(p: &Value, value: &Value) -> anyhow::Result<()> {
    let content = text(value, "contract")?;
    ensure!(
        content.len() <= 16 * 1024,
        "companion contract exceeds bound"
    );
    let mut fields = BTreeMap::new();
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (key, value) = line
            .split_once('=')
            .context("companion contract line invalid")?;
        ensure!(
            matches!(key, "version" | "platform" | "sha256")
                && fields.insert(key, value.trim()).is_none(),
            "companion contract field unknown or duplicated"
        );
    }
    ensure!(
        fields.len() == 3
            && fields["version"] == text(p, "version")?
            && fields["platform"] == text(p, "platform")?,
        "companion identity differs"
    );
    let digest = fields["sha256"].to_ascii_lowercase();
    ensure!(
        digest.len() == 64
            && crate::products::decode("hex", &digest)?.len() == 32
            && digest == text(value, "binary_sha256")?
            && text(value, "stdout")?.trim() == fields["version"],
        "companion bytes or observed version differ"
    );
    Ok(())
}
fn pair(certificate: &str, key: &str, maximum: u64) -> anyhow::Result<()> {
    ensure!(
        maximum <= 64 * 1024 && certificate.len() as u64 <= maximum && key.len() as u64 <= maximum,
        "PEM input exceeds bound"
    );
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .prefix("xssi-media-check-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let cert = directory.path().join("certificate.pem");
    let private = directory.path().join("key.pem");
    crate::filesystem::create(&cert, certificate.as_bytes())?;
    crate::filesystem::create(&private, key.as_bytes())?;
    let certificate = crate::subprocess::bounded(
        Path::new("/usr/bin/openssl"),
        &[
            "x509".into(),
            "-in".into(),
            cert.to_str().context("certificate path missing")?.into(),
            "-pubkey".into(),
            "-noout".into(),
        ],
        3,
        64 * 1024,
    )?;
    let key = crate::subprocess::bounded(
        Path::new("/usr/bin/openssl"),
        &[
            "pkey".into(),
            "-in".into(),
            private.to_str().context("key path missing")?.into(),
            "-pubout".into(),
        ],
        3,
        64 * 1024,
    )?;
    ensure!(
        certificate == key,
        "certificate and private key do not match"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedPairCase {
    fixture: String,
    relationship: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiteralPairCase {
    certificate_pem: String,
    key_pem: String,
}

fn pem_case(input: &Value, maximum: u64) -> anyhow::Result<bool> {
    ensure!(maximum <= 64 * 1024, "PEM example bound exceeds limit");
    if input.get("fixture").is_none() {
        let literal: LiteralPairCase = serde_json::from_value(input.clone())?;
        return Ok(pair(&literal.certificate_pem, &literal.key_pem, maximum).is_ok());
    }
    let generated: GeneratedPairCase = serde_json::from_value(input.clone())?;
    ensure!(
        generated.fixture == "openssl-generated-p256-keypair-v1"
            && matches!(generated.relationship.as_str(), "matching" | "mismatched"),
        "unknown generated PEM example"
    );
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .prefix("xssi-generated-pem-case-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let generate = |name: &str| -> anyhow::Result<(String, String)> {
        let certificate = directory.path().join(format!("{name}-certificate.pem"));
        let private = directory.path().join(format!("{name}-key.pem"));
        // OpenSSL truncates these exclusive 0600 files, preserving their mode.
        crate::filesystem::create(&certificate, b"")?;
        crate::filesystem::create(&private, b"")?;
        crate::subprocess::bounded(
            Path::new("/usr/bin/openssl"),
            &[
                "req".into(),
                "-x509".into(),
                "-newkey".into(),
                "ec".into(),
                "-pkeyopt".into(),
                "ec_paramgen_curve:P-256".into(),
                "-noenc".into(),
                "-keyout".into(),
                private
                    .to_str()
                    .context("fixture path must be UTF8")?
                    .into(),
                "-out".into(),
                certificate
                    .to_str()
                    .context("fixture path must be UTF8")?
                    .into(),
                "-subj".into(),
                "/CN=xssi-generated-contract-fixture".into(),
                "-days".into(),
                "1".into(),
            ],
            3,
            64 * 1024,
        )?;
        for path in [&certificate, &private] {
            let information = std::fs::symlink_metadata(path)?;
            use std::os::unix::fs::MetadataExt;
            ensure!(
                information.is_file()
                    && information.nlink() == 1
                    && information.permissions().mode() & 0o7777 == 0o600,
                "generated PEM example permissions differ"
            );
        }
        Ok((
            String::from_utf8(crate::contracts::read(&certificate, maximum)?)?,
            String::from_utf8(crate::contracts::read(&private, maximum)?)?,
        ))
    };
    let (certificate, key) = generate("first")?;
    let key = if generated.relationship == "mismatched" {
        generate("second")?.1
    } else {
        key
    };
    Ok(pair(&certificate, &key, maximum).is_ok())
}

fn verify_cases(
    algorithm: &Algorithm,
    mut valid: impl FnMut(&crate::contracts::AlgorithmCase) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    ensure!(
        !algorithm.cases.is_empty() && algorithm.cases.iter().any(|case| case.valid),
        "companion semantic examples missing"
    );
    for case in &algorithm.cases {
        ensure!(
            valid(case)? == case.valid,
            "companion semantics disagree with example {}",
            case.name
        );
    }
    Ok(())
}

fn cases(context: &ContextData, algorithm: &Algorithm) -> anyhow::Result<()> {
    let p = &algorithm.parameters;
    let keys = |value: &Value, allowed: &[&str]| -> anyhow::Result<()> {
        let values = value
            .as_object()
            .context("companion parameters must be an object")?;
        ensure!(
            values.keys().all(|key| allowed.contains(&key.as_str())),
            "unknown companion parameter"
        );
        Ok(())
    };
    match algorithm.kind.as_str() {
        "media-yaml-v1" => {
            keys(p, &["scalars", "record_path"])?;
            keys(&p["record_path"], &["key", "resource", "separator"])?;
        }
        "environment-v1" => {
            keys(
                p,
                &["env_path", "keys", "defaults", "duration", "maximum_bytes"],
            )?;
            keys(
                &p["duration"],
                &["units", "minimum_nonzero_ns", "maximum_ns", "allow_plus"],
            )?;
            for unit in p["duration"]["units"]
                .as_array()
                .context("duration units missing")?
            {
                keys(unit, &["unit", "scale_ns", "days"])?;
                ensure!(
                    unit["days"].is_boolean()
                        && (1..=1_000_000_000_000_000_000).contains(&number(unit, "scale_ns")?),
                    "unsupported duration unit scale or policy"
                );
            }
            for value in p["keys"]
                .as_object()
                .context("environment validators missing")?
                .values()
            {
                match text(value, "kind")? {
                    "literal" | "path" => keys(value, &["kind", "value"])?,
                    "host-list" => keys(value, &["kind", "case_insensitive"])?,
                    "socket" | "duration" | "text" => keys(value, &["kind"])?,
                    _ => anyhow::bail!("unknown environment validator"),
                }
            }
        }
        "companion-contract-v1" => keys(
            p,
            &[
                "version",
                "platform",
                "version_arguments",
                "maximum_output_bytes",
                "timeout_seconds",
            ],
        )?,
        "pem-keypair-v1" => keys(p, &["certificate", "key", "maximum_bytes"])?,
        _ => anyhow::bail!("required companion algorithm unknown"),
    }
    verify_cases(algorithm, |case| {
        let valid = match algorithm.kind.as_str() {
            "media-yaml-v1" => {
                let input = case
                    .input
                    .as_str()
                    .context("YAML example must be text")?
                    .replace("$ROOT", context.root.to_str().context("root UTF8 missing")?);
                let media = context
                    .contract
                    .media
                    .as_ref()
                    .context("media definition missing")?;
                let rendered = render_content(context, media, &input, false)?;
                yaml(
                    context,
                    &algorithm.parameters,
                    std::str::from_utf8(&rendered)?,
                )
                .is_ok()
            }
            "environment-v1" => {
                let input = case
                    .input
                    .as_str()
                    .context("environment example must be text")?;
                if input.len() as u64 > number(&algorithm.parameters, "maximum_bytes")? {
                    false
                } else {
                    environment_values(input)
                        .and_then(|mut values| {
                            for value in values.values_mut() {
                                *value = value.replace(
                                    "$ROOT",
                                    context.root.to_str().context("root UTF8 missing")?,
                                );
                            }
                            validate_environment_values(context, &algorithm.parameters, &values)
                        })
                        .is_ok()
                }
            }
            "companion-contract-v1" => contract(&algorithm.parameters, &case.input).is_ok(),
            "pem-keypair-v1" => {
                pem_case(&case.input, number(&algorithm.parameters, "maximum_bytes")?)?
            }
            _ => anyhow::bail!("required companion algorithm unknown"),
        };
        Ok(valid)
    })
}
pub fn examples(context: &ContextData, media: &Media) -> anyhow::Result<()> {
    ensure!(
        !media.validation.is_empty(),
        "companion current validation definitions missing"
    );
    for algorithm in &media.validation {
        cases(context, algorithm)?;
    }
    Ok(())
}

pub fn generate(context: &ContextData, media: &Media, _uid: u32, gid: u32) -> anyhow::Result<()> {
    let mut pending = BTreeMap::new();
    for algorithm in &media.validation {
        if algorithm.kind == "environment-v1" {
            let spec: PathSpec = serde_json::from_value(algorithm.parameters["env_path"].clone())?;
            let path = context.path(&spec)?;
            if !path.try_exists()? {
                let mut output = String::new();
                for (key, value) in algorithm.parameters["defaults"]
                    .as_object()
                    .context("environment defaults missing")?
                {
                    let value = expected(context, value)?;
                    ensure!(
                        !value.chars().any(char::is_control),
                        "environment default control text"
                    );
                    output.push_str(key);
                    output.push_str("=\"");
                    output.push_str(&value.replace('\\', "\\\\").replace('"', "\\\""));
                    output.push_str("\"\n");
                }
                environment(context, &algorithm.parameters, &output)?;
                pending.insert(path, output.into_bytes());
            }
        }
    }
    let path = context.path(&media.configuration_path)?;
    if !crate::creation::active() || !path.try_exists()? {
        pending.insert(path, render(context, media)?);
    }
    // Validate the complete proposed configuration, including retained inputs,
    // before replacing any administrator-owned configuration file.
    check_pending(context, media, &pending)?;
    for (path, bytes) in pending {
        crate::filesystem::configuration(&path, &bytes, gid)?;
    }
    Ok(())
}
pub fn check(context: &ContextData, media: &Media) -> anyhow::Result<()> {
    check_pending(context, media, &BTreeMap::new())
}
fn check_pending(
    context: &ContextData,
    media: &Media,
    pending: &BTreeMap<std::path::PathBuf, Vec<u8>>,
) -> anyhow::Result<()> {
    let read = |path: &Path, maximum: u64| -> anyhow::Result<Vec<u8>> {
        if let Some(bytes) = pending.get(path) {
            ensure!(
                bytes.len() as u64 <= maximum,
                "companion input exceeds bound"
            );
            Ok(bytes.clone())
        } else {
            crate::contracts::read(path, maximum)
        }
    };
    ensure!(
        !media.validation.is_empty(),
        "companion current validation definitions missing"
    );
    for algorithm in &media.validation {
        cases(context, algorithm)?;
        let p = &algorithm.parameters;
        match algorithm.kind.as_str() {
            "media-yaml-v1" => yaml(
                context,
                p,
                std::str::from_utf8(&read(
                    &context.path(&media.configuration_path)?,
                    1024 * 1024,
                )?)?,
            )?,
            "environment-v1" => {
                let spec: PathSpec = serde_json::from_value(p["env_path"].clone())?;
                environment(
                    context,
                    p,
                    std::str::from_utf8(&read(
                        &context.path(&spec)?,
                        number(p, "maximum_bytes")?,
                    )?)?,
                )?;
            }
            "pem-keypair-v1" => {
                let cert: PathSpec = serde_json::from_value(p["certificate"].clone())?;
                let key: PathSpec = serde_json::from_value(p["key"].clone())?;
                pair(
                    std::str::from_utf8(&read(
                        &context.path(&cert)?,
                        number(p, "maximum_bytes")?,
                    )?)?,
                    std::str::from_utf8(&read(&context.path(&key)?, number(p, "maximum_bytes")?)?)?,
                    number(p, "maximum_bytes")?,
                )?;
            }
            "companion-contract-v1" => {
                let arguments: Vec<String> =
                    serde_json::from_value(p["version_arguments"].clone())?;
                ensure!(
                    arguments == ["--version"],
                    "companion can only perform version probe"
                );
                let output = crate::subprocess::bounded(
                    &context.package.join(&media.binary.path),
                    &arguments,
                    number(p, "timeout_seconds")?,
                    usize::try_from(number(p, "maximum_output_bytes")?)?,
                )?;
                contract(
                    p,
                    &serde_json::json!({"contract":String::from_utf8(context.asset(&media.contract)?)?,"stdout":String::from_utf8(output)?,"binary_sha256":media.binary.sha256}),
                )?;
            }
            _ => anyhow::bail!("required companion semantic algorithm unknown"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn generation_fixture(root: &Path) -> ContextData {
        use serde_json::json;
        let path = json!({"base":"root","value":"config/media.yml","fallback":null,"suffix":"","encoding":"path"});
        let asset = json!({"path":"template.yml","sha256":""});
        let mut context = ContextData {
            contract: serde_json::from_value(json!({
                "contract_version":1,
                "identity":{"product":"xcos","version":"1.0.0","source_revision":"a".repeat(40),"target":"linux-x86_64","state_contract_sha256":"a".repeat(64)},
                "schema_identity":{"application":"xcos","application_version":"1.0.0","schema_revision":1,"schema_sha256":"a".repeat(64)},
                "authority_sources":[],
                "config":{"schema":{},"defaults":{},"data_dir":path,"bind_pointer":"/bind","rules":[],"cases":[]},
                "credentials":{"policy_revision":1,"username":{"normalization":"none","minimum_bytes":1,"maximum_bytes":32,"pattern":".*","reject_ascii_control":true},"password":{"minimum_bytes":1,"maximum_bytes":32,"reject_ascii_control":true},"argon2":{"algorithm":"argon2id","version":19,"memory_kib":8,"iterations":1,"parallelism":1,"output_bytes":32,"salt_bytes":16},"administrator_query":"","session_query":"","administrator_id_format":"","identifier_max_bytes":32,"identifier_random_bytes":16,"session_digest_bytes":32,"maximum_session_rows":1,"cases":[]},
                "databases":[],"secrets":[],"writers":[],
                "resources":{"state_paths":[],"writable_paths":[],"readonly_paths":[],"shared_paths":[],"business_paths":[],"config_write_paths":[],"private_directories":[],"business_directories":[],"runtime_locks":[]},
                "media":{"configuration_path":path,"template":asset,"substitutions":{},"binary":asset,"contract":asset,"validation":[{
                    "kind":"environment-v1","description":"fixture environment",
                    "parameters":{"env_path":{"base":"root","value":"config/media.env","fallback":null,"suffix":"","encoding":"path"},"maximum_bytes":1024,"keys":{"REQUIRED":{"kind":"literal","value":"yes"}},"defaults":{"REQUIRED":"yes"},"duration":{"units":[],"minimum_nonzero_ns":"1","maximum_ns":"100","allow_plus":false}},
                    "cases":[{"name":"valid","input":"REQUIRED=yes","valid":true},{"name":"missing-key","input":"","valid":false}]
                }]}
            })).unwrap(),
            package: root.into(), root: root.into(), config_path:root.join("config/config.json"), value:json!({}), data_dir:root.join("state"),
        };
        std::fs::create_dir(root.join("config")).unwrap();
        let template = b"new generated configuration\n";
        std::fs::write(root.join("template.yml"), template).unwrap();
        use sha2::Digest;
        context.contract.media.as_mut().unwrap().template.sha256 = sha2::Sha256::digest(template)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        context
    }

    #[test]
    fn regeneration_rejects_retained_invalid_environment_before_publication() {
        let temporary = tempfile::tempdir().unwrap();
        let context = generation_fixture(temporary.path());
        let media = context.contract.media.as_ref().unwrap();
        let target = context.path(&media.configuration_path).unwrap();
        std::fs::write(&target, b"original configuration").unwrap();
        std::fs::write(temporary.path().join("config/media.env"), b"WRONG=yes").unwrap();
        // A non-root fixture cannot publish administrator-owned files. Reaching
        // the content error proves rejection precedes that publication boundary.
        let error = generate(&context, media, 1000, 1000).unwrap_err();
        assert!(
            error.to_string().contains("environment key set differs"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(target).unwrap(), b"original configuration");
    }

    #[test]
    fn regeneration_rejects_mismatched_pem_before_publication() {
        use serde_json::json;
        let temporary = tempfile::tempdir().unwrap();
        let mut context = generation_fixture(temporary.path());
        for name in ["first", "second"] {
            let certificate = temporary.path().join(format!("config/{name}.pem"));
            let key = temporary.path().join(format!("config/{name}.key"));
            crate::subprocess::bounded(
                Path::new("/usr/bin/openssl"),
                &[
                    "req".into(),
                    "-x509".into(),
                    "-newkey".into(),
                    "ec".into(),
                    "-pkeyopt".into(),
                    "ec_paramgen_curve:P-256".into(),
                    "-noenc".into(),
                    "-keyout".into(),
                    key.to_str().unwrap().into(),
                    "-out".into(),
                    certificate.to_str().unwrap().into(),
                    "-subj".into(),
                    "/CN=fixture".into(),
                    "-days".into(),
                    "1".into(),
                ],
                3,
                65536,
            )
            .unwrap();
        }
        let certificate =
            std::fs::read_to_string(temporary.path().join("config/first.pem")).unwrap();
        let key = std::fs::read_to_string(temporary.path().join("config/first.key")).unwrap();
        context.contract.media.as_mut().unwrap().validation.push(serde_json::from_value(json!({
            "kind":"pem-keypair-v1","description":"fixture pair",
            "parameters":{"maximum_bytes":65536,
                "certificate":{"base":"root","value":"config/first.pem","fallback":null,"suffix":"","encoding":"path"},
                "key":{"base":"root","value":"config/second.key","fallback":null,"suffix":"","encoding":"path"}},
            "cases":[{"name":"matching","valid":true,"input":{"certificate_pem":certificate,"key_pem":key}}]
        })).unwrap());
        let media = context.contract.media.as_ref().unwrap();
        let target = context.path(&media.configuration_path).unwrap();
        std::fs::write(&target, b"original configuration").unwrap();
        std::fs::write(temporary.path().join("config/media.env"), b"REQUIRED=yes").unwrap();
        let error = generate(&context, media, 1000, 1000).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("certificate and private key do not match"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"original configuration");
        let environment = temporary.path().join("config/media.env");
        std::fs::remove_file(&environment).unwrap();
        let error = generate(&context, media, 1000, 1000).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("certificate and private key do not match"),
            "{error:#}"
        );
        assert!(
            !environment.exists(),
            "invalid PEM must not publish default environment"
        );
        assert_eq!(std::fs::read(target).unwrap(), b"original configuration");
    }

    #[test]
    fn candidate_defaults_validate_without_publishing_missing_environment() {
        let temporary = tempfile::tempdir().unwrap();
        let context = generation_fixture(temporary.path());
        let media = context.contract.media.as_ref().unwrap();
        let environment = temporary.path().join("config/media.env");
        let pending = BTreeMap::from([(environment.clone(), b"REQUIRED=yes".to_vec())]);
        check_pending(&context, media, &pending).unwrap();
        assert!(!environment.exists());
        assert!(check_pending(&context, media, &BTreeMap::new()).is_err());
    }

    #[test]
    fn candidate_yaml_can_repair_invalid_existing_yaml() {
        use serde_json::json;
        let temporary = tempfile::tempdir().unwrap();
        let mut context = generation_fixture(temporary.path());
        context.contract.resources.business_paths.push(
            serde_json::from_value(json!({
                "base":"root","value":"recordings","fallback":null,"suffix":"","encoding":"path"
            }))
            .unwrap(),
        );
        let candidate = format!(
            "managed: yes\nrecordPath: \"{}/recordings/%path/date\"\n",
            temporary.path().display()
        );
        context.contract.media.as_mut().unwrap().validation.push(serde_json::from_value(json!({
            "kind":"media-yaml-v1","description":"fixture YAML",
            "parameters":{"scalars":{"managed":"yes"},"record_path":{"key":"recordPath","resource":"/resources/business_paths/0","separator":"/%path/"}},
            "cases":[{"name":"valid","valid":true,"input":candidate}]
        })).unwrap());
        let media = context.contract.media.as_ref().unwrap();
        let target = context.path(&media.configuration_path).unwrap();
        std::fs::write(&target, b"broken YAML").unwrap();
        std::fs::write(temporary.path().join("config/media.env"), b"REQUIRED=yes").unwrap();
        assert!(check(&context, media).is_err());
        check_pending(
            &context,
            media,
            &BTreeMap::from([(target.clone(), candidate.into_bytes())]),
        )
        .unwrap();
        assert_eq!(std::fs::read(target).unwrap(), b"broken YAML");
    }

    #[test]
    fn current_pem_contract_examples_generate_matching_and_distinct_keys() {
        let mut algorithm: Algorithm = serde_json::from_value(serde_json::json!({
            "kind":"pem-keypair-v1", "description":"Current ephemeral contract examples",
            "parameters":{"maximum_bytes":65536}, "cases":[
                {"name":"current-matching-keypair","valid":true,"input":{"fixture":"openssl-generated-p256-keypair-v1","relationship":"matching"}},
                {"name":"distinct-private-key","valid":false,"input":{"fixture":"openssl-generated-p256-keypair-v1","relationship":"mismatched"}},
                {"name":"invalid-certificate","valid":false,"input":{"certificate_pem":"not a PEM certificate","key_pem":"not a PEM private key"}},
                {"name":"missing-certificate","valid":false,"input":{"certificate_pem":"","key_pem":"not a PEM private key"}},
                {"name":"missing-key","valid":false,"input":{"certificate_pem":"not a PEM certificate","key_pem":""}}
            ]
        })).unwrap();
        verify_cases(&algorithm, |case| pem_case(&case.input, 65536)).unwrap();
        algorithm.cases.retain(|case| !case.valid);
        assert!(verify_cases(&algorithm, |case| pem_case(&case.input, 65536)).is_err());
    }

    #[test]
    fn generated_pem_examples_reject_unknown_or_changed_contracts() {
        for input in [
            serde_json::json!({"fixture":"unknown","relationship":"matching"}),
            serde_json::json!({"fixture":"openssl-generated-p256-keypair-v1","relationship":"unknown"}),
            serde_json::json!({"fixture":"openssl-generated-p256-keypair-v1","relationship":"matching","command":"untrusted"}),
            serde_json::json!({"fixture":"openssl-generated-p256-keypair-v1"}),
            serde_json::json!({"certificate_pem":"invalid","key_pem":"invalid","fixture":null}),
            serde_json::json!({"certificate_pem":"invalid","key_pem":"invalid","extra":true}),
        ] {
            assert!(pem_case(&input, 65536).is_err());
        }
        assert!(pem_case(&serde_json::json!({"fixture":"openssl-generated-p256-keypair-v1","relationship":"matching"}), 65537).is_err());
        let algorithm: Algorithm = serde_json::from_value(serde_json::json!({
            "kind":"pem-keypair-v1", "description":"Incorrect positive example",
            "parameters":{"maximum_bytes":65536}, "cases":[
                {"name":"mismatch-is-valid","valid":true,"input":{"fixture":"openssl-generated-p256-keypair-v1","relationship":"mismatched"}}
            ]
        })).unwrap();
        assert!(verify_cases(&algorithm, |case| pem_case(&case.input, 65536)).is_err());
    }
}
