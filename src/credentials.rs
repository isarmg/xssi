//! Credential parameters come from the current policy, never a server crate.
use crate::contracts::Credentials;
use anyhow::{Context, ensure};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, SaltString},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub fn normalize(policy: &Credentials, value: &str) -> anyhow::Result<String> {
    let rule = &policy.username;
    ensure!(
        rule.normalization == "ascii-trim-lowercase"
            && rule.reject_ascii_control
            && !value.is_empty()
            && value.len() <= rule.maximum_bytes
            && value.is_ascii()
            && !value.bytes().any(|byte| byte.is_ascii_control()),
        "invalid administrator username"
    );
    let value = value.trim_ascii().to_ascii_lowercase();
    let pattern = regex::RegexBuilder::new(&rule.pattern)
        .size_limit(64 * 1024)
        .nest_limit(32)
        .build()?;
    ensure!(
        (rule.minimum_bytes..=rule.maximum_bytes).contains(&value.len())
            && pattern
                .find(&value)
                .is_some_and(|matched| matched.start() == 0 && matched.end() == value.len()),
        "administrator username violates current policy"
    );
    Ok(value)
}

pub fn validate_password(policy: &Credentials, value: &str) -> anyhow::Result<()> {
    ensure!(
        policy.password.reject_ascii_control
            && (policy.password.minimum_bytes..=policy.password.maximum_bytes)
                .contains(&value.len())
            && !value.bytes().any(|byte| byte.is_ascii_control()),
        "password violates current policy"
    );
    Ok(())
}

fn argon(policy: &Credentials) -> anyhow::Result<Argon2<'static>> {
    let p = &policy.argon2;
    ensure!(
        p.algorithm == "argon2id" && p.version == 19,
        "unsupported current password algorithm"
    );
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            p.memory_kib,
            p.iterations,
            p.parallelism,
            Some(p.output_bytes),
        )
        .map_err(|error| anyhow::anyhow!("invalid current password policy: {error}"))?,
    ))
}

pub fn random(bytes: usize) -> anyhow::Result<Vec<u8>> {
    ensure!(
        (1..=4096).contains(&bytes),
        "random material exceeds its bound"
    );
    let mut value = vec![0; bytes];
    getrandom::fill(&mut value)
        .map_err(|_| anyhow::anyhow!("operating system random source failed"))?;
    Ok(value)
}

pub fn identifier(policy: &Credentials) -> anyhow::Result<String> {
    ensure!(
        policy.administrator_id_format == "base64url-no-pad",
        "unsupported identifier format"
    );
    let value = URL_SAFE_NO_PAD.encode(random(policy.identifier_random_bytes)?);
    ensure!(
        value.len() <= policy.identifier_max_bytes,
        "identifier exceeds policy bound"
    );
    Ok(value)
}

pub fn hash_password(policy: &Credentials, password: &str) -> anyhow::Result<String> {
    validate_password(policy, password)?;
    let salt = SaltString::encode_b64(&random(policy.argon2.salt_bytes)?)
        .map_err(|_| anyhow::anyhow!("salt encoding failed"))?;
    argon(policy)?
        .hash_password(password.as_bytes(), &salt)
        .map(|value| value.to_string())
        .map_err(|_| anyhow::anyhow!("password hashing failed"))
}

pub fn check_hash(policy: &Credentials, value: &str) -> anyhow::Result<()> {
    let hash =
        PasswordHash::new(value).map_err(|_| anyhow::anyhow!("invalid password encoding"))?;
    let p = &policy.argon2;
    let mut salt_bytes = [0u8; 64];
    ensure!(
        hash.algorithm.as_str() == p.algorithm
            && hash.version == Some(p.version)
            && hash.params.as_str()
                == format!("m={},t={},p={}", p.memory_kib, p.iterations, p.parallelism)
            && hash
                .salt
                .and_then(|salt| salt.decode_b64(&mut salt_bytes).ok())
                .is_some_and(|salt| salt.len() == p.salt_bytes)
            && hash
                .hash
                .as_ref()
                .is_some_and(|value| value.len() == p.output_bytes),
        "stored password violates current policy"
    );
    Ok(())
}

pub fn verify_examples(policy: &Credentials) -> anyhow::Result<()> {
    let _ = argon(policy)?;
    ensure!(
        !policy.cases.is_empty(),
        "credential policy lacks validation examples"
    );
    for case in &policy.cases {
        let checked = (|| -> anyhow::Result<String> {
            validate_password(policy, &case.password)?;
            normalize(policy, &case.username)
        })();
        ensure!(
            checked.is_ok() == case.valid,
            "credential implementation disagrees with validation example"
        );
        if case.valid {
            ensure!(
                Some(checked.context("credential example failed")?) == case.normalized_username,
                "username normalization disagrees with validation example"
            );
        }
    }
    Ok(())
}

pub fn verify_password(hash: &str, password: &str) -> anyhow::Result<()> {
    use argon2::{PasswordHash, PasswordVerifier};
    let parsed = PasswordHash::new(hash)
        .map_err(|_| anyhow::anyhow!("creation credential format is invalid"))?;
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| {
            anyhow::anyhow!("initialization credential differs from the original operation")
        })
}
