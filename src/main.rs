#![deny(unsafe_code)]
#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
compile_error!("xssi supports only x86_64-unknown-linux-gnu");
#[cfg(test)]
mod contract_tests;
mod contracts;
mod creation;
mod credentials;
mod database;
mod filesystem;
mod media;
mod products;
mod strict_json;
mod subprocess;
mod validation;

use anyhow::{Context, ensure};
use clap::{Parser, Subcommand};
use std::{io::Read, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "setup",
    version,
    about = "SHA256-bound current installation definitions and independent offline maintenance"
)]
struct Cli {
    #[arg(long)]
    product: String,
    #[arg(long)]
    root: PathBuf,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    tool_lock_fd: Option<i32>,
    #[arg(long, global = true)]
    service_uid: Option<u32>,
    #[arg(long, global = true)]
    service_gid: Option<u32>,
    #[arg(long, global = true)]
    instance_lock_fd: Vec<String>,
    #[arg(long, global = true)]
    operation_id: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    ValidateCredentials {
        #[arg(long, default_value = "admin")]
        username: String,
    },
    ConfigValidate,
    #[command(hide = true)]
    Initialize {
        #[arg(long, default_value = "admin")]
        username: String,
    },
    Check,
    AdminReset {
        #[arg(long)]
        username: String,
    },
    RegenerateMedia,
}

fn password() -> anyhow::Result<xcsc::secret::SecretString> {
    let mut bytes = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "password input exceeds its bound");
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    ensure!(
        !bytes.iter().any(|byte| matches!(byte, b'\r' | b'\n')),
        "password must be one line"
    );
    Ok(xcsc::secret::SecretString::new(
        String::from_utf8(bytes).context("password input must be UTF-8")?,
    ))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return std::process::ExitCode::SUCCESS;
            }
            println!(
                "{}",
                serde_json::json!({"error":{"code":"INVALID_ARGUMENT","message":"Invalid offline tool arguments.","retryable":false}})
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let operation = match &cli.command {
        Command::ValidateCredentials { .. } => "validate-credentials",
        Command::ConfigValidate => "config-validate",
        Command::Initialize { .. } => "initialize",
        Command::Check => "check",
        Command::AdminReset { .. } => "admin-reset",
        Command::RegenerateMedia => "regenerate-media",
    };
    match execute(cli).await {
        Ok(value) => {
            println!("{value}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            // Context errors are fixed diagnostic text, while chained causes
            // may contain library input values and are intentionally omitted.
            let diagnostic = error.to_string();
            let diagnostic: String = diagnostic
                .chars()
                .filter(|ch| !ch.is_control())
                .take(160)
                .collect();
            eprintln!("offline {operation} failed: {diagnostic}");
            println!(
                "{}",
                serde_json::json!({"error":{"code":"OFFLINE_OPERATION_FAILED","message":"Verify current installation definitions, tool authority, permissions and stopped writers.","retryable":false}})
            );
            std::process::ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> anyhow::Result<serde_json::Value> {
    let _machine_output = cli.json; // JSON is also the default for these internal helpers.
    contracts::normalized(&cli.root)?;
    let config = cli
        .config
        .clone()
        .unwrap_or_else(|| cli.root.join("config/config.json"));
    ensure!(
        config == cli.root.join("config/config.json"),
        "config must identify ROOT/config/config.json"
    );
    let pure_credentials = matches!(cli.command, Command::ValidateCredentials { .. });
    let _lock = if pure_credentials {
        cli.tool_lock_fd
            .map(|fd| filesystem::tool_lock(&cli.root, fd))
            .transpose()?
    } else {
        Some(filesystem::tool_lock(
            &cli.root,
            cli.tool_lock_fd
                .context("installation tool lock is required")?,
        )?)
    };
    let context = products::context(
        &cli.product,
        &cli.root,
        &config,
        matches!(
            cli.command,
            Command::Initialize { .. } | Command::ValidateCredentials { .. }
        ),
    )?;
    let service = if matches!(
        cli.command,
        Command::Initialize { .. }
            | Command::AdminReset { .. }
            | Command::RegenerateMedia
            | Command::Check
    ) {
        Some(service_identity(&cli)?)
    } else {
        None
    };
    let credential = if matches!(
        cli.command,
        Command::Initialize { .. }
            | Command::AdminReset { .. }
            | Command::ValidateCredentials { .. }
    ) {
        Some(password()?)
    } else {
        None
    };
    let creation = if let Command::Initialize { username } = &cli.command {
        let (uid, gid) = service.context("initializer identity missing")?;
        let password = credential
            .as_ref()
            .context("initializer credential missing")?;
        credentials::validate_password(&context.contract.credentials, password.expose())?;
        let username = credentials::normalize(&context.contract.credentials, username)?;
        Some(creation::Session::begin(
            &context,
            cli.operation_id
                .as_deref()
                .context("initialization operation ID required")?,
            uid,
            gid,
            &username,
            password.expose(),
        )?)
    } else {
        ensure!(
            cli.operation_id.is_none(),
            "only initialization accepts an operation ID"
        );
        None
    };
    let instances = if let Some((uid, gid)) = service {
        filesystem::instances(
            &context,
            uid,
            gid,
            &cli.instance_lock_fd,
            matches!(cli.command, Command::Initialize { .. }),
        )?
    } else {
        ensure!(
            cli.instance_lock_fd.is_empty(),
            "this command does not accept runtime descriptors"
        );
        filesystem::InstanceLocks::empty()
    };
    if let Some(session) = &creation
        && !session.complete()?
    {
        session.clean_partial()?;
        products::precheck_initialize(&context)?;
    }
    let result = match cli.command {
        Command::ValidateCredentials { username } => {
            let password = credential.as_ref().context("credential missing")?;
            credentials::validate_password(&context.contract.credentials, password.expose())?;
            let username = credentials::normalize(&context.contract.credentials, &username)?;
            Ok(
                serde_json::json!({"product":cli.product,"username":username,"status":"credentials_valid"}),
            )
        }
        Command::ConfigValidate => context.report(false),
        Command::Check => {
            let (uid, gid) = service.context("check identity missing")?;
            products::check(&context, uid, gid).await
        }
        Command::Initialize { username } => {
            let (uid, gid) = service.context("write identity missing")?;
            if !creation
                .as_ref()
                .context("creation scope missing")?
                .complete()?
            {
                products::initialize(
                    &context,
                    &username,
                    credential.as_ref().context("credential missing")?.expose(),
                    uid,
                    gid,
                )
                .await?;
            }
            products::check(&context, uid, gid).await
        }
        Command::AdminReset { username } => {
            let (uid, gid) = service.context("write identity missing")?;
            products::reset(
                &context,
                &username,
                credential.as_ref().context("credential missing")?.expose(),
                uid,
                gid,
            )
            .await?;
            products::check(&context, uid, gid).await
        }
        Command::RegenerateMedia => {
            let (uid, gid) = service.context("write identity missing")?;
            let media = context
                .contract
                .media
                .as_ref()
                .context("product has no media configuration")?;
            validation::generate_media(&context, media, uid, gid)?;
            products::check(&context, uid, gid).await
        }
    }?;
    instances.verify()?;
    if let Some(session) = creation {
        session.finish()?;
    }
    Ok(result)
}

fn service_identity(cli: &Cli) -> anyhow::Result<(u32, u32)> {
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "offline writes require the administrator tool"
    );
    let uid = cli.service_uid.context("service UID missing")?;
    let gid = cli.service_gid.context("service GID missing")?;
    ensure!(
        uid > 0 && gid > 0 && uid < u32::MAX && gid < u32::MAX,
        "service identity must be non-root"
    );
    Ok((uid, gid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn current_helper_arguments_are_unambiguous() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from([
            "setup",
            "--product",
            "xocs",
            "--root",
            "/srv/fixture",
            "--json",
            "--service-uid",
            "65534",
            "--service-gid",
            "65534",
            "--tool-lock-fd",
            "8",
            "check",
        ])
        .unwrap();
        assert_eq!(cli.tool_lock_fd, Some(8));
        assert!(cli.json);
        assert!(
            Cli::try_parse_from([
                "setup",
                "--product",
                "xocs",
                "--root",
                "/srv/fixture",
                "migrate"
            ])
            .is_err()
        );
    }
}
