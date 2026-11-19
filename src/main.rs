use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use nepenthes::config::Config;
use nepenthes::{server, telemetry};

const DEFAULT_CONFIG: &str = "config/server.toml";

fn usage() -> String {
    format!(
        "usage: nepenthes [--config <path>] [--print-default-config]\n\n\
         Starts the tarpit (data plane) and the control plane described in the config.\n\
         Config path defaults to {DEFAULT_CONFIG}; it can also be set with NEPENTHES_CONFIG."
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut explicit: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => match args.next() {
                Some(path) => explicit = Some(PathBuf::from(path)),
                None => bail!("--config needs a path\n\n{}", usage()),
            },
            "--print-default-config" => {
                print!("{}", toml::to_string_pretty(&Config::default())?);
                return Ok(());
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return Ok(());
            }
            other => bail!("unknown argument `{other}`\n\n{}", usage()),
        }
    }

    let explicit = explicit.or_else(|| std::env::var_os("NEPENTHES_CONFIG").map(PathBuf::from));
    let config = match explicit {
        Some(path) => Config::load(&path)?,
        None if Path::new(DEFAULT_CONFIG).exists() => Config::load(Path::new(DEFAULT_CONFIG))?,
        None => {
            eprintln!("note: {DEFAULT_CONFIG} not found, using built-in defaults");
            Config::default()
        }
    };

    telemetry::metrics::init_tracing(&config.telemetry);
    server::run(config).await
}
