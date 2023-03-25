use leaf::listener;
use leaf::listener::run;
use leaf::{Result, SubCommands};
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt, Clone)]
struct Opts {
    #[structopt(short, long, default_value = "info", env = "LEAF_LOG_LEVEL")]
    log_level: String,
    #[structopt(subcommand)]
    subcommand: SubCommands,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::from_args();
    // set tracing log level from opts
    let log_level = tracing::Level::from_str(&opts.log_level).map_err(|_| "Invalid log level")?;
    tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(log_level)
        .init();

    match opts.subcommand {
        SubCommands::Sniff(sniff_opts) => run(sniff_opts).await?,
        SubCommands::Interfaces(_) => listener::list_interfaces(),
    }

    Ok(())
}
