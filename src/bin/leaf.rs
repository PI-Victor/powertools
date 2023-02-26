use leaf::server::run;
use leaf::SubCommands;
use leaf::{Result, TLProtocol};
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short, long, default_value = "info", env = "LEAF_LOG_LEVEL")]
    log_level: String,
    #[structopt(long,  possible_values = &TLProtocol::variants(), case_insensitive = true, default_value = "ALL")]
    pub protocol: TLProtocol,
    #[structopt(long, default_value = "1000", env = "LEAF_INTERVAL")]
    interval: u64,
    #[structopt(long, default_value = "0", env = "LEAF_DURATION")]
    duration: u64,
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
        SubCommands::Sniff(sniff_opts) => run(sniff_opts, opts.protocol).await?,
    }

    Ok(())
}
