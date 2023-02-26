pub mod server;

use std::str::FromStr;
use structopt::StructOpt;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, StructOpt)]
pub enum SubCommands {
    Sniff(SniffOpts),
}

#[derive(Debug, StructOpt)]
pub struct SniffOpts {
    #[structopt(short = "if", long)]
    pub interface: String,
    #[structopt(long)]
    pub ip: Option<String>,
    #[structopt(short, long)]
    pub port: Option<u16>,
}

#[derive(Debug, StructOpt)]
pub enum TLProtocol {
    ALL,
    TCP,
    UDP,
}

impl TLProtocol {
    pub fn variants() -> &'static [&'static str] {
        &["TCP", "UDP", "ALL"]
    }
}

impl FromStr for TLProtocol {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "TCP" => Ok(TLProtocol::TCP),
            "UDP" => Ok(TLProtocol::UDP),
            "ALL" => Ok(TLProtocol::ALL),
            _ => Err(format!("Invalid protocol: {}", s)),
        }
    }
}
