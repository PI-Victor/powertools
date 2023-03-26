pub mod listener;

use std::str::FromStr;
use structopt::StructOpt;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, StructOpt, Clone)]
pub enum SubCommands {
    Sniff(SniffOpts),
    Interfaces(InterfacesOpt),
}

#[derive(Debug, StructOpt, Clone)]
pub struct SniffOpts {
    #[structopt(short = "if", long)]
    pub interface: String,
    #[structopt(short, long, possible_values = TLProtocol::variants(), case_insensitive = true, default_value = "ALL")]
    pub protocol: TLProtocol,
    #[structopt(long)]
    pub source: Option<String>,
    #[structopt(long)]
    pub source_port: Option<u16>,
    #[structopt(long)]
    pub destination: Option<String>,
    #[structopt(short, long)]
    pub destination_port: Option<u16>,
    /// Will try to resolve IP addresses to hostnames
    #[structopt(short, long)]
    pub resolve: bool,
    #[structopt(long)]
    promiscuous: bool,
}

#[derive(Debug, StructOpt, Clone)]
pub struct InterfacesOpt {
    #[structopt(short, long)]
    pub list: bool,
}

#[derive(Debug, StructOpt, Clone)]
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
