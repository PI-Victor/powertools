pub mod listener;
pub mod pcap;

use pcap::{PcapFile, PcapHeader, PcapPacket};
use std::path::PathBuf;
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
    /// Interface to listen on
    #[structopt(short = "if", long)]
    pub interface: String,
    /// Filter by protocol
    #[structopt(short, long, possible_values = TLProtocol::variants(), case_insensitive = true, default_value = "ALL")]
    pub protocol: TLProtocol,
    /// Filter by source IP address
    #[structopt(long)]
    pub source: Option<String>,
    /// Filter by source port
    #[structopt(long)]
    pub source_port: Option<u16>,
    /// Filter by destination IP address
    #[structopt(long)]
    pub destination: Option<String>,
    /// Filter by destination port
    #[structopt(short, long)]
    pub destination_port: Option<u16>,
    /// Will try to resolve IP addresses to hostnames
    #[structopt(short, long)]
    pub resolve: bool,
    /// Turns promiscuous mode on
    #[structopt(long)]
    promiscuous: bool,
    /// Save captured packets to a pcap file
    #[structopt(short, long)]
    pub output: Option<PathBuf>,
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
        match s.to_uppercase().as_str() {
            "TCP" => Ok(TLProtocol::TCP),
            "UDP" => Ok(TLProtocol::UDP),
            "ALL" => Ok(TLProtocol::ALL),
            _ => Err(format!("Invalid protocol: {s}")),
        }
    }
}
