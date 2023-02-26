use crate::{Result, SniffOpts, TLProtocol};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info};

pub async fn run(opts: SniffOpts, protocol: TLProtocol) -> Result<()> {
    let interface = check_interface(opts.interface)?;

    info!("Listening on interface: {}", interface.name);

    // Open a raw socket on the interface
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type"),
        Err(e) => panic!("error creating channel: {}", e),
    };
    let mut stats_summary = Summary {
        packets: HashMap::new(),
    };
    let mut sigint = signal(SignalKind::interrupt())?;
    // Loop over incoming packets
    loop {
        tokio::select! {
                    _ = sigint.recv() => {
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
        match rx.next() {
                    Ok(packet) => {
                        // Parse the Ethernet packet

                        let ethernet = match EthernetPacket::new(packet) {
                            Some(ethernet) => ethernet,
                            None => {
                                error!("failed to parse ethernet packet");
                                continue;
                            }
                        };

                        // Parse the IPv4 packet
                        let ipv4 = if let Some(ipv4) = Ipv4Packet::new(ethernet.packet()) {
                            ipv4
                        } else {
                            error!("failed to parse ipv4 packet");
                            continue;
                        };

                        match ipv4.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ipv4.packet()) {
                                    if let TLProtocol::TCP | TLProtocol::ALL = protocol {
                                        stats_summary.upsert(
                                            tcp.get_source().to_string(),
                                            tcp.get_destination().to_string(),
                                            IpNextHeaderProtocols::Tcp,
                                            tcp.packet().len(),
                                        );
                                    }
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ipv4.packet()) {
                                    if let TLProtocol::UDP | TLProtocol::ALL = protocol {
                                        stats_summary.upsert(
                                            udp.get_source().to_string(),
                                            udp.get_destination().to_string(),
                                            IpNextHeaderProtocols::Udp,
                                            udp.packet().len(),
                                        );
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => info!("error receiving packet: {}", e),
                }
                    }
                }
    }
    Ok(())
}

fn check_interface(interface: String) -> Result<NetworkInterface> {
    // Get the first available interface
    datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface)
        .ok_or(format!("No such interface: {}", interface).into())
}

struct Summary {
    packets: HashMap<(String, String), PacketSummary>,
}

impl Summary {
    fn upsert(
        &mut self,
        source: String,
        destination: String,
        protocol: IpNextHeaderProtocol,
        total_bytes: usize,
    ) {
        self.packets
            .entry((source, destination))
            .and_modify(|e| {
                e.total += total_bytes;
            })
            .or_insert(PacketSummary {
                protocol: protocol.to_string(),
                total: total_bytes,
            });
    }
}

struct PacketSummary {
    protocol: String,
    total: usize,
}
