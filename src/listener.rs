use crate::{Result, SniffOpts};
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, error, info};

pub async fn run(opts: SniffOpts) -> Result<()> {
    let interface = get_interface(&opts.interface)?;

    info!("Listening on interface: {}", interface.name);

    // Open a raw socket on the interface
    let (_, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type"),
        Err(e) => panic!("error creating channel: {}", e),
    };
    let mut sigint = signal(SignalKind::interrupt())?;
    // Loop over incoming frames
    let r = Arc::new(Mutex::new(rx));
    loop {
        let rx_clone = r.clone();
        tokio::select! {
            _ = sigint.recv() => {
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(0)) => {
                handle_receiver(rx_clone);
            }
        }
    }
    Ok(())
}

fn handle_receiver(rx: Arc<Mutex<Box<dyn DataLinkReceiver>>>) {
    let mut rx = rx.lock().unwrap();

    match rx.next() {
        Ok(packet) => {
            let mut destination_port = 0;
            let mut source_port = 0;
            let mut flags = String::from("");

            if let Some(eth) = EthernetPacket::new(packet) {
                match eth.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::new(eth.payload()).unwrap();

                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            destination_port = tcp_packet.get_destination();
                            source_port = tcp_packet.get_source();
                            flags = get_flags(tcp_packet.get_flags());
                        };

                        let packet_protocol = match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => IpNextHeaderProtocols::Tcp.to_string(),
                            IpNextHeaderProtocols::Udp => IpNextHeaderProtocols::Udp.to_string(),
                            unsupported => {
                                debug!("unsupported protocol for ipv4 {:?}", unsupported);
                                unsupported.to_string()
                            }
                        };

                        debug!("ethernet frame wrapped ipv4 packet: {:?}", ipv4_packet);

                        println!(
                            "{} {}:{} -> {}:{} {} - size: {}",
                            packet_protocol,
                            ipv4_packet.get_source().to_string(),
                            source_port,
                            ipv4_packet.get_destination().to_string(),
                            destination_port,
                            flags,
                            ipv4_packet.packet().len(),
                        );
                        return;
                    }
                    EtherTypes::Ipv6 => {
                        let ipv6_packet = Ipv6Packet::new(eth.payload()).unwrap();
                        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                            destination_port = tcp_packet.get_destination();
                            source_port = tcp_packet.get_source();
                            flags = get_flags(tcp_packet.get_flags());
                        };

                        let packet_protocol = match ipv6_packet.get_next_header() {
                            IpNextHeaderProtocols::Tcp => IpNextHeaderProtocols::Tcp.to_string(),
                            IpNextHeaderProtocols::Udp => IpNextHeaderProtocols::Udp.to_string(),
                            unsupported => {
                                debug!("unsupported protocol for ipv6 {:?}", unsupported);
                                unsupported.to_string()
                            }
                        };

                        debug!("ethernet frame wrapped ipv6 packet: {:?}", ipv6_packet);

                        println!(
                            "{} [{}]:{} -> [{}]:{} {} - size: {}",
                            packet_protocol,
                            ipv6_packet.get_source().to_string(),
                            source_port,
                            ipv6_packet.get_destination().to_string(),
                            destination_port,
                            flags,
                            ipv6_packet.packet().len()
                        );
                        return;
                    }
                    // TODO: maybe handle other protocols?
                    _ => return,
                }
            } else {
                error!("failed to parse ethernet packet, skipping...");
            };

            if let Some(ipv4_packet) = Ipv4Packet::new(packet) {
                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                    destination_port = tcp_packet.get_destination();
                    source_port = tcp_packet.get_source();
                    flags = get_flags(tcp_packet.get_flags());
                };

                let packet_protocol = match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => IpNextHeaderProtocols::Tcp.to_string(),
                    IpNextHeaderProtocols::Udp => IpNextHeaderProtocols::Udp.to_string(),
                    unsupported => {
                        debug!("unsupported protocol for ipv4 {:?}", unsupported);
                        unsupported.to_string()
                    }
                };

                debug!("found unwrapped ipv4 tcp packet: {:?}", ipv4_packet);

                println!(
                    "{} {}:{} -> {}:{} {} - size: {}",
                    packet_protocol,
                    ipv4_packet.get_source().to_string(),
                    source_port,
                    ipv4_packet.get_destination().to_string(),
                    destination_port,
                    flags,
                    ipv4_packet.packet().len()
                );
            } else {
                if let Some(ipv6_packet) = Ipv6Packet::new(packet) {
                    if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                        destination_port = tcp_packet.get_destination();
                        source_port = tcp_packet.get_source();
                        flags = get_flags(tcp_packet.get_flags());
                    };

                    let packet_protocol = match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => IpNextHeaderProtocols::Tcp.to_string(),
                        IpNextHeaderProtocols::Udp => IpNextHeaderProtocols::Udp.to_string(),
                        unsupported => {
                            debug!("unsupported protocol for ipv6: {:?}", unsupported);
                            unsupported.to_string()
                        }
                    };

                    debug!("found unwrapped ipv6 tcp packet: {:?}", ipv6_packet);

                    println!(
                        "{} [{}]:{} -> [{}]:{} {} - size: {}",
                        packet_protocol,
                        ipv6_packet.get_source().to_string(),
                        source_port,
                        ipv6_packet.get_destination().to_string(),
                        destination_port,
                        flags,
                        ipv6_packet.packet().len()
                    );
                };
            }
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::Interrupted {
                error!("error reading: {}", e);
            }
        }
    }
}

// perform bitwise operations to determine the flags
fn get_flags(tcp_flags: u16) -> String {
    let mut flags = String::new();
    if tcp_flags & TcpFlags::SYN > 0 {
        flags.push_str("SYN ");
    }
    if tcp_flags & TcpFlags::ACK > 0 {
        flags.push_str("ACK ");
    }
    if tcp_flags & TcpFlags::FIN > 0 {
        flags.push_str("FIN ");
    }
    if tcp_flags & TcpFlags::RST > 0 {
        flags.push_str("RST ");
    }
    if tcp_flags & TcpFlags::PSH > 0 {
        flags.push_str("PSH ");
    }
    if tcp_flags & TcpFlags::URG > 0 {
        flags.push_str("URG ");
    }
    flags
}

fn get_interface(interface: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface)
        .ok_or(format!("No such interface: {interface}").into())
}

pub fn list_interfaces() {
    datalink::interfaces().into_iter().for_each(|i| {
        println!("{}", i);
    });
}
