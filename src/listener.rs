use crate::{Result, SniffOpts, TLProtocol};
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, error, info};

pub async fn run(opts: SniffOpts) -> Result<()> {
    let interface = get_interface(&opts.interface)?;

    info!("Listening on interface: {}", interface.name);
    info!("NO | Source | Destination | Protocol | Flags | Length | Sequence | Window");

    // Open a raw socket on the interface
    let (_, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type"),
        Err(e) => panic!("error creating channel: {}", e),
    };
    let mut sigint = signal(SignalKind::interrupt())?;
    // Loop over incoming frames
    let r = Arc::new(Mutex::new(rx));
    let mut no = 0;

    loop {
        let rx_clone = r.clone();
        tokio::select! {
            _ = sigint.recv() => {
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(0)) => {
                if let Some(mut packet_info) = handle_receiver(rx_clone){
                   if matches_filter(packet_info.clone(), &opts) {
                    if opts.resolve {
                       packet_info.source_ip = resolve_dns(&packet_info.source_ip);
                       packet_info.destination_ip = resolve_dns(&packet_info.destination_ip);
                    }
                       println!("{}: {}", no, &packet_info);
                   }
                   no += 1;
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PacketInfo {
    source_ip: String,
    destination_ip: String,
    source_port: u16,
    destination_port: u16,
    protocol: IpNextHeaderProtocol,
    flags: String,
    ipv6: bool,
    length: usize,
    sequence: u32,
    window: u16,
}

impl Display for PacketInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.ipv6 {
            write!(
                f,
                "{} [{}]:{} -> [{}]:{}, {} {} [{}  {}] ",
                self.protocol.to_string().to_uppercase(),
                self.source_ip,
                self.source_port,
                self.destination_ip,
                self.destination_port,
                self.flags,
                self.length,
                self.sequence,
                self.window,
            )
        } else {
            write!(
                f,
                "{} {}:{} -> {}:{} {} {} [{} {}]",
                self.protocol.to_string().to_uppercase(),
                self.source_ip,
                self.source_port,
                self.destination_ip,
                self.destination_port,
                self.flags,
                self.length,
                self.sequence,
                self.window,
            )
        }
    }
}

fn handle_receiver(rx: Arc<Mutex<Box<dyn DataLinkReceiver>>>) -> Option<PacketInfo> {
    let mut rx = rx.lock().unwrap();

    match rx.next() {
        Ok(packet) => {
            if let Some(eth) = EthernetPacket::new(packet) {
                match eth.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::new(eth.payload())?;
                        let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;

                        debug!("ethernet frame wrapped ipv4 packet: {:?}", ipv4_packet);

                        return Some(PacketInfo {
                            source_ip: ipv4_packet.get_source().to_string(),
                            destination_ip: ipv4_packet.get_destination().to_string(),
                            source_port: tcp_packet.get_source(),
                            destination_port: tcp_packet.get_destination(),
                            protocol: ipv4_packet.get_next_level_protocol(),
                            flags: get_flags(tcp_packet.get_flags()),
                            ipv6: false,
                            length: tcp_packet.packet().len(),
                            sequence: u32::from_be(tcp_packet.get_sequence()),
                            window: u16::from_be(tcp_packet.get_window()),
                        });
                    }
                    EtherTypes::Ipv6 => {
                        let ipv6_packet = Ipv6Packet::new(eth.payload())?;
                        let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;

                        debug!("ethernet frame wrapped ipv6 packet: {:?}", ipv6_packet);

                        return Some(PacketInfo {
                            source_ip: ipv6_packet.get_source().to_string(),
                            destination_ip: ipv6_packet.get_destination().to_string(),
                            source_port: tcp_packet.get_source(),
                            destination_port: tcp_packet.get_destination(),
                            protocol: ipv6_packet.get_next_header(),
                            flags: get_flags(tcp_packet.get_flags()),
                            ipv6: true,
                            length: tcp_packet.packet().len(),
                            sequence: u32::from_be(tcp_packet.get_sequence()),
                            window: u16::from_be(tcp_packet.get_window()),
                        });
                    }
                    // TODO: maybe handle other protocols?
                    _ => return None,
                }
            } else {
                error!("failed to parse ethernet packet, skipping...");
            };

            if let Some(ipv4_packet) = Ipv4Packet::new(packet) {
                let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;

                debug!("found unwrapped ipv4 tcp packet: {:?}", ipv4_packet);

                return Some(PacketInfo {
                    source_ip: ipv4_packet.get_source().to_string(),
                    destination_ip: ipv4_packet.get_destination().to_string(),
                    source_port: tcp_packet.get_source(),
                    destination_port: tcp_packet.get_destination(),
                    protocol: ipv4_packet.get_next_level_protocol(),
                    flags: get_flags(tcp_packet.get_flags()),
                    ipv6: false,
                    length: tcp_packet.packet().len(),
                    sequence: u32::from_be(tcp_packet.get_sequence()),
                    window: u16::from_be(tcp_packet.get_window()),
                });
            } else {
                let ipv6_packet = Ipv6Packet::new(packet)?;
                let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;

                debug!("found unwrapped ipv6 tcp packet: {:?}", ipv6_packet);
                return Some(PacketInfo {
                    source_ip: ipv6_packet.get_source().to_string(),
                    destination_ip: ipv6_packet.get_destination().to_string(),
                    source_port: tcp_packet.get_source(),
                    destination_port: tcp_packet.get_destination(),
                    protocol: ipv6_packet.get_next_header(),
                    flags: get_flags(tcp_packet.get_flags()),
                    ipv6: true,
                    length: tcp_packet.packet().len(),
                    sequence: u32::from_be(tcp_packet.get_sequence()),
                    window: u16::from_be(tcp_packet.get_window()),
                });
            };
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::Interrupted {
                error!("error reading: {}", e);
            }
            return None;
        }
    }
}

fn matches_filter(packet_info: PacketInfo, opts: &SniffOpts) -> bool {
    if opts.source.is_some() && opts.source.as_ref().unwrap() != &packet_info.source_ip {
        return false;
    }
    if opts.destination.is_some()
        && opts.destination.as_ref().unwrap() != &packet_info.destination_ip
    {
        return false;
    }
    if opts.source_port.is_some() && opts.source_port.unwrap() != packet_info.source_port {
        return false;
    }
    if opts.destination_port.is_some()
        && opts.destination_port.unwrap() != packet_info.destination_port
    {
        return false;
    }

    match opts.protocol {
        TLProtocol::ALL => {
            return true;
        }
        TLProtocol::TCP => {
            if packet_info.protocol != IpNextHeaderProtocols::Tcp {
                return false;
            }
        }
        TLProtocol::UDP => {
            if packet_info.protocol != IpNextHeaderProtocols::Udp {
                return false;
            }
        }
    }
    true
}

fn resolve_dns(ip: &str) -> String {
    if let Ok(ip) = ip.parse::<IpAddr>() {
        if let Ok(hostname) = dns_lookup::lookup_addr(&ip) {
            return hostname;
        }
    }
    ip.to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_flags() {
        assert_eq!(get_flags(0b0000000000000000), "");
        assert_eq!(get_flags(0b0000000000000001), "FIN ");
        assert_eq!(get_flags(0b0000000000000010), "SYN ");
        assert_eq!(get_flags(0b0000000000000011), "SYN FIN ");
        assert_eq!(get_flags(0b0000000000000100), "RST ");
        assert_eq!(get_flags(0b0000000000000101), "RST FIN ");
        assert_eq!(get_flags(0b0000000000000110), "RST SYN ");
        assert_eq!(get_flags(0b0000000000000111), "RST SYN FIN ");
        assert_eq!(get_flags(0b0000000000001000), "PSH ");
        assert_eq!(get_flags(0b0000000000001001), "PSH FIN ");
        assert_eq!(get_flags(0b0000000000001010), "PSH SYN ");
        assert_eq!(get_flags(0b0000000000001011), "PSH SYN FIN ");
        assert_eq!(get_flags(0b0000000000001100), "PSH RST ");
        assert_eq!(get_flags(0b0000000000001101), "PSH RST FIN ");
        assert_eq!(get_flags(0b0000000000001110), "PSH RST SYN ");
        assert_eq!(get_flags(0b0000000000001111), "PSH RST SYN FIN ");
        assert_eq!(get_flags(0b0000000000010000), "ACK ");
        assert_eq!(get_flags(0b0000000000010001), "ACK FIN ");
        assert_eq!(get_flags(0b0000000000010010), "ACK SYN ");
        assert_eq!(get_flags(0b0000000000010011), "ACK SYN FIN ");
        assert_eq!(get_flags(0b0000000000010100), "ACK RST ");
        assert_eq!(get_flags(0b0000000000010101), "ACK RST FIN ");
        assert_eq!(get_flags(0b0000000000010110), "ACK RST SYN ");
        assert_eq!(get_flags(0b0000000000010111), "ACK RST SYN FIN ");
    }

    #[test]
    fn test_matches_filter() {}
}
