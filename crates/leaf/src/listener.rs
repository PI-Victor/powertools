use crate::{Result, SniffOpts, TLProtocol};
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, error};

pub async fn run(opts: SniffOpts) -> Result<()> {
    let interface = get_interface(&opts.interface)?;

    println!("Listening on interface: {}\n", interface.name);
    println!("NO | Source | Destination | Protocol | Flags | Length | Sequence | Window\n");
    println!("--------------------------------------------------------------------------------\n");

    // Open a raw socket on the interface
    let (_, rx) = match datalink::channel(
        &interface,
        datalink::Config {
            promiscuous: opts.promiscuous,
            ..Default::default()
        },
    ) {
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
                    // TODO: Find a better solution, if the packet is filtered
                    // out, it should not be resolved, this adds dns overhead
                    if opts.resolve {
                       packet_info.source = resolve_dns(&packet_info.source);
                       packet_info.destination = resolve_dns(&packet_info.destination);
                    }

                   if matches_filter(packet_info.clone(), &opts) {
                       println!("{no}: {}", &packet_info);
                   }
                   no += 1;
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PacketInfo<T> {
    source: String,
    source_port: u16,
    destination: String,
    destination_port: u16,
    protocol: T,
    flags: String,
    ipv6: bool,
    length: usize,
    sequence: u32,
    window: u16,
}

impl<T: fmt::Display> Display for PacketInfo<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.ipv6 {
            write!(
                f,
                "{} [{}]:{} -> [{}]:{}, {} {} [{}  {}] ",
                self.protocol.to_string().to_uppercase(),
                self.source,
                self.source_port,
                self.destination,
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
                self.source,
                self.source_port,
                self.destination,
                self.destination_port,
                self.flags,
                self.length,
                self.sequence,
                self.window,
            )
        }
    }
}

fn handle_receiver<T>(rx: Arc<Mutex<Box<dyn DataLinkReceiver>>>) -> Option<PacketInfo<T>> {
    let mut rx = rx.lock().unwrap();

    match rx.next() {
        Ok(packet) => {
            if let Some(eth) = EthernetPacket::new(packet) {
                match eth.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::new(eth.payload())?;
                        let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;

                        debug!("ethernet frame wrapped ipv4 packet: {:?}", ipv4_packet);

                        return Some(new_packet_v4_info(&tcp_packet, &ipv4_packet));
                    }
                    EtherTypes::Ipv6 => {
                        let ipv6_packet = Ipv6Packet::new(eth.payload())?;
                        let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;

                        debug!("ethernet frame wrapped ipv6 packet: {:?}", ipv6_packet);

                        return Some(new_packet_v6_info(&tcp_packet, &ipv6_packet));
                    }
                    // TODO: maybe handle other protocols?
                    EtherTypes::Aarp => {
                        let arp_packet = ArpPacket::new(eth.payload())?;
                    }
                    _ => (),
                }
            } else {
                error!("failed to parse ethernet packet, skipping...");
            };

            if let Some(ipv4_packet) = Ipv4Packet::new(packet) {
                let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;

                debug!("found unwrapped ipv4 tcp packet: {:?}", ipv4_packet);

                return Some(new_packet_v4_info(&tcp_packet, &ipv4_packet));
            } else {
                let ipv6_packet = Ipv6Packet::new(packet)?;
                let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;

                debug!("found unwrapped ipv6 tcp packet: {:?}", ipv6_packet);
                return Some(new_packet_v6_info(&tcp_packet, &ipv6_packet));
            };
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::Interrupted {
                error!("error reading: {e}");
            }
            return None;
        }
    }
}

fn new_packet_v4_info<T>(tcp_packet: &TcpPacket, ipv4_packet: &Ipv4Packet) -> PacketInfo<T> {
    PacketInfo {
        source: ipv4_packet.get_source().to_string(),
        destination: ipv4_packet.get_destination().to_string(),
        source_port: tcp_packet.get_source(),
        destination_port: tcp_packet.get_destination(),
        protocol: ipv4_packet.get_next_level_protocol(),
        flags: get_flags(tcp_packet.get_flags()),
        ipv6: false,
        length: tcp_packet.packet().len(),
        sequence: u32::from_be(tcp_packet.get_sequence()),
        window: u16::from_be(tcp_packet.get_window()),
    }
}

fn new_packet_v6_info<T>(tcp_packet: &TcpPacket, ipv6_packet: &Ipv6Packet) -> PacketInfo<T> {
    PacketInfo {
        source: ipv6_packet.get_source().to_string(),
        destination: ipv6_packet.get_destination().to_string(),
        source_port: tcp_packet.get_source(),
        destination_port: tcp_packet.get_destination(),
        protocol: ipv6_packet.get_next_header(),
        flags: get_flags(tcp_packet.get_flags()),
        ipv6: true,
        length: tcp_packet.packet().len(),
        sequence: u32::from_be(tcp_packet.get_sequence()),
        window: u16::from_be(tcp_packet.get_window()),
    }
}

fn new_arp_packet<T>(arp_packet: &ArpPacket, ethernet_packet: &EthernetPacket) -> PacketInfo<T> {
    PacketInfo {
        source: ethernet_packet.get_source().to_string(),
        destination: ethernet_packet.get_destination().to_string(),
        source_port: 0,
        destination_port: 0,
        protocol: arp_packet.get_protocol_type(),
        flags: String::new(),
        ipv6: false,
        length: arp_packet.packet().len(),
        sequence: 0,
        window: 0,
    }
}

fn matches_filter<T>(packet_info: PacketInfo<T>, opts: &SniffOpts) -> bool {
    if opts.port_filter.contains(&packet_info.source_port)
        || opts.port_filter.contains(&packet_info.destination_port)
    {
        return false;
    }
    if let Some(source) = &opts.source {
        if source != &packet_info.source {
            return false;
        }
    }
    if let Some(destination) = &opts.destination {
        if destination != &packet_info.destination {
            return false;
        }
    }
    if let Some(source_port) = opts.source_port {
        if source_port != packet_info.source_port || opts.port_filter.contains(&source_port) {
            return false;
        }
    }
    if let Some(destination_port) = opts.destination_port {
        if destination_port != packet_info.destination_port
            || opts.port_filter.contains(&destination_port)
        {
            return false;
        }
    }

    match opts.protocol {
        TLProtocol::ALL => true,
        TLProtocol::TCP => packet_info.protocol == IpNextHeaderProtocols::Tcp,
        TLProtocol::UDP => packet_info.protocol == IpNextHeaderProtocols::Udp,
        TLProtocol::ICMP => packet_info.protocol == IpNextHeaderProtocols::Icmp,
    }
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
    if tcp_flags & TcpFlags::FIN > 0 {
        flags.push_str("FIN ");
    }
    if tcp_flags & TcpFlags::SYN > 0 {
        flags.push_str("SYN ");
    }
    if tcp_flags & TcpFlags::RST > 0 {
        flags.push_str("RST ");
    }
    if tcp_flags & TcpFlags::PSH > 0 {
        flags.push_str("PSH ");
    }
    if tcp_flags & TcpFlags::ACK > 0 {
        flags.push_str("ACK ");
    }
    if tcp_flags & TcpFlags::URG > 0 {
        flags.push_str("URG ");
    }
    if tcp_flags & TcpFlags::ECE > 0 {
        flags.push_str("ECE ");
    }
    if tcp_flags & TcpFlags::CWR > 0 {
        flags.push_str("CWR ");
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
        println!("{i}");
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
        assert_eq!(get_flags(0b0000000000000011), "FIN SYN ");
        assert_eq!(get_flags(0b0000000000000100), "RST ");
        assert_eq!(get_flags(0b0000000000000101), "FIN RST ");
        assert_eq!(get_flags(0b0000000000000110), "SYN RST ");
        assert_eq!(get_flags(0b0000000000000111), "FIN SYN RST ");
        assert_eq!(get_flags(0b0000000000001000), "PSH ");
        assert_eq!(get_flags(0b0000000000001001), "FIN PSH ");
        assert_eq!(get_flags(0b0000000000001010), "SYN PSH ");
        assert_eq!(get_flags(0b0000000000001011), "FIN SYN PSH ");
        assert_eq!(get_flags(0b0000000000001100), "RST PSH ");
        assert_eq!(get_flags(0b0000000000001101), "FIN RST PSH ");
        assert_eq!(get_flags(0b0000000000001110), "SYN RST PSH ");
        assert_eq!(get_flags(0b0000000000001111), "FIN SYN RST PSH ");
        assert_eq!(get_flags(0b0000000000010000), "ACK ");
        assert_eq!(get_flags(0b0000000000010001), "FIN ACK ");
        assert_eq!(get_flags(0b0000000000010010), "SYN ACK ");
        assert_eq!(get_flags(0b0000000000010011), "FIN SYN ACK ");
        assert_eq!(get_flags(0b0000000000010100), "RST ACK ");
        assert_eq!(get_flags(0b0000000000010101), "FIN RST ACK ");
        assert_eq!(get_flags(0b0000000000010110), "SYN RST ACK ");
        assert_eq!(get_flags(0b0000000000010111), "FIN SYN RST ACK ");
    }
}
