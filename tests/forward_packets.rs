mod client;

use pnet::datalink;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::checksum;
use std::time::Duration;
use tokio::time;

#[tokio::test]
async fn send_packet() {
    let iface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == "enp0s5")
        .unwrap();
    let (mut tx, _) = match datalink::channel(&iface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type"),
        Err(e) => panic!("error creating channel: {}", e),
    };
    let mut buf = [0u8; 20];

    let mut udp_packet = MutableUdpPacket::new(&mut buf).unwrap();
    udp_packet.set_destination(1111);
    udp_packet.set_source(2222);
    udp_packet.set_length(UdpPacket::minimum_packet_size() as u16);
    let udp_payload = [0x41, 0x42, 0x43, 0x44];
    udp_packet.set_payload(&udp_payload);
    udp_packet.set_length(8);
    udp_packet.set_checksum(checksum(&udp_packet.packet(), 1));

    let mut ip_packet = MutableIpv4Packet::new(udp_packet.packet_mut()).unwrap();
    ip_packet.set_destination([10, 211, 55, 7].into());
    ip_packet.set_source([10, 211, 55, 2].into());
    ip_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);

    loop {
        time::sleep(Duration::from_secs(1)).await;

        match tx.send_to(ip_packet.packet(), Some(iface.clone())) {
            Some(res) => match res {
                Ok(()) => {
                    println!("Sent packet");
                }
                Err(e) => {
                    println!("Failed to send packet: {}", e);
                }
            },
            None => {
                println!("Failed to send packet");
            }
        }
    }

    // let mut client = leaf::client::run().await;
    // packet.set_payload("Hello, world!".to_string());
    // client.send_packet(packet).await;
    // let packet = server.recv_packet().await;
    // assert_eq!(packet.get_payload(), "Hello, world!");
}
