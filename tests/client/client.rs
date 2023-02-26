pub struct LeafClient {
    pub name: String,
    pub iface: String,
}

pub struct Packet<'a> {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl LeafClient {
    pub fn new(name: String, iface: String) -> Self {
        Self { name, iface }
    }
}
