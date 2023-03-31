use crate::Result;
use std::path::Path;
use tokio::fs::File;

// Pcap file format
//                      1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     0 |                          Magic Number                         |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     4 |          Major Version        |         Minor Version         |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     8 |      Reserved1 - ThisZone - GMT to local correction           |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    12 |      Reserved2 - sigfigs - Accuracy of timestamps             |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    16 |                            SnapLen                            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    20 | FCS |f|                   LinkType                            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
pub struct PcapFile {
    pub file: File,
    pub header: PcapHeader,
    pub packets: Vec<PcapPacket>,
}

#[derive(Debug)]
pub struct PcapHeader {
    pub magic_number: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub reserved1: u32,
    pub reserved2: u32,
    pub snaplen: u32,
    pub linktype: u32,
}

impl PcapFile {
    pub async fn new(path: impl AsRef<Path>) -> Result<PcapFile> {
        let file = File::open(path).await?;
        let header = PcapHeader {
            magic_number: 0xa1b2c3d4,
            major_version: 0,
            minor_version: 0,
            reserved1: 0,
            reserved2: 0,
            snaplen: 0,
            linktype: 0,
        };

        Ok(PcapFile {
            file,
            header,
            packets: Vec::new(),
        })
    }
}

// Infile packet format
//                           1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     0 |                      Timestamp (Seconds)                      |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     4 |            Timestamp (Microseconds or nanoseconds)            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     8 |                    Captured Packet Length                     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    12 |                    Original Packet Length                     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    16 /                                                               /
//       /                          Packet Data                          /
//       /                        variable length                        /
//       /                                                               /
//       +---------------------------------------------------------------+
#[derive(Debug)]
pub struct PcapPacket {}
