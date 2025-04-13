use byteorder::{BigEndian, ByteOrder, LittleEndian};
use tokio::fs::File;
use tokio::io::{self, AsyncReadExt, BufReader};

#[repr(C)]
#[derive(Debug)]
pub struct PcapHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct PcapPacket {
    pub header: PcapPacketHeader,
    pub data: Vec<u8>,
}


#[repr(C)]
#[derive(Debug)]
pub struct PcapPacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}

pub struct Capture {
    reader: BufReader<File>,
    header: PcapHeader,
    is_big_endian: bool,
}

impl Capture {
    pub async fn from_file(file_path: &str) -> io::Result<Self> {
        let file = File::open(file_path).await?;
        let mut reader = BufReader::new(file);

        // Read magic number
        let mut magic_number_buf = [0u8; 4];
        reader.read_exact(&mut magic_number_buf).await?;
        let magic_number = LittleEndian::read_u32(&magic_number_buf);
        let is_big_endian = match magic_number {
            0xa1b2c3d4 => false,
            0xd4c3b2a1 => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid pcap file",
                ));
            }
        };

        let read_u16 = |buf: &[u8]| -> u16 {
            if is_big_endian {
                BigEndian::read_u16(buf)
            } else {
                LittleEndian::read_u16(buf)
            }
        };

        let read_u32 = |buf: &[u8]| -> u32 {
            if is_big_endian {
                BigEndian::read_u32(buf)
            } else {
                LittleEndian::read_u32(buf)
            }
        };

        // Read header
        let mut header_buf = [0u8; 20];
        reader.read_exact(&mut header_buf).await?;
        let header = PcapHeader {
            magic_number,
            version_major: read_u16(&header_buf[0..2]),
            version_minor: read_u16(&header_buf[2..4]),
            thiszone: LittleEndian::read_i32(&header_buf[4..8]),
            sigfigs: read_u32(&header_buf[8..12]),
            snaplen: read_u32(&header_buf[12..16]),
            network: read_u32(&header_buf[16..20]),
        };

        Ok(Self {
            reader,
            header,
            is_big_endian,
        })
    }

    pub fn header(&self) -> &PcapHeader {
        &self.header
    }

    pub async fn next_packet(&mut self) -> io::Result<Option<PcapPacket>> {
        let read_u32 = |buf: &[u8]| -> u32 {
            if self.is_big_endian {
                BigEndian::read_u32(buf)
            } else {
                LittleEndian::read_u32(buf)
            }
        };

        let mut packet_header_buf = [0u8; 16];
        match self.reader.read_exact(&mut packet_header_buf).await {
            Ok(_) => {
                let packet_header = PcapPacketHeader {
                    ts_sec: read_u32(&packet_header_buf[0..4]),
                    ts_usec: read_u32(&packet_header_buf[4..8]),
                    incl_len: read_u32(&packet_header_buf[8..12]),
                    orig_len: read_u32(&packet_header_buf[12..16]),
                };

                let mut packet_data = vec![0u8; packet_header.incl_len as usize];
                self.reader.read_exact(&mut packet_data).await?;

                Ok(Some(PcapPacket {
                    header: packet_header,
                    data: packet_data,
                }))
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::EthernetPacket;

    use super::Capture;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_capture() {
        let temp_file_path = "test.pcap";
        let mut file = File::create(temp_file_path).await.unwrap();

        // Write fake pcap header
        file.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, // magic number
            0x02, 0x00, // version major
            0x04, 0x00, // version minor
            0x00, 0x00, 0x00, 0x00, // thiszone
            0x00, 0x00, 0x00, 0x00, // sigfigs
            0xff, 0xff, 0x00, 0x00, // snaplen
            0x01, 0x00, 0x00, 0x00, // network
        ])
        .await
        .unwrap();

        // Write fake packet header and data
        file.write_all(&[
            0x5e, 0x2a, 0x2b, 0x2c, // ts_sec
            0x00, 0x00, 0x00, 0x00, // ts_usec
            0x04, 0x00, 0x00, 0x00, // incl_len
            0x04, 0x00, 0x00, 0x00, // orig_len
            0xde, 0xad, 0xbe, 0xef, // packet data
        ])
        .await
        .unwrap();

        let mut capture = Capture::from_file(temp_file_path).await.unwrap();
        let header = capture.header();
        assert_eq!(header.magic_number, 0xa1b2c3d4);

        if let Some(packet) = capture.next_packet().await.unwrap() {
            assert_eq!(packet.header.incl_len, 4);
            assert_eq!(packet.data, vec![0xde, 0xad, 0xbe, 0xef]);
        }

        tokio::fs::remove_file(temp_file_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_tcpdump_file() {
        let temp_file_path = "sample.pcap";
        // Read the pcap file
        let mut capture = Capture::from_file(temp_file_path).await.unwrap();
        let header = capture.header();
        assert_eq!(header.magic_number, 0xa1b2c3d4);
        // Sum packet number
        let mut packet_count = 0;
        while let Some(_) = capture.next_packet().await.unwrap() {
            packet_count += 1;
            // println!("{:?}", packet);
        }
        println!("Total packets: {}", packet_count);
    }

    #[tokio::test]
    async fn test_extract_ethernet() {
        let temp_file_path = "sample.pcap";
        // Read the pcap file
        let mut capture = Capture::from_file(temp_file_path).await.unwrap();
        let header = capture.header();
        assert_eq!(header.magic_number, 0xa1b2c3d4);
        if let Some(raw_packet) = capture.next_packet().await.unwrap() {
            let eth_packet = EthernetPacket::try_from(raw_packet.data.as_slice()).unwrap();
            println!("Ethernet Packet: {:?}", eth_packet);
            println!("Destination MAC: {}", eth_packet.header.dest_mac);
            println!("Source MAC: {}", eth_packet.header.src_mac);
            println!("EtherType: {:?}", eth_packet.header.ether_type);
            println!("Data Length: {}", eth_packet.data.len());
        } else {
            panic!("No Ethernet packet found.");
        }
    }

    #[tokio::test]
    async fn sum_ethernet_type() {
        let temp_file_path = "sample.pcap";
        // Read the pcap file
        let mut capture = Capture::from_file(temp_file_path).await.unwrap();
        let header = capture.header();
        assert_eq!(header.magic_number, 0xa1b2c3d4);
        let mut eth_type_count = std::collections::HashMap::new();
        let mut packet_count = 0;
        while let Some(raw_packet) = capture.next_packet().await.unwrap() {
            let eth_packet = EthernetPacket::try_from(raw_packet.data.as_slice()).unwrap();
            eth_type_count
                .entry(eth_packet.header.ether_type)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            packet_count += 1;
        }
        for (eth_type, count) in eth_type_count {
            println!("EtherType: {:?}, Count: {}", eth_type, count);
        }
        // Print the total number of packets
        println!("Total packets: {}", packet_count);
    }
}
