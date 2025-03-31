use core::fmt;
use std::hash::Hash;

/// Mac Address
/// Represents a MAC address in a human-readable format.
/// The MAC address is represented as a string in the format "XX:XX:XX:XX:XX:XX"
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl From<[u8; 6]> for MacAddress {
    fn from(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }
}

impl Into<[u8; 6]> for MacAddress {
    fn into(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Ethernet Type
/// Represents the EtherType field in an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EtherType {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::IPv6,
            _ => EtherType::Unknown(value),
        }
    }
}

impl Into<u16> for EtherType {
    fn into(self) -> u16 {
        match self {
            EtherType::IPv4 => 0x0800,
            EtherType::ARP => 0x0806,
            EtherType::IPv6 => 0x86DD,
            EtherType::Unknown(value) => value,
        }
    }
}

/// Ethernet header
/// contains the source and destination MAC addresses, as well as the EtherType.
#[repr(C)]
#[derive(Debug)]
pub struct EthernetHeader {
    pub dest_mac: MacAddress,
    pub src_mac: MacAddress,
    pub ether_type: EtherType,
}

/// Ethernet Packet
/// contains a header and data as a [u8] array.
#[repr(C)]
#[derive(Debug)]
pub struct EthernetPacket {
    pub header: EthernetHeader,
    pub data: Vec<u8>,
}

impl TryFrom<&[u8]> for EthernetPacket {
    type Error = &'static str;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 14 {
            return Err("Data too short for Ethernet packet");
        }

        let dest_mac = MacAddress([data[0], data[1], data[2], data[3], data[4], data[5]]);
        let src_mac = MacAddress([data[6], data[7], data[8], data[9], data[10], data[11]]);
        let ether_type = match (data[12], data[13]) {
            (0x08, 0x00) => EtherType::IPv4,
            (0x08, 0x06) => EtherType::ARP,
            (0x86, 0xDD) => EtherType::IPv6,
            _ => EtherType::Unknown(u16::from(data[12]) << 8 | u16::from(data[13])),
        };

        Ok(EthernetPacket {
            header: EthernetHeader {
                dest_mac,
                src_mac,
                ether_type,
            },
            data: Vec::from(&data[14..]),
        })
    }
}

/// IPv4 Packet
/// Represents an IPv4 packet with a header and payload.
#[repr(C)]
#[derive(Debug)]
pub struct IPv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: [u8; 4],
    pub dest_ip: [u8; 4],
    pub payload: Vec<u8>,
}

impl TryFrom<&[u8]> for IPv4Packet {
    type Error = &'static str;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 20 {
            return Err("Data too short for IPv4 packet");
        }

        let version_ihl = data[0];
        let version = version_ihl >> 4;
        let ihl = version_ihl & 0x0F;

        if version != 4 {
            return Err("Not an IPv4 packet");
        }

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        if data.len() < total_length as usize {
            return Err("Data length mismatch");
        }

        Ok(IPv4Packet {
            version,
            ihl,
            tos: data[1],
            total_length,
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: data[6] >> 5,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1F, data[7]]),
            ttl: data[8],
            protocol: data[9],
            header_checksum: u16::from_be_bytes([data[10], data[11]]),
            source_ip: [data[12], data[13], data[14], data[15]],
            dest_ip: [data[16], data[17], data[18], data[19]],
            payload: Vec::from(&data[(ihl as usize * 4)..]),
        })
    }
}

impl IPv4Packet {
    /// Validates the header checksum of the IPv4 packet.
    pub fn validate_checksum(&self) -> bool {
        let mut sum: u32 = 0;
        let header_bytes = &[
            (self.version << 4) | self.ihl,
            self.tos,
            (self.total_length >> 8) as u8,
            self.total_length as u8,
            (self.identification >> 8) as u8,
            self.identification as u8,
            (self.flags << 5) | ((self.fragment_offset >> 8) as u8),
            self.fragment_offset as u8,
            self.ttl,
            self.protocol,
            0, // Placeholder for checksum high byte
            0, // Placeholder for checksum low byte
            self.source_ip[0],
            self.source_ip[1],
            self.source_ip[2],
            self.source_ip[3],
            self.dest_ip[0],
            self.dest_ip[1],
            self.dest_ip[2],
            self.dest_ip[3],
        ];

        for chunk in header_bytes.chunks(2) {
            let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
            sum = sum.wrapping_add(u32::from(word));
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let checksum = !(sum as u16);
        checksum == self.header_checksum
    }
}

mod tests {
    use crate::cap::Capture;

    use super::*;

    #[test]
    fn test_mac_address() {
        let mac = MacAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(format!("{}", mac), "01:23:45:67:89:AB");
    }
    #[test]
    fn test_ethernet_packet() {
        let data: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAC, 0x08, 0x00,
        ];
        let packet: EthernetPacket = (&data[..]).try_into().unwrap();
        assert_eq!(
            packet.header.dest_mac.0,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        );
        assert_eq!(
            packet.header.src_mac.0,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAC]
        );
        assert_eq!(packet.header.ether_type, EtherType::IPv4);
    }

    #[test]
    fn test_ipv4_packet() {
        let data: [u8; 24] = [
            0x45, 0x00, 0x00, 0x18, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0xde, 0xad, 0xbe, 0xef,
        ];
        let packet: IPv4Packet = (&data[..]).try_into().unwrap();

        assert_eq!(packet.version, 4);
        assert_eq!(packet.ihl, 5);
        assert_eq!(packet.total_length, 24);
        assert_eq!(packet.ttl, 64);
        assert_eq!(packet.protocol, 6); // TCP
        assert_eq!(packet.source_ip, [192, 168, 0, 1]);
        assert_eq!(packet.dest_ip, [192, 168, 0, 199]);
        assert_eq!(packet.payload, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_ipv4_packet_checksum_valid() {
        let data: [u8; 24] = [
            0x45, 0x00, 0x00, 0x18, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0xde, 0xad, 0xbe, 0xef,
        ];
        let packet: IPv4Packet = (&data[..]).try_into().unwrap();
        assert!(packet.validate_checksum());
    }

    #[test]
    fn test_ipv4_packet_checksum_invalid() {
        let data: [u8; 24] = [
            0x45, 0x00, 0x00, 0x18, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0xde, 0xad, 0xbe, 0xef,
        ];
        let packet: IPv4Packet = (&data[..]).try_into().unwrap();
        assert!(!packet.validate_checksum());
    }

    async fn get_ethernet_packet(eth_type: Option<EtherType>) -> EthernetPacket {
        let temp_file_path = "sample.pcap";
        // Read the pcap file
        let mut capture = Capture::from_file(temp_file_path).await.unwrap();
        let header = capture.header();
        assert_eq!(header.magic_number, 0xa1b2c3d4);
        while let Some(raw_packet) = capture.next_packet().await.unwrap() {
            let eth_packet = EthernetPacket::try_from(raw_packet.data.as_slice()).unwrap();
            if eth_type.is_none() || eth_packet.header.ether_type == eth_type.unwrap() {
                return eth_packet;
            }
        }
        panic!("No Ethernet packet found.");
    }

    #[tokio::test]
    async fn test_real_ipv4_packet() {
        let ipv4_packet = get_ethernet_packet(Some(EtherType::IPv4)).await;
        assert_eq!(ipv4_packet.header.ether_type, EtherType::IPv4);
        // Resolve the IPv4 packet
        let ipv4_data = IPv4Packet::try_from(ipv4_packet.data.as_slice()).unwrap();
        assert_eq!(ipv4_data.version, 4);
        // Print packet details
        assert!(ipv4_data.validate_checksum());
        println!("IPv4 Packet: {:?}", ipv4_data);
        println!("Source IP: {}.{}.{}.{}", ipv4_data.source_ip[0], ipv4_data.source_ip[1], ipv4_data.source_ip[2], ipv4_data.source_ip[3]);
        println!("Destination IP: {}.{}.{}.{}", ipv4_data.dest_ip[0], ipv4_data.dest_ip[1], ipv4_data.dest_ip[2], ipv4_data.dest_ip[3]);
        println!("Payload Length: {}", ipv4_data.payload.len());
    }
}
