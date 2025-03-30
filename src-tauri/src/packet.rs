use core::fmt;
use std::hash::Hash;


/// Mac Address
/// Represents a MAC address in a human-readable format.
/// The MAC address is represented as a string in the format "XX:XX:XX:XX:XX:XX"
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress (pub [u8; 6]);

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
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2],
            self.0[3], self.0[4], self.0[5])
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

        let dest_mac = MacAddress([
            data[0], data[1], data[2],
            data[3], data[4], data[5],
        ]);
        let src_mac = MacAddress([
            data[6], data[7], data[8],
            data[9], data[10], data[11],
        ]);
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


mod tests {
    use super::*;

    #[test]
    fn test_mac_address() {
        let mac = MacAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(format!("{}", mac), "01:23:45:67:89:AB");
    }
    #[test]
    fn test_ethernet_packet() {
        let data: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAC,
            0x08, 0x00,
        ];
        let packet: EthernetPacket = (&data[..]).try_into().unwrap();
        assert_eq!(packet.header.dest_mac.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(packet.header.src_mac.0, [0x01, 0x23, 0x45, 0x67, 0x89, 0xAC]);
        assert_eq!(packet.header.ether_type, EtherType::IPv4);
    }
}

