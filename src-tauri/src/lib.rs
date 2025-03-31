// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
pub mod cap;
pub mod packet;

use cap::Capture;
use packet::{EthernetPacket, IPv4Packet, EtherType};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EthernetTuple {
    eth_type: String,
    source: String,
    target: String,
    ts_sec: u32,    // 秒级时间戳
    ts_usec: u32,   // 微秒级时间戳
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct IPv4PacketTuple {
    source_ip: String,
    dest_ip: String,
    protocol: u8,
    ttl: u8,
    ts_sec: u32,
    ts_usec: u32,
    total_length: u16,
}

#[tauri::command]
async fn analyze_pcap(file_path: String) -> Result<Vec<EthernetTuple>, String> {
    let mut capture = Capture::from_file(&file_path)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let mut results = Vec::new();

    while let Some(raw_packet) = capture.next_packet().await.map_err(|e| e.to_string())? {
        if let Ok(eth_packet) = EthernetPacket::try_from(raw_packet.data.as_slice()) {
            results.push(EthernetTuple { 
                eth_type: format!("{:?}", eth_packet.header.ether_type),
                source: eth_packet.header.src_mac.to_string(),
                target: eth_packet.header.dest_mac.to_string(),
                ts_sec: raw_packet.header.ts_sec,
                ts_usec: raw_packet.header.ts_usec,
            });
        }
    }

    Ok(results)
}

#[tauri::command]
async fn analyze_ipv4_packets(file_path: String) -> Result<Vec<IPv4PacketTuple>, String> {
    let mut capture = Capture::from_file(&file_path)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let mut results = Vec::new();

    while let Some(raw_packet) = capture.next_packet().await.map_err(|e| e.to_string())? {
        if let Ok(eth_packet) = EthernetPacket::try_from(raw_packet.data.as_slice()) {
            if eth_packet.header.ether_type == EtherType::IPv4 {
                if let Ok(ipv4_packet) = IPv4Packet::try_from(eth_packet.data.as_slice()) {
                    results.push(IPv4PacketTuple {
                        source_ip: format!("{}.{}.{}.{}", 
                            ipv4_packet.source_ip[0], ipv4_packet.source_ip[1], 
                            ipv4_packet.source_ip[2], ipv4_packet.source_ip[3]),
                        dest_ip: format!("{}.{}.{}.{}", 
                            ipv4_packet.dest_ip[0], ipv4_packet.dest_ip[1], 
                            ipv4_packet.dest_ip[2], ipv4_packet.dest_ip[3]),
                        protocol: ipv4_packet.protocol,
                        ttl: ipv4_packet.ttl,
                        ts_sec: raw_packet.header.ts_sec,
                        ts_usec: raw_packet.header.ts_usec,
                        total_length: ipv4_packet.total_length,
                    });
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_pcap() {
        let file_path = "sample.pcap".to_string();
        let result = analyze_pcap(file_path).await;
        assert!(result.is_ok());
        let packets = result.unwrap();
        assert!(!packets.is_empty());
        for eth_packet in &packets {
            assert!(!eth_packet.eth_type.is_empty());
            assert!(!eth_packet.source.is_empty());
            assert!(!eth_packet.target.is_empty());
        }
        // Print first packet details for verification
        if let Some(eth_packet) = packets.first() {
            println!("First packet: EthType: {}, Src MAC: {}, Dest MAC: {}, Timestamp: {}.{}", eth_packet.eth_type, eth_packet.source, eth_packet.target, eth_packet.ts_sec, eth_packet.ts_usec);
        }
    }

    #[tokio::test]
    async fn test_analyze_ipv4_packets() {
        let file_path = "sample.pcap".to_string();
        let result = analyze_ipv4_packets(file_path).await;
        assert!(result.is_ok());
        let ipv4_packets = result.unwrap();
        assert!(!ipv4_packets.is_empty());
        
        for ipv4_packet in &ipv4_packets {
            // 验证IP地址格式是否正确
            assert!(!ipv4_packet.source_ip.is_empty());
            assert!(!ipv4_packet.dest_ip.is_empty());
            
            // 验证TTL值是否有效
            assert!(ipv4_packet.ttl > 0);
            
            // 验证总长度是否有效
            assert!(ipv4_packet.total_length > 0);
        }
        
        // 打印第一个IPv4数据包的详细信息以便手动验证
        if let Some(ipv4_packet) = ipv4_packets.first() {
            println!(
                "First IPv4 packet: Source IP: {}, Dest IP: {}, Protocol: {}, TTL: {}, Total Length: {}, Timestamp: {}.{}", 
                ipv4_packet.source_ip, 
                ipv4_packet.dest_ip, 
                ipv4_packet.protocol, 
                ipv4_packet.ttl, 
                ipv4_packet.total_length,
                ipv4_packet.ts_sec, 
                ipv4_packet.ts_usec
            );
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![analyze_pcap, analyze_ipv4_packets])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
