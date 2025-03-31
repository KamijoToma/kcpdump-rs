// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
pub mod cap;
pub mod packet;

use cap::Capture;
use packet::EthernetPacket;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EthernetTuple {
    eth_type: String,
    source: String,
    target: String,
    ts_sec: u32,    // 秒级时间戳
    ts_usec: u32,   // 微秒级时间戳
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
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![analyze_pcap])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
