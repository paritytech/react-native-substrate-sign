//! # Qr code parser
//!
//! These functions implement fountain bucket for fountained data
//!
//! Currently only metadata is wrapped, but these functions are
//! agnostic for the payload, so expancion should be trivial if needed

use raptorq;
use std::sync::mpsc;
use std::sync::Mutex;
use std::str;
use serde;

#[cfg(test)]
use std::thread;
use std::time::Duration;

const CHUNK_SIZE: u16 = 512;

// this is ugly unsafe global communication channel,
// but leaving it to TS runtime is just worse
// If it starts failing in builds,
// we'll have to serde-send tx to frame getter
static mut RAPTOR_OBJECT_SENDER: Option<Mutex<mpsc::Sender<String>>> = None;

/// object to hold raptorq encoding packet and final message size
/// the size is not known ahead of time but is required by decoding algorithm
#[derive(serde::Serialize, serde::Deserialize)]
struct QrMessage {
    size: u64,
    payload: Vec<u8>,
}

impl QrMessage {
    pub fn new(raw_data: String) -> QrMessage {
        //TODO: unwrap
        serde_json::from_str(&raw_data).unwrap()
    }
}

/// QR data decoding bucket, returns decoded payload when done
pub fn spawn_qr_parser() -> String {
    let (tx, rx) = mpsc::channel::<String>();
    //This static variable is changed only here
    //TODO: check how unwrap behaves
    unsafe{
        RAPTOR_OBJECT_SENDER = Some(Mutex::new(tx));
    };

    //TODO: unwrap
    let firstdata = rx.recv().unwrap();
    let firstmessage = QrMessage::new(firstdata);
    let mut decoder = raptorq::Decoder::new(
        raptorq::ObjectTransmissionInformation::with_defaults(
            firstmessage.size,
            CHUNK_SIZE,
        ));
    let firstpacket = raptorq::EncodingPacket::deserialize(&firstmessage.payload);
    decoder.add_new_packet(firstpacket);

    loop {
        if let Some(decoded) = decoder.get_result() {
            break str::from_utf8(&decoded).unwrap().to_string();
        } else {
            let packet = raptorq::EncodingPacket::deserialize(&firstmessage.payload);
            decoder.add_new_packet(packet);
        }
    }    
    
}


/// Send a single QR raw data frame to processing pipe; do nothing on failure
pub fn get_qr_frame(raw_data: String) {
    //this should be successful unless the pipe is already closed
    //in which case we should just drop all packets
    //TODO: make sure unwrap fails gracefully
    let tx = unsafe { RAPTOR_OBJECT_SENDER.as_ref().unwrap().lock().unwrap().clone() };
    //TODO: unwrap
    tx.send(raw_data).unwrap();
}


#[cfg(test)]
mod tests {
    use super::*;
    
    static SHORT_TEST_MESSAGE: &str = "Evergreen is everfree";

    //This is random value; reasl fountain will be optimized and this test
    //should be adjusted accordingly
    static REPAIR_PACKETS_PER_BLOCK: u32 = 15;

    fn get_standard_encoder (data: Vec<u8>) -> raptorq::Encoder {
        let encoder = raptorq::Encoder::with_defaults(&data, CHUNK_SIZE);
        encoder
    }

    fn get_standard_code_packets (encoder: raptorq::Encoder) -> Vec<Vec<u8>> {
        encoder.get_encoded_packets(REPAIR_PACKETS_PER_BLOCK)
            .iter()
            .map(|packet| packet.serialize())
            .collect()
    }

    fn get_qr_packet_from_raptor_packet (rpacket: &Vec<u8>, message_length: u64) -> String {
        let message = QrMessage {
                size: message_length, 
                payload: rpacket.to_vec()};
        serde_json::to_string(&message).unwrap()
    }

    ///# Test: get_qr_vec_from_message
    ///Model whatever should be sent from RN runtime.
    ///Important: this code should be identical to fountain generator!
    fn get_qr_vec_from_message (data: Vec<u8>) -> Vec<String> {
        let message_length: u64 = data.len() as u64;
        get_standard_code_packets(get_standard_encoder(data)).iter()
            .map(|x| get_qr_packet_from_raptor_packet(x, message_length)).collect()
    }

    #[test]
    fn decode_short_package() {
        let message = SHORT_TEST_MESSAGE.as_bytes().to_vec();
        let frames = get_qr_vec_from_message(message);

        let (test_tx, test_rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            let answer = spawn_qr_parser();
            test_tx.send(answer).unwrap();
        });

        // hack to represent consequentiveness of these threads in RN runtime
        thread::sleep(Duration::from_secs(1));
        for frame in frames.iter() {
            get_qr_frame(frame.to_string());
        }
        let decoded = test_rx.recv().unwrap();
        assert_eq!(SHORT_TEST_MESSAGE, decoded);
    }

}
