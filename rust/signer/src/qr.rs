//! # Qr code parser
//!
//! These functions implement fountain bucket for fountained data
//!
//! Currently only metadata is wrapped, but these functions are
//! agnostic for the payload, so expancion should be trivial if needed

use raptorq;
use std::str;
use hex;

const CHUNK_SIZE: u16 = 1079;

/// QR data decoding bucket, returns decoded payload when done
pub fn parse_goblet(size: u64, data: Vec<&str>) -> String {
    let mut decoder = raptorq::Decoder::new(
        raptorq::ObjectTransmissionInformation::with_defaults(
            size,
            CHUNK_SIZE,
        ));
    
    data.iter()
        .map(|str_packet| hex::decode(str_packet).unwrap())
        .map(|ser_packet| raptorq::EncodingPacket::deserialize(&ser_packet))
        .for_each(|packet| decoder.add_new_packet(packet));
    
    if let Some(decoded) = decoder.get_result() {
        "0x".to_owned() + &hex::encode(decoded)
    } else { "".to_string() }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    
    static SHORT_TEST_MESSAGE: &str = "Evergreen is everfree";

    static 

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

        let decoded = parse_goblet(frames);
        assert_eq!(SHORT_TEST_MESSAGE, decoded);
    }

}*/
