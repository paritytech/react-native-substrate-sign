use raptorq;
use std::sync::mpsc;
use std::sync::Mutex;
use serde;

const CHUNK_SIZE: usize = 512;

static mut RAPTOR_OBJECT_SENDER: Option<Mutex<mpsc::Sender<String>>> = None;

#[derive(serde::Deserialize)]
struct QrMessage {
    size: u32,
    payload: String,
}

impl QrMessage {
    pub fn new(raw_data: String) -> QrMessage {
        //TODO: unwrap
        serde_json::from_str(&raw_data).unwrap()
    }
}

pub fn spawn_qr_parser() -> String {
    let (tx, rx) = mpsc::channel::<String>();
    unsafe{
        RAPTOR_OBJECT_SENDER = Some(Mutex::new(tx));
    };

    //TODO: unwrap
    let firstdata = rx.recv().unwrap();
    let firstmessage = QrMessage::new(firstdata);
    loop {

        break "blem".to_string()
    }    
    
}

pub fn get_qr_frame(raw_data: String) {
    let tx = unsafe { RAPTOR_OBJECT_SENDER.as_ref().unwrap().lock().unwrap().clone() };
    //TODO: unwrap
    tx.send(raw_data).unwrap();
}


/*
#[cfg(test)]
mod tests {
    use super::*;
    
    static SHORT_TEST_MESSAGE: Vec<u8> = "Evergreen is everfree";
    static REPAIR_PACKETS_PER_BLOCK: u32 = 15;

    fn get_standard_encoder (data: Vec<u8>) -> raptorq::<Encoder> {
        let encoder = raptorq::Encoder::with_defaults(&data, CHUNK_SIZE);
        encoder
    }

    fn get_standard_code_packets (encoder: raptorq::Encoder) -> Vec<Vec<u8>> {
        encoder.get_encoded_packets(REPAIR_PACKETS_PER_BLOCK)
            .iter()
            .map(|packet| packet.serialize())
            .collect();
    }

    #[test]
    fn decode_short_package() {
        let message = SHORT.TEST_MESSAGE.as.bytes()
        let encoder = get_standard_encoder(message);
        let packets = get_standard_code_packets(encoder);
        //test test
        let decoded = message;
        assert_eq!(SHORT_TEST_MESSAGE, decoded.as.String());
    }

}
*/
