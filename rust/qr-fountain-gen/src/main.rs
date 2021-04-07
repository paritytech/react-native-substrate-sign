// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! This is a reference fountain QR message generator for Signer;
//!
//! !!! Do NOT compile this into native lib for Signer itself !!!
//!
//! Usage: echo filename | cargo run

use raptorq;
use std::convert::TryInto;
use std::fs::File;
use std::io;
use qrcodegen::{QrCode, QrCodeEcc};
use apng_encoder;

//Chunk size is chosen to fit nicely in easy-to-recognize QR frame
const CHUNK_SIZE: u16 = 256; //503

//This is random not yet optimized value
//TODO: optimize (probably sqrt(data_size/chunk_size))
const REPAIR_PACKETS_PER_BLOCK: u32 = 15;
//const SIZE: u16 = 113;

// apng specs
const WHITE_COLOR: u8 = 0xFF;
const SCALING: u8 = 4;

fn main() {

    // Get data from env::args()
    println!("Reading input...");
    let mut source_data_string = String::new();
    io::stdin().read_line(&mut source_data_string).expect("Failed to read input");
    let source_data = source_data_string.trim();

/*    let source_data = concat!(
 *		"Alice was beginning to get very tired of sitting by her sister on the bank, ",
 *		"and of having nothing to do: once or twice she had peeped into the book her sister was reading, ",
 *		"but it had no pictures or conversations in it, 'and what is the use of a book,' thought Alice ",
 *		"'without pictures or conversations?' So she was considering in her own mind (as well as she could, ",
 * 		"for the hot day made her feel very sleepy and stupid), whether the pleasure of making a ",
 *		"daisy-chain would be worth the trouble of getting up and picking the daisies, when suddenly ",
 *		"a White Rabbit with pink eyes ran close by her.");
 */

    let filename_out = "out.png";

    // Compactify data
    println!("Compressing...");
    let compressed_data = source_data.as_bytes().to_vec();
    let data_size = compressed_data.len() as u64;
    let data_size_vec = data_size.to_be_bytes();
    println!("appended data size: {:?}", data_size_vec);

    // Generate raptorq frames
    println!("Generating fountain frames...");
    let mut output_file = File::create(filename_out).unwrap();
    let mut qr_frames_nervous_counter = 0;

    let raptor_encoder = raptorq::Encoder::with_defaults(&compressed_data, CHUNK_SIZE);
    let frames: Vec<QrCode> = raptor_encoder.get_encoded_packets(REPAIR_PACKETS_PER_BLOCK)
        .iter()
        .map(|packet| packet.serialize())
        .map(|serpacket| [data_size_vec.to_vec(), serpacket].concat())
        .map(|qrpacket| {
            qr_frames_nervous_counter += 1;
            println("Generating fountain codes: {}", qr_frames_nervous_counter);
            QrCode::encode_binary(&qrpacket, QrCodeEcc::High).unwrap()
        })
        .collect();

    let frames_count = frames.len().try_into().unwrap();
    println!("Generating {} frames", frames_count);
    let size: u32 = (frames[0].size() as u32) * (SCALING as u32); // size is always positive and small

    let apng_meta = apng_encoder::Meta {
        width: size,
        height: size,
        color: apng_encoder::Color::Grayscale(8), 
        frames: frames_count,
        plays: None,
    };

    let apng_frame = apng_encoder::Frame {
        delay: Some(apng_encoder::Delay::new(1, 10)),
        ..Default::default()
    };

    let mut apng_encoder = apng_encoder::Encoder::create(&mut output_file, apng_meta).unwrap();
    let mut nervous_counter = 0;

    frames.iter().for_each(|qr| {
            nervous_counter += 1;
            println!("Generating frame {} of {}", nervous_counter, frames_count);
            let mut buffer: Vec<u8> = Vec::new();
            for x in 0..size {
                for y in 0..size {
                    buffer.push((qr.get_module(x as i32 / SCALING as i32, y as i32 / SCALING as i32) as u8) * WHITE_COLOR);
            }}
            apng_encoder.write_frame(&buffer, Some(&apng_frame), None, None).unwrap();
        });
    apng_encoder.finish().unwrap();

    // Save gif
    println!("Saving file...");

    println!("Done!");
}
