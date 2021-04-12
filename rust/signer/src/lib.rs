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

use bip39::{Language, Mnemonic, MnemonicType};
use blake2_rfc::blake2b::blake2b;
use blockies::Ethereum;
use ethsign::{keyfile::Crypto, Protected};
use pixelate::{Color, Image, BLACK};
use qrcodegen::{QrCode, QrCodeEcc};
use rlp::decode_list;
use rustc_hex::{FromHex, ToHex};
use tiny_keccak::keccak256 as keccak;
use tiny_keccak::Keccak;
use serde_json;

use eth::{KeyPair, PhraseKind};
use result::{Error, Result};

mod eth;
mod export;
mod result;
mod sr25519;
mod metadata;
mod qr;

const CRYPTO_ITERATIONS: u32 = 10240;

fn base64png(png: &[u8]) -> String {
	static HEADER: &str = "data:image/png;base64,";
	let mut out = String::with_capacity(png.len() + png.len() / 2 + HEADER.len());
	out.push_str(HEADER);
	base64::encode_config_buf(png, base64::STANDARD, &mut out);
	out
}

fn qrcode_bytes(data: &[u8]) -> crate::Result<String> {
	let qr = QrCode::encode_binary(data, QrCodeEcc::Medium)?;
	let palette = &[Color::Rgba(255, 255, 255, 0), BLACK];
	let mut pixels = Vec::with_capacity((qr.size() * qr.size()) as usize);
	for y in 0..qr.size() {
		for x in 0..qr.size() {
			pixels.push(qr.get_module(x, y) as u8);
		}
	}
	let mut result = Vec::new();
	Image {
		palette,
		pixels: &pixels,
		width: qr.size() as usize,
		scale: 16,
	}
	.render(&mut result)
	.map_err(|e| crate::Error::Pixelate(e))?;
	Ok(base64png(&result))
}

export! {
	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyBrainwalletAddress
	fn ethkey_brainwallet_address(
		seed: &str
	) -> String {
		let (kind, keypair) = KeyPair::from_auto_phrase(seed);
		let mut out = String::with_capacity(47);
		out += match kind {
			PhraseKind::Bip39 => "bip39:",
			PhraseKind::Legacy => "legacy:",
		};
		out += &keypair.address().to_hex::<String>();
		out
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyBrainwalletBIP39Address
	fn ethkey_brainwallet_bip39_address(
		seed: &str
	) -> crate::Result<String> {
		let keypair = KeyPair::from_bip39_phrase(seed)
			.ok_or(crate::Error::KeyPairIsNone)?;
		Ok(keypair.address().to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyBrainwalletSign
	fn ethkey_brainwallet_sign(
		seed: &str,
		message: &str
	) -> crate::Result<String> {
		let (_, keypair) = KeyPair::from_auto_phrase(seed);
		let message: Vec<u8> = message.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		let signature = keypair.sign(&message)
			.map_err(|e| crate::Error::Ethsign(e))?;
		Ok(signature.to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyRlpItem
	fn rlp_item(
		rlp: &str,
		position: u32
	) -> crate::Result<String> {
		let hex: Vec<u8> = rlp.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		let rlp = decode_list::<Vec<u8>>(&hex);
		rlp.get(position as usize).map(|data| data.to_hex())
			.ok_or(anyhow::anyhow!("index out of bounds"))
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyKeccak
	fn keccak256(
		data: &str
	) -> crate::Result<String> {
		let data: Vec<u8> = data.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		Ok(keccak(&data).to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyBlake
	fn blake(
		data: &str
	) -> crate::Result<String> {
		let data: Vec<u8> = data.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		Ok(blake2b(32, &[], &data).as_bytes().to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyBlockiesIcon
	fn blockies_icon(
		seed: String
	) -> crate::Result<String> {
		let mut result = Vec::new();
		let blockies = Ethereum::default();
		match blockies.create_icon(&mut result, seed.as_bytes()) {
			Ok(_) => Ok(base64png(&result)),
			Err(e) => Err(crate::Error::Blockies(e).into()),
		}
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyEthSign
	fn eth_sign(
		data: &str
	) -> crate::Result<String> {
		let hex: Vec<u8> = data.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		let message = format!("\x19Ethereum Signed Message:\n{}", hex.len()).into_bytes();
		let mut res = [0u8; 32];
		let mut keccak = Keccak::new_keccak256();
		keccak.update(&message);
		keccak.update(&hex);
		keccak.finalize(&mut res);
		Ok(res.to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyRandomPhrase
	fn random_phrase(
		words_number:u32
	) -> String {
		let mnemonic_type = match MnemonicType::for_word_count(words_number as usize) {
			Ok(t) => t,
			Err(_e) => MnemonicType::Words24,
		};
		let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
		mnemonic.into_phrase()
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyEncryptData
	fn encrypt_data(
		data: &str,
		password: String
	) -> crate::Result<String> {
		let password = Protected::new(password.into_bytes());
		let crypto = Crypto::encrypt(data.as_bytes(), &password, CRYPTO_ITERATIONS)
			.map_err(|e| crate::Error::Ethsign(e))?;
		Ok(serde_json::to_string(&crypto)?)
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyDecryptData
	fn decrypt_data(
		data: &str,
		password: String
	) -> crate::Result<String> {
		let password = Protected::new(password.into_bytes());
		let crypto: Crypto = serde_json::from_str(data)?;
		let decrypted = crypto.decrypt(&password)
			.map_err(|e| crate::Error::Ethsign(e))?;
		Ok(String::from_utf8(decrypted)?)
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyQrCode
	fn qrcode(
		data: &str
	) -> crate::Result<String> {
		qrcode_bytes(data.as_bytes())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyQrCodeHex
	fn qrcode_hex(
		data: &str
	) -> crate::Result<String> {
		let bytes = &data.from_hex::<Vec<u8>>()
			.map_err(|e| crate::Error::FromHex(e))?;
		qrcode_bytes(&bytes)
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_substrateBrainwalletAddress
	fn substrate_brainwallet_address(
		suri: &str,
		prefix: u8
	) -> crate::Result<String> {
		let keypair = sr25519::KeyPair::from_suri(suri)
			.ok_or(crate::Error::KeyPairIsNone)?;
		Ok(keypair.ss58_address(prefix))
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_substrateBrainwalletSign
	fn substrate_brainwallet_sign(
		suri: &str,
		message: &str
	) -> crate::Result<String> {
		let keypair = sr25519::KeyPair::from_suri(suri)
			.ok_or(crate::Error::KeyPairIsNone)?;
		let message: Vec<u8> = message.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		let signature = keypair.sign(&message);
		Ok(signature.to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_schnorrkelVerify
	fn schnorrkel_verify(
		suri: &str,
		msg: &str,
		signature: &str
	) -> crate::Result<bool> {
		let keypair = sr25519::KeyPair::from_suri(suri)
			.ok_or(crate::Error::KeyPairIsNone)?;
		let message: Vec<u8> = msg.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		let signature: Vec<u8> = signature.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		keypair.verify_signature(&message, &signature)
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyDecryptDataRef
	fn decrypt_data_ref(
		data: &str,
		password: String
	) -> crate::Result<i64> {
		let password = Protected::new(password.into_bytes());
		let crypto: Crypto = serde_json::from_str(data)?;
		let decrypted = crypto.decrypt(&password)
			.map_err(|e| crate::Error::Ethsign(e))?;
		Ok(Box::into_raw(Box::new(String::from_utf8(decrypted).ok())) as i64)
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyDestroyDataRef
	fn destroy_data_ref(data_ref: i64) -> () {
		unsafe { Box::from_raw(data_ref as *mut String) };
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyBrainwalletSignWithRef
	fn ethkey_brainwallet_sign_with_ref(
		seed_ref: i64,
		message: &str
	) -> crate::Result<String> {
		let seed = unsafe { Box::from_raw(seed_ref as *mut String) };
		let (_, keypair) = KeyPair::from_auto_phrase(&seed);
		let message: Vec<u8> = message.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		let signature = keypair.sign(&message)
			.map_err(|e| crate::Error::Ethsign(e))?;
		// so that the reference remains valid
		let _ = Box::into_raw(seed) as i64;
		Ok(signature.to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeySubstrateBrainwalletSignWithRef
	fn substrate_brainwallet_sign_with_ref(
		seed_ref: i64,
		suri_suffix: &str,
		message: &str
	) -> crate::Result<String> {
		let seed = unsafe { Box::from_raw(seed_ref  as *mut String) };
		let suri = format!("{}{}", &seed, suri_suffix);
		let keypair = sr25519::KeyPair::from_suri(&suri)
			.ok_or(crate::Error::KeyPairIsNone)?;
		let message: Vec<u8> = message.from_hex()
			.map_err(|e| crate::Error::FromHex(e))?;
		let signature = keypair.sign(&message);
		// so that the reference remains valid
		let _ = Box::into_raw(seed) as i64;
		Ok(signature.to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeySubstrateWalletAddressWithRef
	fn substrate_address_with_ref(
		seed_ref: i64,
		suri_suffix: &str,
		prefix: u8
	) -> crate::Result<String> {
		let seed = unsafe { Box::from_raw(seed_ref  as *mut String) };
		let suri = format!("{}{}", &seed, suri_suffix);
		let keypair = sr25519::KeyPair::from_suri(&suri)
			.ok_or(crate::Error::KeyPairIsNone)?;
		// so that the reference remains valid
		let _ = Box::into_raw(seed) as i64;
		Ok(keypair.ss58_address(prefix))
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeyBrainWalletAddressWithRef
	fn brain_wallet_address_with_ref(
		seed_ref: i64
	) -> crate::Result<String> {
		let seed = unsafe { Box::from_raw(seed_ref  as *mut String) };
		let address = ethkey_brainwallet_address(&seed);
		// so that the reference remains valid
		let _ = Box::into_raw(seed) as i64;
		Ok(address)
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeySubstrateMiniSecretKey
	fn substrate_mini_secret_key(
		suri: &str
	) -> crate::Result<String> {
		let bytes = sr25519::KeyPair::get_derived_secret(&suri)
			.ok_or(crate::Error::KeyPairIsNone)?;
		Ok(bytes.to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_ethkeySubstrateMiniSecretKeyWithRef
	fn substrate_mini_secret_key_with_ref (
		seed_ref: i64,
		suri_suffix: &str
	) -> crate::Result<String> {
		let seed = unsafe { Box::from_raw(seed_ref as *mut String) };
		let suri = format!("{}{}", &seed, suri_suffix);
		let bytes = sr25519::KeyPair::get_derived_secret(&suri)
			.ok_or(crate::Error::KeyPairIsNone)?;
		let _ = Box::into_raw(seed) as i64;
		Ok(bytes.to_hex())
	}

	@Java_io_parity_substrateSign_SubstrateSignModule_qrparserTryDecodeQrSequence
	fn try_decode_qr_sequence(
        size: i64,
		data_json: &str
	) -> crate::Result<String> {
        let data: Vec<&str> = qr::deserialize(data_json);
        if size>0 {return Ok(
        "0x6d6574610c601853797374656d011853797374656d401c4163636f756e7401010230543a3a4163636f756e744964944163636f756e74496e666f3c543a3a496e6465782c20543a3a4163636f756e74446174613e0031010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e8205468652066756c6c206163636f756e7420696e666f726d6174696f6e20666f72206120706172746963756c6172206163636f756e742049442e3845787472696e736963436f756e7400000c753332040004b820546f74616c2065787472696e7369637320636f756e7420666f72207468652063757272656e7420626c6f636b2e2c426c6f636b576569676874010038436f6e73756d6564576569676874600000000000000000000000000000000000000000000000000488205468652063757272656e742077656967687420666f722074686520626c6f636b2e40416c6c45787472696e736963734c656e00000c753332040004410120546f74616c206c656e6774682028696e2062797465732920666f7220616c6c2065787472696e736963732070757420746f6765746865722c20666f72207468652063757272656e7420626c6f636b2e24426c6f636b4861736801010538543a3a426c6f636b4e756d6265721c543a3a48617368008000000000000000000000000000000000000000000000000000000000000000000498204d6170206f6620626c6f636b206e756d6265727320746f20626c6f636b206861736865732e3445787472696e736963446174610101050c7533321c5665633c75383e000400043d012045787472696e73696373206461746120666f72207468652063757272656e7420626c6f636b20286d61707320616e2065787472696e736963277320696e64657820746f206974732064617461292e184e756d626572010038543a3a426c6f636b4e756d6265721000000000040901205468652063757272656e7420626c6f636b206e756d626572206265696e672070726f6365737365642e205365742062792060657865637574655f626c6f636b602e28506172656e744861736801001c543a3a4861736880000000000000000000000000000000000000000000000000000000000000000004702048617368206f66207468652070726576696f757320626c6f636b2e1844696765737401002c4469676573744f663c543e040004f020446967657374206f66207468652063757272656e7420626c6f636b2c20616c736f2070617274206f662074686520626c6f636b206865616465722e184576656e747301008c5665633c4576656e745265636f72643c543a3a4576656e742c20543a3a486173683e3e040004a0204576656e7473206465706f736974656420666f72207468652063757272656e7420626c6f636b2e284576656e74436f756e740100284576656e74496e646578100000000004b820546865206e756d626572206f66206576656e747320696e2074686520604576656e74733c543e60206c6973742e2c4576656e74546f706963730101021c543a3a48617368845665633c28543a3a426c6f636b4e756d6265722c204576656e74496e646578293e000400282501204d617070696e67206265747765656e206120746f7069632028726570726573656e74656420627920543a3a486173682920616e64206120766563746f72206f6620696e646578657394206f66206576656e747320696e2074686520603c4576656e74733c543e3e60206c6973742e00510120416c6c20746f70696320766563746f727320686176652064657465726d696e69737469632073746f72616765206c6f636174696f6e7320646570656e64696e67206f6e2074686520746f7069632e2054686973450120616c6c6f7773206c696768742d636c69656e747320746f206c6576657261676520746865206368616e67657320747269652073746f7261676520747261636b696e67206d656368616e69736d20616e64e420696e2063617365206f66206368616e67657320666574636820746865206c697374206f66206576656e7473206f6620696e7465726573742e004d01205468652076616c756520686173207468652074797065206028543a3a426c6f636b4e756d6265722c204576656e74496e646578296020626563617573652069662077652075736564206f6e6c79206a7573744d012074686520604576656e74496e64657860207468656e20696e20636173652069662074686520746f70696320686173207468652073616d6520636f6e74656e7473206f6e20746865206e65787420626c6f636b0101206e6f206e6f74696669636174696f6e2077696c6c20626520747269676765726564207468757320746865206576656e74206d69676874206265206c6f73742e484c61737452756e74696d65557067726164650000584c61737452756e74696d6555706772616465496e666f04000455012053746f726573207468652060737065635f76657273696f6e6020616e642060737065635f6e616d6560206f66207768656e20746865206c6173742072756e74696d6520757067726164652068617070656e65642e545570677261646564546f553332526566436f756e74010010626f6f6c0400044d012054727565206966207765206861766520757067726164656420736f207468617420607479706520526566436f756e74602069732060753332602e2046616c7365202864656661756c7429206966206e6f742e585570677261646564546f4475616c526566436f756e74010010626f6f6c04000855012054727565206966207765206861766520757067726164656420736f2074686174204163636f756e74496e666f20636f6e7461696e732074776f207479706573206f662060526566436f756e74602e2046616c736548202864656661756c7429206966206e6f742e38457865637574696f6e50686173650000145068617365040004882054686520657865637574696f6e207068617365206f662074686520626c6f636b2e01242866696c6c5f626c6f636b04185f726174696f1c50657262696c6c040901204120646973706174636820746861742077696c6c2066696c6c2074686520626c6f636b2077656967687420757020746f2074686520676976656e20726174696f2e1872656d61726b041c5f72656d61726b1c5665633c75383e1c6c204d616b6520736f6d65206f6e2d636861696e2072656d61726b2e002c2023203c7765696768743e24202d20604f28312960e0202d2042617365205765696768743a20302e36363520c2b5732c20696e646570656e64656e74206f662072656d61726b206c656e6774682e50202d204e6f204442206f7065726174696f6e732e302023203c2f7765696768743e387365745f686561705f7061676573041470616765730c75363420fc2053657420746865206e756d626572206f6620706167657320696e2074686520576562417373656d626c7920656e7669726f6e6d656e74277320686561702e002c2023203c7765696768743e24202d20604f283129604c202d20312073746f726167652077726974652e64202d2042617365205765696768743a20312e34303520c2b57360202d203120777269746520746f20484541505f5041474553302023203c2f7765696768743e207365745f636f64650410636f64651c5665633c75383e28682053657420746865206e65772072756e74696d6520636f64652e002c2023203c7765696768743e3501202d20604f2843202b2053296020776865726520604360206c656e677468206f662060636f64656020616e642060536020636f6d706c6578697479206f66206063616e5f7365745f636f64656088202d20312073746f726167652077726974652028636f64656320604f28432960292e7901202d20312063616c6c20746f206063616e5f7365745f636f6465603a20604f28532960202863616c6c73206073705f696f3a3a6d6973633a3a72756e74696d655f76657273696f6e6020776869636820697320657870656e73697665292e2c202d2031206576656e742e7d012054686520776569676874206f6620746869732066756e6374696f6e20697320646570656e64656e74206f6e207468652072756e74696d652c206275742067656e6572616c6c792074686973206973207665727920657870656e736976652e902057652077696c6c207472656174207468697320617320612066756c6c20626c6f636b2e302023203c2f7765696768743e5c7365745f636f64655f776974686f75745f636865636b730410636f64651c5665633c75383e201d012053657420746865206e65772072756e74696d6520636f646520776974686f757420646f696e6720616e7920636865636b73206f662074686520676976656e2060636f6465602e002c2023203c7765696768743e90202d20604f2843296020776865726520604360206c656e677468206f662060636f64656088202d20312073746f726167652077726974652028636f64656320604f28432960292e2c202d2031206576656e742e75012054686520776569676874206f6620746869732066756e6374696f6e20697320646570656e64656e74206f6e207468652072756e74696d652e2057652077696c6c207472656174207468697320617320612066756c6c20626c6f636b2e302023203c2f7765696768743e5c7365745f6368616e6765735f747269655f636f6e666967044c6368616e6765735f747269655f636f6e666967804f7074696f6e3c4368616e67657354726965436f6e66696775726174696f6e3e28a02053657420746865206e6577206368616e676573207472696520636f6e66696775726174696f6e2e002c2023203c7765696768743e24202d20604f28312960b0202d20312073746f72616765207772697465206f722064656c6574652028636f64656320604f28312960292ed8202d20312063616c6c20746f20606465706f7369745f6c6f67603a20557365732060617070656e6460204150492c20736f204f28312964202d2042617365205765696768743a20372e32313820c2b57334202d204442205765696768743aa820202020202d205772697465733a204368616e67657320547269652c2053797374656d20446967657374302023203c2f7765696768743e2c7365745f73746f7261676504146974656d73345665633c4b657956616c75653e206c2053657420736f6d65206974656d73206f662073746f726167652e002c2023203c7765696768743e94202d20604f2849296020776865726520604960206c656e677468206f6620606974656d73607c202d206049602073746f72616765207772697465732028604f28312960292e74202d2042617365205765696768743a20302e353638202a206920c2b57368202d205772697465733a204e756d626572206f66206974656d73302023203c2f7765696768743e306b696c6c5f73746f7261676504106b657973205665633c4b65793e2078204b696c6c20736f6d65206974656d732066726f6d2073746f726167652e002c2023203c7765696768743efc202d20604f28494b296020776865726520604960206c656e677468206f6620606b6579736020616e6420604b60206c656e677468206f66206f6e65206b657964202d206049602073746f726167652064656c6574696f6e732e70202d2042617365205765696768743a202e333738202a206920c2b57368202d205772697465733a204e756d626572206f66206974656d73302023203c2f7765696768743e2c6b696c6c5f70726566697808187072656669780c4b6579205f7375626b6579730c7533322c1501204b696c6c20616c6c2073746f72616765206974656d7320776974682061206b657920746861742073746172747320776974682074686520676976656e207072656669782e003d01202a2a4e4f54453a2a2a2057652072656c79206f6e2074686520526f6f74206f726967696e20746f2070726f7669646520757320746865206e756d626572206f66207375626b65797320756e64657241012074686520707265666978207765206172652072656d6f76696e6720746f2061636375726174656c792063616c63756c6174652074686520776569676874206f6620746869"
                .to_string())};
        let answer = qr::parse_goblet(size as u64, data);
        Ok(answer)
	}

}

ffi_support::define_string_destructor!(signer_destroy_string);

#[cfg(test)]
mod tests {
	use super::*;

	static SEED_PHRASE: &str =
		"grant jaguar wish bench exact find voice habit tank pony state salmon";
	static SURI_SUFFIX: &str = "//hard/soft/0";
	static SURI_SUFFIX_HARD: &str = "//hard";
	static ENCRYPTED_SEED: &str = "{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"47b4b75d13045ff7569da858e234f7ea\"},\"ciphertext\":\"ca1cf5387822b70392c4aeec729676f91ab00a795d7593fb7e52ecc333dbc4a1acbedc744b5d8d519c714e194bd741995244c8128bfdce6c184d6bda4ca136ed265eedcee9\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":10240,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"b4a2d1edd1a70fe2eb48d7aff15c19e234f6aa211f5142dddb05a59af12b3381\"},\"mac\":\"b38a54eb382f2aa1a8be2f7b86fe040fe112d0f42fea03fac186dccdd7ae3eb9\"}";
	static PIN: &str = "000000";
	static SUBSTRATE_ADDRESS: &str = "5D4kaJXj5HVoBw2tFFsDj56BjZdPhXKxgGxZuKk4K3bKqHZ6";
	static ETHEREUM_ADDRESS: &str = "bip39:f85f35e47e976650641ecd1a644e33edccc9cab1";

	#[test]
	fn test_random_phrase() {
		let result_12 = random_phrase(12);
		assert_eq!(12, result_12.split_whitespace().count());
		let result_24 = random_phrase(24);
		assert_eq!(24, result_24.split_whitespace().count());
		let result_17 = random_phrase(17);
		assert_eq!(24, result_17.split_whitespace().count());
	}

	#[test]
	fn test_blake() {
		let data = "454545454545454545454545454545454545454545454545454545454545454501\
                    000000000000002481853da20b9f4322f34650fea5f240dcbfb266d02db94bfa01\
                    53c31f4a29dbdbf025dd4a69a6f4ee6e1577b251b655097e298b692cb34c18d318\
                    2cac3de0dc00000000";
		let expected = "1025e5db74fdaf4d2818822dccf0e1604ae9ccc62f26cecfde23448ff0248abf";
		let result = blake(data);

		assert_eq!(expected.to_string(), result.unwrap());
	}

	#[test]
	fn test_rlp_item() {
		let rlp = "f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804";
		assert_eq!(rlp_item(rlp, 0).unwrap(), "".to_owned());
		assert_eq!(rlp_item(rlp, 1).unwrap(), "01".to_owned());
		assert_eq!(rlp_item(rlp, 2).unwrap(), "5208".to_owned());
		assert_eq!(
			rlp_item(rlp, 3).unwrap(),
			"095e7baea6a6c7c4c2dfeb977efac326af552d87".to_owned()
		);
		assert_eq!(rlp_item(rlp, 4).unwrap(), "0a".to_owned());
		assert_eq!(rlp_item(rlp, 5).unwrap(), "".to_owned());
	}

	#[test]
	fn test_substrate_brainwallet_address() {
		// Secret seed: 0xb139e4050f80172b44957ef9d1755ef5c96c296d63b8a2b50025bf477bd95224
		// Public key (hex): 0x944eeb240615f4a94f673f240a256584ba178e22dd7b67503a753968e2f95761
		let expected = "5FRAPSnpgmnXAnmPVv68fT6o7ntTvaZmkTED8jDttnXs9k4n";
		let generated = substrate_brainwallet_address(SEED_PHRASE, 42).unwrap();

		assert_eq!(expected, generated);
	}

	#[test]
	fn test_substrate_secret() {
		let data_pointer = decrypt_data_ref(ENCRYPTED_SEED, String::from(PIN)).unwrap();
		let suri = format!("{}{}", SEED_PHRASE, SURI_SUFFIX_HARD);
		let expected = "0c4a1f0e772497883ba79c484dfed441008c38572769ab40260a959127949665";
		let generated = substrate_mini_secret_key(&suri).unwrap();
		assert_eq!(expected, generated);
		let passworded_suri = format!("{}///password", SURI_SUFFIX_HARD);
		let generated_passworded_secret= substrate_mini_secret_key_with_ref(data_pointer, &passworded_suri).unwrap();
		let expected_passworded_secret = "057687d479e550b1c0caca121db7e7519c573ebb6a7ce6f771213e41900181f6";
		assert_eq!(expected_passworded_secret, generated_passworded_secret);
	}

	#[test]
	fn test_substrate_secret_with_ref() {
		let data_pointer = decrypt_data_ref(ENCRYPTED_SEED, String::from(PIN)).unwrap();
		let expected = "0c4a1f0e772497883ba79c484dfed441008c38572769ab40260a959127949665";
		let generated = substrate_mini_secret_key_with_ref(data_pointer, SURI_SUFFIX_HARD).unwrap();
		assert_eq!(expected, generated);
	}

	#[test]
	fn test_substrate_brainwallet_address_suri() {
		let suri = format!("{}{}", SEED_PHRASE, SURI_SUFFIX);
		let generated = substrate_brainwallet_address(&suri, 42).unwrap();

		assert_eq!(SUBSTRATE_ADDRESS, generated);
	}

	#[test]
	fn test_substrate_sign() {
		let msg: String = b"Build The Future".to_hex();
		let signature = substrate_brainwallet_sign(SEED_PHRASE, &msg).unwrap();

		let is_valid = schnorrkel_verify(SEED_PHRASE, &msg, &signature).unwrap();

		assert!(is_valid);
	}

	#[test]
	fn test_substrate_sign_with_ref() {
		let msg: String = b"Build The Future".to_hex();
		let data_pointer = decrypt_data_ref(ENCRYPTED_SEED, String::from(PIN)).unwrap();
		let signature_by_ref =
			substrate_brainwallet_sign_with_ref(data_pointer, SURI_SUFFIX, &msg).unwrap();
		let suri = format!("{}{}", SEED_PHRASE, SURI_SUFFIX);
		let is_valid = schnorrkel_verify(&suri, &msg, &signature_by_ref).unwrap();
		destroy_data_ref(data_pointer);
		assert!(is_valid);
	}

	#[test]
	fn decrypt_with_ref() {
		let decrypted_result = decrypt_data(ENCRYPTED_SEED, String::from(PIN)).unwrap();
		assert_eq!(SEED_PHRASE, decrypted_result);
	}

	#[test]
	fn test_generate_substrate_address() {
		let data_pointer = decrypt_data_ref(ENCRYPTED_SEED, String::from(PIN)).unwrap();
		let address = substrate_address_with_ref(data_pointer, SURI_SUFFIX, 42).unwrap();
		destroy_data_ref(data_pointer);
		assert_eq!(address, SUBSTRATE_ADDRESS);
	}

	#[test]
	fn test_generate_ethereum_address() {
		let data_pointer = decrypt_data_ref(ENCRYPTED_SEED, String::from(PIN)).unwrap();
		let address = brain_wallet_address_with_ref(data_pointer).unwrap();
		destroy_data_ref(data_pointer);
		assert_eq!(address, ETHEREUM_ADDRESS);
	}
}
