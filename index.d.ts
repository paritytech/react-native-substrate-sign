declare module 'react-native-substrate-sign' {
	interface SubstrateSign {
		brainWalletAddress(seed: string): Promise<string>;

		brainWalletBIP39Address(seed: string): Promise<string>;

		brainWalletSign(seed: string, message: string): Promise<string>;

		rlpItem(rlp: string, position: number): Promise<string>;

		keccak(data: string): Promise<string>;

		blake2b(data: string): Promise<string>;

		ethSign(data: string): Promise<string>;

		blockiesIcon(seed: string): Promise<string>;

		randomPhrase(wordsNumber: number): Promise<string>;

		encryptData(data: string, password: string): Promise<string>;

		decryptData(data: string, password: string): Promise<string>;

		qrCode(data: string): Promise<string>;

		qrCodeHex(data: string): Promise<string>;

		substrateAddress(seed: string, prefix: number): Promise<string>;

		substrateSign(seed: string, message: string): Promise<string>;

		schnorrkelVerify(seed: string, message: string, signature: string): Promise<boolean>;

		decryptDataRef(data: string, password: string): Promise<number>;

		destroyDataRef(dataRef: number): Promise<void>;

		brainWalletSignWithRef(dataRef: number, message: string): Promise<string>;

		substrateSignWithRef(dataRef: number, suriSuffix: string, message: string): Promise<string>;

		brainWalletAddressWithRef(dataRef: number): Promise<string>;

		substrateAddressWithRef(dataRef: number, suriSuffix: string, prefix: number): Promise<string>;
	}
}
