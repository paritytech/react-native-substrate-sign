declare module 'react-native-substrate-sign' {

	export function brainWalletAddress(seed: string): Promise<string>;

	export function brainWalletBIP39Address(seed: string): Promise<string>;

	export function brainWalletSign(seed: string, message: string): Promise<string>;

	export function rlpItem(rlp: string, position: number): Promise<string>;

	export function keccak(data: string): Promise<string>;

	export function blake2b(data: string): Promise<string>;

	export function ethSign(data: string): Promise<string>;

	export function blockiesIcon(seed: string): Promise<string>;

	export function randomPhrase(wordsNumber: number): Promise<string>;

	export function encryptData(data: string, password: string): Promise<string>;

	export function decryptData(data: string, password: string): Promise<string>;

	export function qrCode(data: string): Promise<string>;

	export function qrCodeHex(data: string): Promise<string>;

	export function substrateAddress(seed: string, prefix: number): Promise<string>;

	export function substrateSign(seed: string, message: string): Promise<string>;

	export function schnorrkelVerify(seed: string, message: string, signature: string): Promise<boolean>;

	export function decryptDataRef(data: string, password: string): Promise<number>;

	export function destroyDataRef(dataRef: number): Promise<void>;

	export function brainWalletSignWithRef(dataRef: number, message: string): Promise<string>;

	export function substrateSignWithRef(dataRef: number, suriSuffix: string, message: string): Promise<string>;

	export function brainWalletAddressWithRef(dataRef: number): Promise<string>;

	export function substrateAddressWithRef(dataRef: number, suriSuffix: string, prefix: number): Promise<string>;

}
