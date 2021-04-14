# react-native-substrate-sign

[![npm version](https://badge.fury.io/js/react-native-substrate-sign.svg)](https://badge.fury.io/js/react-native-substrate-sign)

This React Native library packages practical crypto functions written in Rust for Substrate, Polkadot and Ethereum. Originally used for [Parity Signer](https://github.com/paritytech/parity-signer/).

## Getting started

```shell script
yarn add react-native-substrate-sign
cd ios && pod install && cd ..
```

## Usage

All the functions could be find in the `index.d.ts` file. They are wrapped with async behaviors, since we need access to Rust runtime, be sure to use `await` or `then` to access the result.

```javascript
import SubstrateSign from 'react-native-substrate-sign';

async function getRandomPhrase(){
  const newRandomPhrase = SubstrateSign.randomPhrase(12);
}
```

## Build and Develop

### Requirements

- `node.js` ( `>=10`)
- `yarn` (tested on `1.6.0`)
- `rustup` (tested on `rustup 1.21.0`)
- `rustc` (tested on `rustc 1.41.1`,  from 1.42.0 rust [dropped 32-bit apple target support](https://blog.rust-lang.org/2020/01/03/reducing-support-for-32-bit-apple-targets.html))
- `cargo` (tested on `cargo 1.41.0`)
- `android_ndk` (tested on `r21`, can be downloaded [here](https://developer.android.com/ndk/downloads))
- `$NDK_HOME` envarionment variable set to ndk home directory (eg. `/usr/local/opt/android-ndk`)

\* It's recommended to install **Android Studio** and use that to install the necessary build tools and SDKs for the Android version you want to test on. It's also the best way to test in the emulator. 

### Setup

- Use the following script to install the required rust toolchains.

```shell script
./scripts/init.sh
```


### Develop
After update the rust code, you need to change the following files for updating the interface to native android and ios code.

- ios/signer.h
- ios/SubstrateSign.m
- ios/SubstrateSign.swift
- android/src/main/java/io/parity/substrateSign/SubstrateSignModule.java
- index.js
- index.d.ts

### Test

- To run the rust test

```shell script
yarn test
```

### Build

- Use the following script to build the dynamic library for Android and static library for iOS.

```shell script
./scripts/build.sh
```
