#!/bin/bash

set -x
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Uncomment for the very first run
#rustup target add aarch64-apple-ios
#rustup target add x86_64-apple-ios

export IPHONEOS_DEPLOYMENT_TARGET=16.0
export IPHONEOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path)
export IPHONESIM_SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)

export CC_aarch64_apple_ios=$(xcrun --sdk iphoneos -f clang)
export CFLAGS_aarch64_apple_ios="-target arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET} -isysroot ${IPHONEOS_SDK}"

export CC_x86_64_apple_ios=$(xcrun --sdk iphonesimulator -f clang)
export CFLAGS_x86_64_apple_ios="-target x86_64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator -isysroot ${IPHONESIM_SDK}"

rm -rf "$SCRIPT_DIR/target/aarch64-apple-ios"
rm -rf "$SCRIPT_DIR/target/x86_64-apple-ios"

cargo build -p mwc_wallet_lib --lib --target aarch64-apple-ios
cargo build -p mwc_wallet_lib --lib --target aarch64-apple-ios --release

cargo build -p mwc_wallet_lib --lib --target x86_64-apple-ios
cargo build -p mwc_wallet_lib --lib --target x86_64-apple-ios --release
