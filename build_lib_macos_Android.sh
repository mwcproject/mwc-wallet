#!/bin/bash

set -x
set -e

# Dev script to build debug and release ARM builds for MacOS.
# Needed for Android build

# Uncomment for the very first run
#rustup target add aarch64-linux-android

export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/26.1.10909125
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android28-clang
export CC_aarch64_linux_android=$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER
export CXX_aarch64_linux_android=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android28-clang++
export AR_aarch64_linux_android=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar
export CFLAGS_aarch64_linux_android="-DANDROID"

cargo build -p mwc_wallet_lib --lib --target aarch64-linux-android
cargo build -p mwc_wallet_lib --lib --target aarch64-linux-android --release
