#!/bin/bash

# it is how we can build mwc wallet & node lib with sanitizer. It required 
# to use nightly rust under MacOS.

export CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes -Cdebuginfo=2 -Copt-level=1 -C link-arg=-Wl,-dead_strip"
export CFLAGS="-fno-common"
export CPPFLAGS="-fno-common"
export RUSTFLAGS="-C link-arg=-fno-common"

#cargo +nightly clean
cargo +nightly build   --target aarch64-apple-darwin   -Zbuild-std   --package mwc_wallet_lib   --lib --release

