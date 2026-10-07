#!/usr/bin/env bash
# Builds the Linux artifacts used by e2e tests (runs inside the rust:1 image):
# tsnx-host, the LD_PRELOAD shim and the vsock test client.
set -euo pipefail
cd /src
export CARGO_TARGET_DIR=/src/target/linux
cargo build -q -p tsnx-host -p tsnx-ffi ${CARGO_PROFILE_FLAG:-} ${TSNX_FFI_FEATURES:+--features tsnx-ffi/$TSNX_FFI_FEATURES}
out=/src/target/linux
inc="-Icrates/tsnx-ffi/include -Inative/driver -Inative/runtime -Inative/vsock"
cc -c -fPIC -O1 -g $inc native/driver/tsnx_driver.c -o $out/tsnx_driver.o
cc -c -fPIC -O1 -g $inc native/driver/tsnx_dns.c -o $out/tsnx_dns.o
cc -c -fPIC -O1 -g -DTSNX_BUILD_UNIX=$(date +%s) $inc native/driver/tsnx_app.c -o $out/tsnx_app.o
c++ -std=c++17 -shared -fPIC -O1 -g -Wall $inc -o $out/libtsnx_interpose.so \
  native/vsock/vsock.cpp native/runtime/runtime.cpp native/interpose/interpose.cpp \
  $out/tsnx_driver.o $out/tsnx_app.o $out/tsnx_dns.o $out/${RUST_PROFILE_DIR:-debug}/libtsnx_ffi.a -lpthread -ldl -lm
cc -O1 -g -Wall -o $out/vsock-test native/interpose/vsock_test.c
cc -O1 -g -Wall -o $out/heap-probe native/interpose/heap_probe.c -ldl
# A fixed path for the compose service, whichever profile was built.
mkdir -p $out/bin && cp $out/${RUST_PROFILE_DIR:-debug}/tsnx-host $out/bin/tsnx-host
echo "built ($RUST_PROFILE_DIR): $out/bin/tsnx-host, $out/libtsnx_interpose.so, $out/vsock-test"
