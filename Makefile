# Top-level entry points. Switch builds run inside the tsnx-build Docker image
# (devkitA64 + libnx + Rust nightly) so nothing beyond Docker is needed on the
# host. Set IN_DOCKER=1 to run the Switch steps directly (e.g. in CI).

SWITCH_TARGET := aarch64-nintendo-switch-freestanding
# Build time: a floor for "is the console's clock plausible" (TLS needs it).
BUILD_UNIX := $(shell date +%s)
export TSNX_BUILD_UNIX := $(BUILD_UNIX)
RUST_SWITCH_FLAGS := --release --target $(SWITCH_TARGET) -Zbuild-std=core,alloc
DOCKER_IMAGE := tsnx-build

ifeq ($(IN_DOCKER),1)
  SW :=
else
  SW := docker run --rm -v "$(CURDIR)":/src -v tsnx-cargo-registry:/opt/cargo/registry -e CARGO_TARGET_DIR=/src/target/switch -w /src $(DOCKER_IMAGE)
endif

.PHONY: release overlay mitm-test nxlink-mitm-test all host-test host-c e2e sysmodule libstratosphere docker-image rust-switch nro nxlink clean

all: host-test nro

host-test:
	cargo test --workspace

# Local tailnet end-to-end tests (headscale + stock tailscaled in Docker).
e2e:
	e2e/setup.sh
	e2e/run-tests.sh

# Host build of the C driver + FFI (the Switch app's code paths, on the Mac).
HOST_C_SRCS := native/host/main.c native/driver/tsnx_driver.c native/driver/tsnx_app.c native/driver/tsnx_dns.c
host-c: target/tsnx-c

target/tsnx-c: $(HOST_C_SRCS) native/driver/*.h crates/tsnx-ffi/include/tsnx.h FORCE
	cargo build -p tsnx-ffi
	$(CC) -O1 -g -Wall -Wextra -DTSNX_BUILD_UNIX=$(BUILD_UNIX) -o $@ $(HOST_C_SRCS) -Icrates/tsnx-ffi/include -Inative/driver \
		target/debug/libtsnx_ffi.a -framework CoreFoundation -framework Security

FORCE:

docker-image:
	docker build -t $(DOCKER_IMAGE) docker

rust-switch:
	$(SW) cargo build -p tsnx-ffi $(RUST_SWITCH_FLAGS)

nro: rust-switch
	$(SW) make -C switch/app TSNX_BUILD_UNIX=$(BUILD_UNIX)

# Send the NRO to hbmenu's netloader (press Y on the console first) and stream
# its stdout back. NXLINK_HOST is the console's IP; broadcast discovery does not
# work from inside Docker Desktop.
# Atmosphère's libstratosphere (pinned to the console's Atmosphère, 1.12.0).
LIBSTRAT := third_party/Atmosphere/libraries/libstratosphere/lib/nintendo_nx_arm64_armv8a/release/libstratosphere.a
libstratosphere: $(LIBSTRAT)
$(LIBSTRAT):
	$(SW) make -C third_party/Atmosphere/libraries/libstratosphere -j8

sysmodule: rust-switch $(LIBSTRAT)
	$(SW) make -C switch/sysmodule TSNX_BUILD_UNIX=$(BUILD_UNIX) dist

# Release zip for the SD card root: dist/tailscale-nx-<version>.zip
release:
	tools/package-release.sh

# Tesla/Ultrahand overlay: status, on/off and login QR (switch/overlay).
overlay:
	$(SW) make -C switch/overlay

# Socket-virtualization suite as plain homebrew, through the sysmodule's
# bsd:u MITM. Needs tools/echo-server.py running on the tailnet peer
# (MITM_PEER, e.g. this Mac's `tailscale ip -4`).
mitm-test:
	$(SW) make -C switch/mitm-test

nxlink-mitm-test: mitm-test target/nxlink
	@test -n "$(NXLINK_HOST)" -a -n "$(MITM_PEER)" || (echo "set NXLINK_HOST=<switch ip> MITM_PEER=<tailnet peer ip>" && false)
	script -q target/nxlink-mitm.log target/nxlink -a $(NXLINK_HOST) -s switch/mitm-test/mitm-test.nro $(MITM_PEER) $(MITM_PASSTHROUGH)

nxlink: nro target/nxlink
	@test -n "$(NXLINK_HOST)" || (echo "set NXLINK_HOST=<switch ip>" && false)
	# `script` gives nxlink a pty so the console's log streams line by line
	# (also into target/nxlink.log).
	script -q target/nxlink.log target/nxlink -a $(NXLINK_HOST) -s switch/app/tsnx-app.nro

# nxlink built natively (switchbrew/switch-tools): the console has to connect
# back for stdout, which is simplest without Docker's port mapping.
target/nxlink:
	rm -rf target/switch-tools && git clone -q --depth 1 https://github.com/switchbrew/switch-tools.git target/switch-tools
	$(CC) -O2 -o $@ target/switch-tools/src/nxlink.c -lz

clean:
	cargo clean
	$(SW) make -C switch/app TSNX_BUILD_UNIX=$(BUILD_UNIX) clean

# Interpose shim (run unmodified programs through the socket virtualization
# layer) and its test client, for macOS.
VSOCK_SRCS := native/vsock/vsock.cpp native/runtime/runtime.cpp native/interpose/interpose.cpp
VSOCK_C_SRCS := native/driver/tsnx_driver.c native/driver/tsnx_app.c
VSOCK_INC := -Icrates/tsnx-ffi/include -Inative/driver -Inative/runtime -Inative/vsock
.PHONY: interpose
interpose: target/libtsnx_interpose.dylib target/vsock-test

target/libtsnx_interpose.dylib: $(VSOCK_SRCS) $(VSOCK_C_SRCS) native/*/*.h* FORCE
	cargo build -p tsnx-ffi
	$(CC) -c -O1 -g -Wall $(VSOCK_INC) native/driver/tsnx_driver.c -o target/tsnx_driver.o
	$(CC) -c -O1 -g -Wall -DTSNX_BUILD_UNIX=$(BUILD_UNIX) $(VSOCK_INC) native/driver/tsnx_app.c -o target/tsnx_app.o
	$(CC) -c -O1 -g -Wall $(VSOCK_INC) native/driver/tsnx_dns.c -o target/tsnx_dns.o
	$(CXX) -std=c++17 -O1 -g -Wall -dynamiclib -o $@ $(VSOCK_INC) $(VSOCK_SRCS) target/tsnx_driver.o target/tsnx_app.o target/tsnx_dns.o \
		target/debug/libtsnx_ffi.a -framework CoreFoundation -framework Security

target/vsock-test: native/interpose/vsock_test.c
	$(CC) -O1 -g -Wall -o $@ $<
