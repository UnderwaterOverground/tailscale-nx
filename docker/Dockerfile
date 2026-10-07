# Switch build image: devkitA64 + libnx + portlibs, plus Rust nightly for
# -Zbuild-std on the aarch64-nintendo-switch-freestanding target.
FROM devkitpro/devkita64:latest

ARG RUST_TOOLCHAIN=nightly-2026-09-25
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
         --default-toolchain ${RUST_TOOLCHAIN} -c rust-src \
    && chmod -R a+rwX /opt/rustup /opt/cargo

# Atmosphère 1.12.0's libstratosphere needs libnx newer than the 4.12.0
# package (firmware 23 commands), so build a pinned libnx master.
ARG LIBNX_COMMIT=feebd026ca0f5dcc2119f46ad8e0d16ad3dd4973
RUN apt-get update && apt-get install -y --no-install-recommends git make && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/switchbrew/libnx.git /tmp/libnx \
    && cd /tmp/libnx && git checkout ${LIBNX_COMMIT} \
    && . /opt/devkitpro/switchvars.sh 2>/dev/null; export DEVKITPRO=/opt/devkitpro \
    && make -C nx -j8 install && rm -rf /tmp/libnx

WORKDIR /src
