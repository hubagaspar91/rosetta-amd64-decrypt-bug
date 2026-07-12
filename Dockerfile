# Builder
FROM rust:1-slim AS builder
# ring compiles hand-written assembly, so it needs a C toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

# Runtime
FROM debian:stable-slim
COPY --from=builder /app/target/release/crypto-kat /usr/local/bin/crypto-kat
ENTRYPOINT ["/usr/local/bin/crypto-kat"]
