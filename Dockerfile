# Start with a Rust base image for the build stage
FROM rust:latest as builder

# Create a new empty shell project
RUN USER=root cargo new --bin app
WORKDIR /app

# Copy your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# Build only the dependencies to cache them, to avoid rebuilding them unnecessarily
RUN cargo build --release
RUN rm src/*.rs

# Now, copy the source code
COPY ./src ./src

# Build for release. Assuming bulletproofs_server is your binary name, adjust as necessary
RUN rm ./target/release/deps/bulletproofs_server* || true
RUN cargo build --release

# Use Debian Bullseye as the final base image
FROM debian:bookworm-slim

# Install OpenSSL, ca-certificates for SSL support, and libc6 for newer GLIBC
RUN apt-get update && apt-get install -y \
    openssl \
    libssl-dev \
    ca-certificates \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Copy the build artifact from the build stage
COPY --from=builder /app/target/release/bulletproofs_server /app/bulletproofs_server

# Expose the port your application listens on
# EXPOSE your_app_port (Uncomment and modify this line if your application listens on a specific port)

# Set the working directory to /app
WORKDIR /app

# Set the startup command to run your binary
CMD ["./bulletproofs_server"]
