# Multi-stage build for rpc-replay
FROM rust:1.75-bullseye as builder

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire workspace
COPY . .

# Build the rpc-replay binary in release mode
RUN cargo build --release --bin rpc-replay

# Runtime stage - using Ubuntu as requested
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libgmp10 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user
RUN useradd -m -u 1000 appuser

# Create output directory
RUN mkdir -p /app/output && chown appuser:appuser /app/output

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rpc-replay /usr/local/bin/rpc-replay

# Set proper permissions
RUN chmod +x /usr/local/bin/rpc-replay

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Set environment variables for logging
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Default arguments (can be overridden at runtime)
ENV START_BLOCK=1309257
ENV RPC_URL="https://pathfinder-madara-ci.d.karnot.xyz"
ENV INTERVAL=30
ENV OUTPUT_DIR="/app/output"

# Expose volume for output files
VOLUME ["/app/output"]

# Default command - uses environment variables
CMD ["sh", "-c", "rpc-replay --start-block $START_BLOCK --rpc-url $RPC_URL --interval $INTERVAL --output-dir $OUTPUT_DIR"]