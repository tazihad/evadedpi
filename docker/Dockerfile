# -----------------------------------------------------------------------------
# EvadeDPI Multi-Stage Dockerfile
# Cross-Platform DPI Circumvention Proxy (SOCKS5 & HTTP CONNECT on port 9090)
# -----------------------------------------------------------------------------

# Stage 1: Build binary using official Rust Alpine image
FROM rust:alpine AS builder

RUN apk update && apk add --no-cache \
    build-base \
    musl-dev

WORKDIR /usr/src/evadedpi

# Cache dependency compilation
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy project source and build release binary
COPY . .
RUN touch src/main.rs && cargo build --release

# Stage 2: Minimal runtime image
FROM alpine:latest

# Install CA certificates and time zone data
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 10001 evadedpi && \
    adduser -S -u 10001 -G evadedpi evadedpi

# Copy compiled binary from builder stage
COPY --from=builder /usr/src/evadedpi/target/release/evadedpi /usr/local/bin/evadedpi

# Run as non-root user
USER evadedpi

# Expose default unified proxy port
EXPOSE 9090

# Default environment variables for container runtime
ENV EVADEDPI_BIND=0.0.0.0
ENV EVADEDPI_PORT=9090

ENTRYPOINT ["evadedpi"]
CMD ["--bind", "0.0.0.0", "--port", "9090"]
