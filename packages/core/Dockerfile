# =============================================================================
# x0 - Payment Infrastructure for AI Agents
# Multi-stage Docker build for production deployment
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM rust:1.87-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests first (for better layer caching)
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./
COPY rust-toolchain.toml ./

# Create dummy main.rs to cache dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo fetch

# Build dependencies only (cached layer)
RUN cargo build --release || true

# Copy actual source code
COPY src ./src
COPY migrations ./migrations

# Build arguments for compile-time configuration
ARG BUILD_TIMESTAMP
ARG GIT_HASH
ARG BUILD_FEATURES=""

# Set build-time environment variables
ENV BUILD_TIMESTAMP=${BUILD_TIMESTAMP:-unknown}
ENV GIT_HASH=${GIT_HASH:-unknown}

# Build the actual application
RUN touch src/main.rs && \
    if [ -n "$BUILD_FEATURES" ]; then \
        cargo build --release --features "$BUILD_FEATURES"; \
    else \
        cargo build --release; \
    fi

# Verify the binary was created
RUN test -f /app/target/release/x0 || test -f /app/target/release/x0-core

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Labels for container registry
LABEL org.opencontainers.image.title="x0"
LABEL org.opencontainers.image.description="Payment Infrastructure for AI Agents"
LABEL org.opencontainers.image.vendor="x0 Labs"
LABEL org.opencontainers.image.source="https://github.com/x0-labs/x0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 x0 \
    && useradd --uid 1000 --gid x0 --shell /bin/bash --create-home x0

WORKDIR /app

# Copy binary from builder (try both possible names)
COPY --from=builder /app/target/release/x0* /usr/local/bin/
RUN if [ -f /usr/local/bin/x0-core ]; then \
        mv /usr/local/bin/x0-core /usr/local/bin/x0; \
    fi && \
    chmod +x /usr/local/bin/x0

# Copy migrations
COPY --from=builder /app/migrations ./migrations

# Set ownership
RUN chown -R x0:x0 /app

# Switch to non-root user
USER x0

# Environment configuration
ENV RUST_LOG=info,sqlx=warn,tower_http=info
ENV RUST_BACKTRACE=1
ENV PORT=8080

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

# Use tini as init system to handle signals properly
ENTRYPOINT ["/usr/bin/tini", "--"]

# Run the application
CMD ["/usr/local/bin/x0"]
