FROM rust:1.98-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /app/backend
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/backend/target \
    cargo build --release --locked --bin vi-server --bin vi-worker && \
    mkdir -p /out && cp target/release/vi-server target/release/vi-worker /out/
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd -r -u 10001 sentinel && mkdir -p /app/backend/data /var/lib/vi && chown -R sentinel:sentinel /app /var/lib/vi
WORKDIR /app
COPY --from=builder /out/vi-server /usr/local/bin/vi-server
COPY --from=builder /out/vi-worker /usr/local/bin/vi-worker
USER sentinel
ENV PORT=8080 BIND_ADDR=0.0.0.0
EXPOSE 8080
CMD ["vi-server"]
