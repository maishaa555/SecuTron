FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 secutron \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin secutron
WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/target/release/secutron /usr/local/bin/secutron
COPY --chown=10001:10001 web ./web
USER 10001:10001
EXPOSE 8765
ENTRYPOINT ["/usr/local/bin/secutron"]
CMD ["serve", "--bind", "0.0.0.0:8765", "--public-origin", "http://127.0.0.1:8765"]

