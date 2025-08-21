FROM rust:1.89.0-alpine AS builder
ENV CARGO_INCREMENTAL=0
RUN apk add --no-cache libc-dev cmake make
WORKDIR /app

COPY Cargo.toml Cargo.lock /app
COPY src/ /app/src/

RUN cargo build --release --bin ohttp-proxy

FROM alpine:3.22.1 AS final
WORKDIR /app

COPY --from=builder /app/target/release/ohttp-proxy /usr/local/bin/ohttp-proxy
EXPOSE 32547
ENTRYPOINT ["ohttp-proxy"]