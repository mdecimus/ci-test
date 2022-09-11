FROM rust:latest AS chef 
RUN cargo install cargo-chef 
RUN rustup component add rustfmt
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml .
COPY Cargo.lock .
COPY src/ src/
COPY resources/ resources/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM scratch AS runtime

COPY --from=builder /app/target/x86_64-unknown-linux-musl/stalwart-jmap /usr/bin/stalwart-jmap
RUN addgroup -S stalwart-jmap && adduser -S stalwart-jmap -G stalwart-jmap
RUN mkdir -p /var/lib/stalwart-jmap
RUN mkdir -p /etc/stalwart-jmap
RUN chown stalwart-jmap:stalwart-jmap /var/lib/stalwart-jmap
RUN chown stalwart-jmap:stalwart-jmap /etc/stalwart-jmap

USER stalwart-jmap

ENTRYPOINT ["/usr/bin/stalwart-jmap"]
