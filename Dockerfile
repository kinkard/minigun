FROM rust:alpine AS builder

# Dependencies for some crates
RUN apk add --no-cache alpine-sdk capnproto-dev

WORKDIR /usr/src/app

# First build a dummy target to cache dependencies in a separate Docker layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() { println!("Dummy image called!"); }' > src/main.rs
RUN cargo build --release

# Now build the real target
COPY src ./src
COPY schema ./schema
COPY build.rs .
# Update modified attribute as otherwise cargo won't rebuild it
RUN touch -a -m ./src/main.rs
RUN cargo build --release

FROM alpine AS runtime
COPY --from=builder /usr/src/app/target/release/minigun /usr/local/bin/minigun
CMD ["minigun"]
