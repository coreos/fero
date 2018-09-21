FROM rust:1.27-stretch as build

ADD https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
    /tmp/protoc.zip

RUN apt-get update && \
    apt-get install -yy \
        build-essential \
        cmake \
        golang-go \
        libsqlite3-dev \
        unzip && \
    unzip -d /usr /tmp/protoc.zip

WORKDIR /usr/src/fero
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./fero-client/ ./fero-client/
COPY ./fero-bastion/ ./fero-bastion/
COPY ./fero-proto/ ./fero-proto/
COPY ./fero-server/ ./fero-server/
RUN cargo build --release --package fero-bastion

FROM debian:stretch-slim
WORKDIR /opt/fero-bastion/bin
EXPOSE 50051
ENTRYPOINT ["./fero-bastion"]
COPY --from=build /usr/src/fero/target/release/fero-bastion .
