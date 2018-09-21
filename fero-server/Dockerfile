FROM rust:1.27-stretch as build

ADD https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
    /tmp/protoc.zip

ADD https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-1.0.1-debian9-amd64.tar.gz \
    /tmp/yubihsm-sdk.tar.gz

RUN apt-get update && \
    apt-get install -yy \
        build-essential \
        clang \
        cmake \
        golang-go \
        libclang-dev \
        libgpgme11-dev \
        libgpg-error-dev \
        libusb-1.0 \
        libsqlite3-dev \
        unzip && \
    unzip -d /usr /tmp/protoc.zip

RUN tar xf /tmp/yubihsm-sdk.tar.gz -C /tmp && \
    dpkg -i /tmp/yubihsm2-sdk/libyubihsm1_1.0.1-1_amd64.deb && \
    dpkg -i /tmp/yubihsm2-sdk/libyubihsm-dev_1.0.1-1_amd64.deb && \
    dpkg -i /tmp/yubihsm2-sdk/yubihsm-connector_1.0.1-1_amd64.deb

WORKDIR /usr/src/fero
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./fero-client/ ./fero-client/
COPY ./fero-bastion/ ./fero-bastion/
COPY ./fero-proto/ ./fero-proto/
COPY ./fero-server/ ./fero-server/
RUN cargo build --release --package fero-server

FROM debian:stretch-slim
ADD https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-1.0.1-debian9-amd64.tar.gz \
    /tmp/yubihsm-sdk.tar.gz
RUN apt-get update && \
    apt-get install -yy \
        libcurl3 \
        libgpgme11-dev \
        libgpg-error-dev && \
    tar xf /tmp/yubihsm-sdk.tar.gz -C /tmp && \
    dpkg -i /tmp/yubihsm2-sdk/libyubihsm1_1.0.1-1_amd64.deb
VOLUME ["/fero"]
WORKDIR /opt/fero-server/bin
EXPOSE 50051
ENV RUST_BACKTRACE 1
ENTRYPOINT ["./fero-server", "-d", "/fero/fero.db", "-c", "yubihsm-connector:12345"]
COPY --from=build /usr/src/fero/fero-server/migrations ./migrations/
COPY --from=build /usr/src/fero/target/release/fero-server .
