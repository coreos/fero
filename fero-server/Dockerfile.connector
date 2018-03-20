FROM debian:stretch-slim
EXPOSE 12345

RUN apt-get update && \
    apt-get install -yy libusb-1.0

ADD https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-1.0.1-debian9-amd64.tar.gz \
    /tmp/yubihsm-sdk.tar.gz

RUN tar xf /tmp/yubihsm-sdk.tar.gz -C /tmp && \
    dpkg -i /tmp/yubihsm2-sdk/yubihsm-connector_1.0.1-1_amd64.deb

ENTRYPOINT ["yubihsm-connector", "-l", "0.0.0.0:12345", "-d"]
