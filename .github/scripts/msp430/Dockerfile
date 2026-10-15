FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libncursesw5 libtinfo5 zlib1g libexpat1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ADD toolchain.tar.bz2 /opt/
ENV PATH="/opt/msp430-gcc-9.3.1.11_linux64/bin:${PATH}"
WORKDIR /work
ENTRYPOINT ["sh", "/harness/run-tests.sh"]
