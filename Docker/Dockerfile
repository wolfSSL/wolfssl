FROM ubuntu:22.04

RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y build-essential autoconf libtool

ARG USER=docker
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} docker && useradd -ms /bin/bash ${USER} -u ${UID} -g ${GID}

USER ${UID}:${GID}