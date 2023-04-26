FROM debian:bullseye

RUN DEBIAN_FRONTEND=noninteractive set -ex \
    && sed -i -- 's/# deb-src/deb-src/g' /etc/apt/sources.list \
    && echo "deb-src http://deb.debian.org/debian bullseye main" >>/etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
               build-essential \
               cdbs \
               debian-keyring \
               devscripts \
               equivs \
               fakeroot \
               git \
               less \
               quilt \
               rename \
               sudo \
               wget \
               vim \
    && apt build-dep -y libwolfssl24 \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/*

ARG USER=docker
ARG UID=1000
ARG GID=1000
RUN groupadd -f -g ${GID} docker && ( getent passwd ${UID} || useradd -ms /bin/bash ${USER} -u ${UID} -g ${GID} )
# Add user to sudoers
RUN usermod -aG sudo docker

WORKDIR /workdir
RUN chown docker /workdir && chown docker /home/docker -R
USER docker

# Set up quilt
RUN echo "alias dquilt="quilt --quiltrc=/home/docker/.quiltrc-dpkg"\n\
. /usr/share/bash-completion/completions/quilt\n\
complete -F _quilt_completion $_quilt_complete_opt dquilt\n" >> /home/docker/.bashrc
COPY .quiltrc-dpkg /home/docker/.

# Set up package maintainer info
ARG DEBEMAIL="your.email.address@example.org"
ARG DEBFULLNAME="Firstname Lastname"
ENV DEBEMAIL=${DEBEMAIL}
ENV DEBFULLNAME=${DEBFULLNAME}
