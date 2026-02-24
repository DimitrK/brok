FROM docker:27-dind

RUN apk add --no-cache \
  bash \
  bpftool \
  clang \
  coreutils \
  curl \
  gcc \
  git \
  iproute2 \
  jq \
  llvm \
  make \
  musl-dev \
  nodejs \
  npm \
  socat

COPY packages/interceptor-ebpf/docker/host-init.sh /usr/local/bin/host-init.sh
RUN chmod +x /usr/local/bin/host-init.sh

ENTRYPOINT ["/usr/local/bin/host-init.sh"]
CMD []
