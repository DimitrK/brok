#!/usr/bin/env sh
set -eu

mkdir -p /var/run/broker-interceptor-ebpf
chmod 0770 /var/run/broker-interceptor-ebpf || true

mkdir -p /sys/fs/bpf
if ! mount | grep -q " /sys/fs/bpf "; then
  if ! mount -t bpf bpf /sys/fs/bpf; then
    echo "[ebpf-host] failed to mount bpffs at /sys/fs/bpf"
    exit 1
  fi
fi

echo "[ebpf-host] kernel: $(uname -r)"
echo "[ebpf-host] docker: $(dockerd --version)"

exec /usr/local/bin/dockerd-entrypoint.sh "$@"
