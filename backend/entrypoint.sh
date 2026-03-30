#!/bin/bash
set -e

# Install tshark at runtime if not already present.
# This runs when the container starts, not during image build,
# so the network is always available.
if ! command -v tshark &> /dev/null; then
    echo "[entrypoint] tshark not found — installing..."
    apt-get update -qq && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark wireshark-common && \
    rm -rf /var/lib/apt/lists/* && \
    dpkg-statoverride --update --add root wireshark 0750 /usr/bin/dumpcap 2>/dev/null || true
    echo "[entrypoint] tshark installed: $(tshark --version | head -1)"
else
    echo "[entrypoint] tshark already available: $(tshark --version | head -1)"
fi

exec "$@"
