FROM python:3.11-slim

# Install tshark + capinfos (wireshark-common)
# Pre-answer tshark debconf prompt to avoid interactive prompt blocking install
RUN apt-get update --allow-releaseinfo-change && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark \
        wireshark-common \
    && rm -rf /var/lib/apt/lists/*

# Allow tshark to run as non-root (tshark binary is setuid via dpkg-statoverride)
RUN dpkg-statoverride --update --add root wireshark 0750 /usr/bin/dumpcap || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
