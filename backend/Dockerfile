FROM python:3.11-slim

# Install tshark + capinfos (wireshark-common)
RUN apt-get update && \
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
