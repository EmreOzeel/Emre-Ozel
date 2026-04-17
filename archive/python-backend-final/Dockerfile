FROM python:3.11-slim

# Install tshark at build time (reliable network during docker build)
RUN apt-get update -qq && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark wireshark-common curl && \
    dpkg-statoverride --update --add root wireshark 0750 /usr/bin/dumpcap 2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
