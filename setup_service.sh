#!/bin/bash
# Run this after install.sh fails at nginx step (Docker port conflict)
set -e

echo "[1/4] Disabling Docker autostart..."
systemctl disable docker 2>/dev/null || true
systemctl disable docker.socket 2>/dev/null || true
systemctl stop docker 2>/dev/null || true
systemctl stop docker.socket 2>/dev/null || true

echo "[2/4] Creating data dirs..."
mkdir -p /opt/pcap-data/uploads /var/log/pcap-analyzer

echo "[3/4] Writing systemd service..."
JWT=$(openssl rand -hex 32)
cat > /etc/systemd/system/pcap-backend.service << EOF
[Unit]
Description=PCAP Analyzer Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/pcap/backend
Environment=DB_PATH=/opt/pcap-data/pcap.db
Environment=UPLOAD_DIR=/opt/pcap-data/uploads
Environment=JWT_SECRET=${JWT}
Environment=DEFAULT_USER=admin
Environment=DEFAULT_PASS=admin123
ExecStart=/opt/pcap-venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5
StandardOutput=append:/var/log/pcap-analyzer/backend.log
StandardError=append:/var/log/pcap-analyzer/backend.log

[Install]
WantedBy=multi-user.target
EOF

echo "[4/4] Starting services..."
systemctl daemon-reload
systemctl enable pcap-backend
systemctl start pcap-backend
systemctl restart nginx

sleep 3
if curl -sf http://localhost/api/health > /dev/null; then
    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "=============================="
    echo " Ready! Open: http://$IP"
    echo " Login: admin / admin123"
    echo "=============================="
else
    echo "Backend failed. Logs:"
    tail -20 /var/log/pcap-analyzer/backend.log
fi
