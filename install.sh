#!/bin/bash
# PCAP Analyzer — Docker-free installer
# Tested on Ubuntu 22.04 / 24.04
set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="/opt/pcap-data"
LOG_DIR="/var/log/pcap-analyzer"

echo "=============================="
echo " PCAP Analyzer — Installing"
echo "=============================="

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/6] Installing system packages..."
apt-get update -q
apt-get install -y \
    python3 python3-pip python3-venv \
    nginx \
    tshark \
    curl wget git \
    nodejs npm 2>/dev/null || true

# Node 20 via nodesource if system node is too old
NODE_VER=$(node --version 2>/dev/null | cut -c2- | cut -d. -f1)
if [ -z "$NODE_VER" ] || [ "$NODE_VER" -lt 18 ]; then
    echo "  Installing Node 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi

# ── 2. Python venv + backend deps ─────────────────────────────────────────────
echo "[2/6] Installing Python dependencies..."
python3 -m venv /opt/pcap-venv
/opt/pcap-venv/bin/pip install --quiet --upgrade pip
# Remove psycopg2-binary (we use SQLite), install rest
grep -v psycopg2 "$REPO_DIR/backend/requirements.txt" > /tmp/req.txt
/opt/pcap-venv/bin/pip install --quiet -r /tmp/req.txt

# ── 3. Build frontend ─────────────────────────────────────────────────────────
echo "[3/6] Building frontend..."
cd "$REPO_DIR/frontend"
npm install --silent
npm run build

# ── 4. Data directories ───────────────────────────────────────────────────────
echo "[4/6] Creating data directories..."
mkdir -p "$DATA_DIR/uploads" "$LOG_DIR"

# ── 5. Nginx config ───────────────────────────────────────────────────────────
echo "[5/6] Configuring nginx..."
cat > /etc/nginx/sites-available/pcap-analyzer << NGINX
server {
    listen 80 default_server;
    server_name _;
    client_max_body_size 200m;

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 360s;
        proxy_request_buffering off;
    }

    location / {
        root $REPO_DIR/frontend/dist;
        index index.html;
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/pcap-analyzer /etc/nginx/sites-enabled/
nginx -t
systemctl enable nginx
systemctl restart nginx

# ── 6. Systemd service for backend ────────────────────────────────────────────
echo "[6/6] Creating systemd service..."
cat > /etc/systemd/system/pcap-backend.service << SERVICE
[Unit]
Description=PCAP Analyzer Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR/backend
Environment=DB_PATH=$DATA_DIR/pcap.db
Environment=UPLOAD_DIR=$DATA_DIR/uploads
Environment=JWT_SECRET=$(openssl rand -hex 32)
Environment=DEFAULT_USER=admin
Environment=DEFAULT_PASS=admin123
ExecStart=/opt/pcap-venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/backend.log
StandardError=append:$LOG_DIR/backend.log

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable pcap-backend
systemctl restart pcap-backend

# ── Done ──────────────────────────────────────────────────────────────────────
sleep 3
if curl -sf http://localhost/api/health > /dev/null; then
    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "=============================="
    echo " Installation complete!"
    echo " Open: http://$IP"
    echo " Login: admin / admin123"
    echo "=============================="
else
    echo "ERROR: Backend did not start. Check logs:"
    echo "  journalctl -u pcap-backend -n 30"
    echo "  cat $LOG_DIR/backend.log"
    exit 1
fi
