#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# PCAP Analyzer — Production Installer for Ubuntu 22.04
# ══════════════════════════════════════════════════════════════════════════════
#
# This script is idempotent — safe to run multiple times.
#
# Usage:
#   sudo bash install.sh
#
# Prerequisites:
#   - Ubuntu 22.04 LTS (fresh or existing server)
#   - Root or sudo access
#   - Internet connectivity
#
set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/pcap-analyzer"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env"
ENV_TEMPLATE=".env.production.example"
NGINX_TEMPLATE="nginx/nginx.prod.conf"
NGINX_OUTPUT="nginx/nginx.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC}  $*"; }

# ── Pre-flight checks ───────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo)."
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   PCAP Analyzer — Production Installer       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# STEP 1: System dependencies
# ═════════════════════════════════════════════════════════════════════════════
info "Step 1/11: Installing system dependencies..."

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# Install packages idempotently (apt-get install -y is already idempotent)
apt-get install -y --no-install-recommends \
    docker.io docker-compose-plugin \
    tshark \
    libpcap-dev \
    curl wget git \
    ufw \
    fail2ban \
    logrotate \
    gettext-base \
    > /dev/null 2>&1

# Ensure Docker is running
systemctl enable docker --now 2>/dev/null || true

ok "System dependencies installed."

# ═════════════════════════════════════════════════════════════════════════════
# STEP 2: Docker permissions
# ═════════════════════════════════════════════════════════════════════════════
info "Step 2/11: Configuring Docker permissions..."

# Add the invoking user (not root) to docker group
REAL_USER="${SUDO_USER:-$USER}"
if id -nG "$REAL_USER" | grep -qw docker; then
    ok "User '$REAL_USER' already in docker group."
else
    usermod -aG docker "$REAL_USER"
    ok "Added '$REAL_USER' to docker group (re-login required for non-sudo usage)."
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 3: UFW firewall rules
# ═════════════════════════════════════════════════════════════════════════════
info "Step 3/11: Configuring firewall (UFW)..."

ufw default deny incoming  > /dev/null 2>&1 || true
ufw default allow outgoing > /dev/null 2>&1 || true

# Allow rules are idempotent — ufw skips duplicates
ufw allow ssh         > /dev/null 2>&1 || true
ufw allow 80/tcp      > /dev/null 2>&1 || true
ufw allow 443/tcp     > /dev/null 2>&1 || true
ufw allow 5514/udp    > /dev/null 2>&1 || true   # syslog
ufw allow 5514/tcp    > /dev/null 2>&1 || true   # syslog TCP
ufw allow 2055/udp    > /dev/null 2>&1 || true   # netflow

ufw --force enable > /dev/null 2>&1 || true

ok "Firewall configured (SSH, HTTP, HTTPS, Syslog, NetFlow)."

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4: Directory structure
# ═════════════════════════════════════════════════════════════════════════════
info "Step 4/11: Creating directory structure..."

# Install directory (copy repo if not already there)
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    # Sync files, preserving .env if it exists
    rsync -a --exclude='.git' --exclude='node_modules' --exclude='__pycache__' \
        --exclude='.env' --exclude='nginx/nginx.conf' \
        "$SCRIPT_DIR/" "$INSTALL_DIR/"
    ok "Project files synced to $INSTALL_DIR"
else
    ok "Already running from $INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Data directories
mkdir -p \
    "$INSTALL_DIR/backups" \
    "$INSTALL_DIR/nginx/ssl" \
    "$INSTALL_DIR/geoip" \
    "$INSTALL_DIR/scripts" \
    /data/uploads \
    /data/captures \
    /data/geoip

# Set ownership for Docker-accessible dirs
chown -R 1000:1000 /data 2>/dev/null || true

ok "Directories created."

# ═════════════════════════════════════════════════════════════════════════════
# STEP 5: Environment file
# ═════════════════════════════════════════════════════════════════════════════
info "Step 5/11: Checking environment configuration..."

if [ ! -f "$INSTALL_DIR/$ENV_FILE" ]; then
    if [ -f "$INSTALL_DIR/$ENV_TEMPLATE" ]; then
        cp "$INSTALL_DIR/$ENV_TEMPLATE" "$INSTALL_DIR/$ENV_FILE"
        chmod 600 "$INSTALL_DIR/$ENV_FILE"

        warn "Created $INSTALL_DIR/$ENV_FILE from template."
        echo ""
        echo "  ┌─────────────────────────────────────────────────────────────┐"
        echo "  │  ACTION REQUIRED: Edit the .env file before proceeding.     │"
        echo "  │                                                             │"
        echo "  │  At minimum, set:                                           │"
        echo "  │    DOMAIN=pcap.yourcompany.com                              │"
        echo "  │    POSTGRES_PASSWORD=\$(openssl rand -hex 32)                │"
        echo "  │    JWT_SECRET=\$(openssl rand -hex 64)                       │"
        echo "  │    DEFAULT_PASS=\$(openssl rand -base64 24)                  │"
        echo "  │                                                             │"
        echo "  │  Then re-run:  sudo bash install.sh                         │"
        echo "  └─────────────────────────────────────────────────────────────┘"
        echo ""
        exit 1
    else
        err "Neither $ENV_FILE nor $ENV_TEMPLATE found. Cannot continue."
        exit 1
    fi
fi

# Validate required variables
set -a
# shellcheck source=/dev/null
source "$INSTALL_DIR/$ENV_FILE"
set +a

MISSING=""
[ -z "${DOMAIN:-}" ]            && MISSING="$MISSING DOMAIN"
[ -z "${POSTGRES_PASSWORD:-}" ] && MISSING="$MISSING POSTGRES_PASSWORD"
[ -z "${JWT_SECRET:-}" ]        && MISSING="$MISSING JWT_SECRET"
[ -z "${DEFAULT_PASS:-}" ]      && MISSING="$MISSING DEFAULT_PASS"

if [ -n "$MISSING" ]; then
    err "Missing required variables in $ENV_FILE:$MISSING"
    echo "  Edit $INSTALL_DIR/$ENV_FILE and re-run."
    exit 1
fi

ok "Environment file validated (DOMAIN=$DOMAIN)."

# ═════════════════════════════════════════════════════════════════════════════
# STEP 6: Nginx config — domain substitution
# ═════════════════════════════════════════════════════════════════════════════
info "Step 6/11: Generating nginx configuration for $DOMAIN..."

export DOMAIN
envsubst '${DOMAIN}' < "$INSTALL_DIR/$NGINX_TEMPLATE" > "$INSTALL_DIR/$NGINX_OUTPUT"

ok "Nginx config written to $NGINX_OUTPUT"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 7: Backup cron job
# ═════════════════════════════════════════════════════════════════════════════
info "Step 7/11: Setting up daily database backup cron..."

CRON_CMD="0 2 * * * $INSTALL_DIR/scripts/backup.sh >> /var/log/pcap-backup.log 2>&1"
CRON_MARKER="pcap-analyzer-backup"

# Remove old entry if exists, then add fresh (idempotent)
( crontab -l 2>/dev/null | grep -v "$CRON_MARKER" || true
  echo "$CRON_CMD  # $CRON_MARKER"
) | crontab -

chmod +x "$INSTALL_DIR/scripts/backup.sh" 2>/dev/null || true

ok "Daily backup cron set (02:00, 7-day retention)."

# ═════════════════════════════════════════════════════════════════════════════
# STEP 8: Build and start services
# ═════════════════════════════════════════════════════════════════════════════
info "Step 8/11: Building and starting Docker services..."

cd "$INSTALL_DIR"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build 2>&1 | tail -5

ok "Docker services started."

# ═════════════════════════════════════════════════════════════════════════════
# STEP 9: Wait for backend health
# ═════════════════════════════════════════════════════════════════════════════
info "Step 9/11: Waiting for backend to become healthy..."

HEALTH_URL="http://localhost:8000/api/health"
MAX_WAIT=60
WAITED=0

# The backend is on the internal Docker network; probe via the container
while [ $WAITED -lt $MAX_WAIT ]; do
    if docker compose -f "$COMPOSE_FILE" exec -T backend curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
        ok "Backend healthy after ${WAITED}s."
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    printf "  waiting... %ds / %ds\r" "$WAITED" "$MAX_WAIT"
done

if [ $WAITED -ge $MAX_WAIT ]; then
    warn "Backend did not respond within ${MAX_WAIT}s."
    echo "  Check logs:  docker compose -f $COMPOSE_FILE logs backend"
    echo "  The service may still be starting — continuing..."
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 10: Database migrations
# ═════════════════════════════════════════════════════════════════════════════
info "Step 10/11: Running database migrations..."

docker compose -f "$COMPOSE_FILE" exec -T backend \
    alembic upgrade head 2>&1 || warn "Migrations may have already been applied."

ok "Database migrations complete."

# ═════════════════════════════════════════════════════════════════════════════
# STEP 11: Success
# ═════════════════════════════════════════════════════════════════════════════
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Installation Complete!                      ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  URL:       https://$DOMAIN"
echo "║  Also:      https://$SERVER_IP (if DNS not ready)"
echo "║                                                              ║"
echo "║  Login:     ${DEFAULT_USER:-admin} / ****** (from .env)      ║"
echo "║                                                              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  IMPORTANT: Change default password after first login!       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  Syslog Ingestion:                                           ║"
echo "║    Point firewalls to: $SERVER_IP:5514 (UDP/TCP)"
echo "║    See: scripts/paloalto_syslog_config.txt                   ║"
echo "║                                                              ║"
echo "║  SSL Certificate:                                            ║"
echo "║    sudo certbot certonly --standalone -d $DOMAIN"
echo "║    Then restart: docker compose -f $COMPOSE_FILE restart nginx"
echo "║                                                              ║"
echo "║  Useful commands:                                            ║"
echo "║    Logs:    docker compose -f $COMPOSE_FILE logs -f          ║"
echo "║    Stop:    docker compose -f $COMPOSE_FILE down             ║"
echo "║    Backup:  bash scripts/backup.sh                           ║"
echo "║    Update:  git pull && sudo bash install.sh                 ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
