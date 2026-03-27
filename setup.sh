#!/bin/bash
# PCAP Analyzer - Ubuntu Server Setup Script
# Run this on your Ubuntu Server VM

set -e

echo "=== PCAP Analyzer Setup ==="
echo ""

# 1. Update system
echo "[1/5] Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# 2. Install Docker
echo "[2/5] Installing Docker..."
if ! command -v docker &> /dev/null; then
    sudo apt-get install -y ca-certificates curl gnupg lsb-release
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo usermod -aG docker $USER
    echo "Docker installed. You may need to log out and back in for group changes."
else
    echo "Docker already installed."
fi

# 3. Install Docker Compose (standalone)
echo "[3/5] Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    sudo curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
else
    echo "Docker Compose already installed."
fi

# 4. Setup .env file
echo "[4/5] Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a random JWT secret
    JWT_SECRET=$(openssl rand -hex 32)
    sed -i "s/your-super-secret-jwt-key-change-this/$JWT_SECRET/" .env
    echo ""
    echo "  Created .env file with a random JWT secret."
    echo "  IMPORTANT: Edit .env to set your admin password before starting!"
    echo ""
else
    echo ".env already exists."
fi

# 5. Build and start
echo "[5/5] Building and starting PCAP Analyzer..."
docker-compose up -d --build

echo ""
echo "=== Setup Complete! ==="
echo ""
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "  Access the app at: http://$SERVER_IP"
echo ""
echo "  Default credentials:"
grep DEFAULT_USER .env || echo "  Username: admin"
grep DEFAULT_PASS .env || echo "  Password: admin123"
echo ""
echo "  To view logs: docker-compose logs -f"
echo "  To stop:      docker-compose down"
echo "  To update:    git pull && docker-compose up -d --build"
