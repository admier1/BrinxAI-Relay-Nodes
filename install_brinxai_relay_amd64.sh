#!/bin/bash

set -e

IMAGE_NAME="admier/brinxai_nodes-relay:latest"
CONTAINER_NAME="brinxai_relay_amd64"
VOLUME_NAME="openvpn_data"

# Function to validate UUID format
validate_uuid() {
    local uuid=$1
    [[ $uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

# Prompt user for node_UUID
while true; do
    read -p "Enter the node_UUID (valid UUID, e.g., 123e4567-e89b-12d3-a456-426614174000): " NODE_UUID
    if validate_uuid "$NODE_UUID"; then
        echo "✅ Valid UUID provided."
        break
    else
        echo "❌ Invalid UUID format. Try again."
    fi
done

# Save UUID to .env
echo "💾 Saving node_UUID to .env..."
echo "NODE_UUID=$NODE_UUID" > .env

# Check if Docker is installed
echo "🔧 Checking for Docker..."
if ! command -v docker &>/dev/null; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    echo "⚠️ Please log out and log back in, or run 'newgrp docker' to refresh group permissions."
    exit 1
else
    echo "✅ Docker is installed."
fi

# Check Docker access
if ! docker info &>/dev/null; then
    echo "❌ You don't have permission to access Docker. Trying with sudo..."
    USE_SUDO=true
else
    USE_SUDO=false
fi

# Enable IP forwarding
echo "🔐 Enabling IP forwarding..."
sudo tee /etc/sysctl.d/99-ip-forward.conf <<< 'net.ipv4.ip_forward=1'
sudo sysctl --system

# Set up NAT masquerading
EXT_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
echo "🌍 Detected external interface: $EXT_IFACE"
sudo iptables -t nat -A POSTROUTING -s 192.168.255.0/24 -o "$EXT_IFACE" -j MASQUERADE

# Make iptables rules persistent
echo "💾 Making iptables rules persistent..."
sudo apt-get update
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

# Docker volume creation
echo "🌐 Creating Docker volume: $VOLUME_NAME"
if [ "$USE_SUDO" = true ]; then
    sudo docker volume create "$VOLUME_NAME"
else
    docker volume create "$VOLUME_NAME"
fi

# Pull image
echo "🐳 Pulling image: $IMAGE_NAME"
$USE_SUDO && sudo docker pull "$IMAGE_NAME" || docker pull "$IMAGE_NAME"

# Stop and remove existing container
echo "🧼 Cleaning up old container (if exists)..."
$USE_SUDO && sudo docker rm -f "$CONTAINER_NAME" || docker rm -f "$CONTAINER_NAME"

# Start VPN relay container
echo "🚀 Running VPN relay container..."
$USE_SUDO && sudo docker run -d \
  --name "$CONTAINER_NAME" \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --network host \
  --restart always \
  -v "$VOLUME_NAME":/etc/openvpn \
  -e NODE_UUID="$NODE_UUID" \
  --label=com.centurylinklabs.watchtower.enable=true \
  "$IMAGE_NAME" \
|| docker run -d \
  --name "$CONTAINER_NAME" \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --network host \
  --restart always \
  -v "$VOLUME_NAME":/etc/openvpn \
  -e NODE_UUID="$NODE_UUID" \
  --label=com.centurylinklabs.watchtower.enable=true \
  "$IMAGE_NAME"

# Watchtower setup
echo "📡 Deploying Watchtower..."
$USE_SUDO && sudo docker rm -f watchtower || docker rm -f watchtower

$USE_SUDO && sudo docker run -d \
  --name watchtower \
  --restart always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower \
  --include-restarting \
  --label-enable \
  --schedule "0 0 4 * * *" \
|| docker run -d \
  --name watchtower \
  --restart always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower \
  --include-restarting \
  --label-enable \
  --schedule "0 0 4 * * *"

echo "✅ VPN relay is now running. Watchtower will auto-update daily at 4 AM."
