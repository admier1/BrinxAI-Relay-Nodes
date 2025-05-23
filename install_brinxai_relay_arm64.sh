#!/bin/bash

set -e

IMAGE_NAME="admier/brinxai_nodes-relay:arm64"
CONTAINER_NAME="brinxai_relay_arm64"

# Function to validate UUID format
validate_uuid() {
    local uuid=$1
    if [[ $uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Prompt user for node_UUID
while true; do
    read -p "Enter the node_UUID (must be a valid UUID, e.g., 123e4567-e89b-12d3-a456-426614174000): " NODE_UUID
    if validate_uuid "$NODE_UUID"; then
        echo "✅ Valid UUID provided."
        break
    else
        echo "❌ Invalid UUID format. Please provide a valid UUID (e.g., 123e4567-e89b-12d3-a456-426614174000)."
    fi
done

# Save UUID to .env file
echo "💾 Saving node_UUID to .env file..."
echo "NODE_UUID=$NODE_UUID" > .env

echo "🔧 Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed"
else
    echo "✅ Docker already installed"
fi

echo "🔐 Enabling IP forwarding..."
sudo tee -a /etc/sysctl.conf <<< 'net.ipv4.ip_forward = 1'
sudo sysctl -p

# 🧱 Set up NAT masquerading with iptables
EXT_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
echo "🌍 Detected external interface: $EXT_IFACE"
sudo iptables -t nat -A POSTROUTING -s 192.168.255.0/24 -o $EXT_IFACE -j MASQUERADE

echo "💾 Making iptables rules persistent..."
sudo apt-get update
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

echo "🌐 Creating OpenVPN volume..."
docker volume create openvpn_data

echo "🐳 Pulling latest image from Docker Hub..."
docker pull $IMAGE_NAME

echo "🧼 Removing old container if it exists..."
docker rm -f $CONTAINER_NAME || true

echo "🚀 Running VPN relay container..."
docker run -d \
  --name $CONTAINER_NAME \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --network host \
  --restart always \
  -v openvpn_data:/etc/openvpn \
  -e NODE_UUID=$NODE_UUID \
  --label=com.centurylinklabs.watchtower.enable=true \
  $IMAGE_NAME

echo "📡 Deploying Watchtower to monitor and update the container..."
docker rm -f watchtower || true
docker run -d \
  --name watchtower \
  --restart always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower \
  --include-restarting \
  --label-enable \
  --schedule "0 0 4 * * *" # Run daily at 4 AM

echo "✅ VPN relay (arm64) is running and Watchtower will auto-update it daily when a new version of '$IMAGE_NAME' is available!"
