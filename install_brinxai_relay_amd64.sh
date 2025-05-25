#!/bin/bash

set -e

IMAGE_NAME="admier/brinxai_nodes-relay:latest"
CONTAINER_NAME="brinxai_relay_amd64"

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

# Install Docker if not present
echo "🔧 Checking for Docker..."
if ! command -v docker &> /dev/null; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "⚠️ Please log out and back in or run 'newgrp docker' to apply Docker group permissions."
else
    echo "✅ Docker already installed."
fi

# Ensure script runs with proper permissions
if ! docker info > /dev/null 2>&1; then
    echo "❌ You don't have permission to run Docker. Try running this script with sudo or ensure your user is in the docker group."
    exit 1
fi

# Enable IP forwarding
echo "🔐 Enabling IP forwarding..."
sudo tee /etc/sysctl.d/99-ip-forward.conf <<< 'net.ipv4.ip_forward=1'
sudo sysctl --system

# Set up NAT masquerading
EXT_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
echo "🌍 Detected external interface: $EXT_IFACE"
sudo iptables -t nat -A POSTROUTING -s 192.168.255.0/24 -o $EXT_IFACE -j MASQUERADE

echo "💾 Making iptables rules persistent..."
sudo apt-get update
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

# Create Docker volume
echo "🌐 Creating OpenVPN volume..."
docker volume create openvpn_data

# Pull Docker image
echo "🐳 Pulling latest image: $IMAGE_NAME"
docker pull $IMAGE_NAME

# Remove old container
echo "🧼 Removing old container if exists..."
docker rm -f $CONTAINER_NAME || true

# Run container
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

# Setup Watchtower
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

echo "✅ VPN relay (amd64) is running. Watchtower will check for updates daily at 4 AM."
