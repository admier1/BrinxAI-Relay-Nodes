#!/bin/bash
#
# BrinxAI Relay Node Installer - Single Container Version
#
# Runs a combined container containing OpenVPN and the BrinxAI status agent.
#
# Usage: Run from the BrinxAI_Relays directory
#   ./install_brinxai_relay.sh
#
set -e

# Configuration
DOCKER_REPO="admier/brinxai_nodes-relay"
CONTAINER_NAME="brinxai_relay"
RELAY_VOLUME="brinxai_relay_data"
VPN_SUBNET="192.168.255.0/24"
DEFAULT_VPN_PORT=1194

echo "🚀 BrinxAI Relay Node Installer (Single Container)"
echo "==============================================="

# Function to validate UUID format
validate_uuid() {
    local uuid=$1
    [[ $uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

# Prompt user for node_UUID
while true; do
    read -p "Enter the node_UUID (valid UUID): " NODE_UUID
    if validate_uuid "$NODE_UUID"; then
        echo "✅ Valid UUID provided."
        break
    else
        echo "❌ Invalid UUID format. Please try again."
    fi
done

# Ask for VPN port configuration
echo ""
read -p "Enter VPN port (default $DEFAULT_VPN_PORT): " VPN_PORT
if [[ -z "$VPN_PORT" ]]; then
    VPN_PORT=$DEFAULT_VPN_PORT
    echo "ℹ️  Using default port $VPN_PORT."
elif [[ ! "$VPN_PORT" =~ ^[0-9]+$ ]] || [ "$VPN_PORT" -lt 1 ] || [ "$VPN_PORT" -gt 65535 ]; then
    echo "❌ Invalid port number. Using default port $VPN_PORT."
    VPN_PORT=$DEFAULT_VPN_PORT
else
    echo "✅ VPN will run on port $VPN_PORT."
fi

# Ask if user wants Watchtower auto-updater
read -p "Do you want to enable Watchtower auto-updater? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ENABLE_WATCHTOWER=true
    echo "✅ Watchtower auto-updater will be enabled."
else
    ENABLE_WATCHTOWER=false
    echo "ℹ️  Watchtower auto-updater will be disabled."
fi

# Detect sudo usage
USE_SUDO=false
if ! docker info &> /dev/null; then
    if sudo docker info &> /dev/null; then
        USE_SUDO=true
        echo "🔐 Using sudo for Docker commands."
    else
        echo "❌ Docker is not accessible. Please install Docker or check permissions."
        exit 1
    fi
fi

DOCKER_CMD="docker"
if [ "$USE_SUDO" = true ]; then
    DOCKER_CMD="sudo docker"
fi

# Get public IP
echo "🌍 Getting public IP address..."
PUBLIC_IP=$(curl -s --connect-timeout 10 http://whatismyip.akamai.com/ || echo "")
if [ -z "$PUBLIC_IP" ]; then
    echo "❌ Could not retrieve public IP. Please check internet connection."
    exit 1
fi
echo "✅ Public IP: $PUBLIC_IP"

# Enable IP forwarding
echo "🔐 Enabling IP forwarding..."
sudo tee /etc/sysctl.d/99-ip-forward.conf <<< 'net.ipv4.ip_forward=1'
sudo sysctl --system

# Set up NAT masquerading
EXT_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
echo "🌍 Detected external interface: $EXT_IFACE"

# Clear any existing NAT rules for our subnet
sudo iptables -t nat -D POSTROUTING -s $VPN_SUBNET -o "$EXT_IFACE" -j MASQUERADE 2>/dev/null || true

# Add NAT masquerading rule
sudo iptables -t nat -A POSTROUTING -s $VPN_SUBNET -o "$EXT_IFACE" -j MASQUERADE

# Allow forwarding for VPN traffic
sudo iptables -A FORWARD -i tun+ -j ACCEPT 2>/dev/null || true
sudo iptables -A FORWARD -o tun+ -j ACCEPT 2>/dev/null || true
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# Make iptables rules persistent
echo "💾 Making iptables rules persistent..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update || echo "⚠️  Warning: apt-get update failed. Continuing anyway..."
    if sudo apt-get install -y iptables-persistent; then
        sudo netfilter-persistent save
    else
        echo "⚠️  Warning: Failed to install iptables-persistent. Rules may not persist after reboot."
    fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PKG_MGR=$(command -v dnf || command -v yum)
    sudo "$PKG_MGR" install -y iptables iptables-services
    sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
    sudo systemctl enable --now iptables
    echo "⚠️  $(basename "$PKG_MGR") based systems do not use iptables-persistent. Rules are saved to /etc/sysconfig/iptables and restored at boot by iptables.service."
elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm iptables iptables-nft iptables-persistent || true
    if command -v netfilter-persistent >/dev/null 2>&1; then
        sudo netfilter-persistent save
    else
        echo "⚠️  'netfilter-persistent' not available on Arch. Please ensure your firewall rules are saved via your preferred method."
    fi
else
    echo "⚠️  Unsupported package manager. Please ensure iptables rules persist after reboot."
fi

# Configure firewall rules for VPN and agent ports
echo "🛡️ Configuring firewall rules..."

# Check if UFW is installed and active
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -q "active"; then
        echo "📋 UFW firewall is active, adding rules..."
        
        # Allow VPN port
        if ! sudo ufw status | grep -q "$VPN_PORT/udp.*ALLOW"; then
            echo "  ✅ Adding VPN port $VPN_PORT/udp..."
            sudo ufw allow $VPN_PORT/udp comment "BrinxAI VPN Server"
        else
            echo "  ✅ VPN port $VPN_PORT/udp already allowed"
        fi
        
        # Allow agent health port
        if ! sudo ufw status | grep -q "8080.*ALLOW"; then
            echo "  ✅ Adding agent health port 8080/tcp..."
            sudo ufw allow 8080/tcp comment "BrinxAI Agent Health Endpoint"
        else
            echo "  ✅ Agent health port 8080/tcp already allowed"
        fi
        
        # Allow SSH if not already allowed
        if ! sudo ufw status | grep -q "OpenSSH.*ALLOW\|22.*ALLOW"; then
            echo "  ✅ Adding SSH access..."
            sudo ufw allow ssh comment "SSH Access"
        fi
        
        echo "  ✅ UFW rules configured successfully"
        
    elif echo "$UFW_STATUS" | grep -q "inactive"; then
        echo "⚠️  UFW firewall is installed but inactive"
        echo "📋 Would you like to enable UFW and configure rules? (y/n)"
        read -r enable_ufw
        if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
            echo "  🔄 Enabling UFW firewall..."
            sudo ufw --force enable
            sudo ufw allow ssh comment "SSH Access"
            sudo ufw allow $VPN_PORT/udp comment "BrinxAI VPN Server"
            sudo ufw allow 8080/tcp comment "BrinxAI Agent Health Endpoint"
            echo "  ✅ UFW enabled and configured"
        else
            echo "  ⚠️  Continuing without UFW. Make sure ports $VPN_PORT/udp and 8080/tcp are accessible."
        fi
    fi
else
    echo "📋 UFW not installed, using iptables rules only"
    echo "⚠️  Make sure ports $VPN_PORT/udp and 8080/tcp are accessible through any other firewall"
fi

# Stop and remove existing container
echo "🧹 Cleaning up existing container..."
$DOCKER_CMD stop $CONTAINER_NAME 2>/dev/null || true
$DOCKER_CMD rm $CONTAINER_NAME 2>/dev/null || true

# Create persistent volume for OpenVPN data
echo "🔄 Creating persistent volume..."
$DOCKER_CMD volume create $RELAY_VOLUME

# Detect architecture and pull appropriate image
echo "� Pulling BrinxAI relay image..."
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        IMAGE_TAG="$DOCKER_REPO:latest"
        ;;
    aarch64|arm64)
        IMAGE_TAG="$DOCKER_REPO:arm64"
        ;;
    *)
        echo "⚠️  Unknown architecture: $ARCH, using latest tag"
        IMAGE_TAG="$DOCKER_REPO:latest"
        ;;
esac

echo "ℹ️  Architecture: $ARCH"
echo "ℹ️  Using image: $IMAGE_TAG"

$DOCKER_CMD pull "$IMAGE_TAG"

# Generate OpenVPN configuration
echo "🔧 Generating OpenVPN configuration..."
$DOCKER_CMD run -v $RELAY_VOLUME:/etc/openvpn --rm $IMAGE_TAG ovpn_genconfig \
    -u "udp://$PUBLIC_IP:$VPN_PORT" \
    -s $VPN_SUBNET \
    -p "redirect-gateway def1 bypass-dhcp" \
    -p "dhcp-option DNS 8.8.8.8" \
    -p "dhcp-option DNS 8.8.4.4"

# Initialize PKI
echo "🔐 Initializing PKI (this may take a moment)..."
$DOCKER_CMD run -v $RELAY_VOLUME:/etc/openvpn --rm -it $IMAGE_TAG ovpn_initpki nopass

# Generate client certificate
echo "👤 Generating client certificate..."
$DOCKER_CMD run -v $RELAY_VOLUME:/etc/openvpn --rm $IMAGE_TAG easyrsa build-client-full client1 nopass

# Save client configuration in the volume so the agent can read it on startup
echo "📄 Saving client configuration..."
$DOCKER_CMD run -v $RELAY_VOLUME:/etc/openvpn --rm $IMAGE_TAG \
    sh -c 'ovpn_getclient client1 > /etc/openvpn/client1.ovpn'

# Start relay container
echo "🚀 Starting BrinxAI relay..."
$DOCKER_CMD run -d \
    --name $CONTAINER_NAME \
    --restart always \
    -p $VPN_PORT:1194/udp \
    -p 8080:8080/tcp \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun \
    -v $RELAY_VOLUME:/etc/openvpn \
    -e NODE_UUID="$NODE_UUID" \
    -e VPN_PORT="$VPN_PORT" \
    -e CENTRAL_SERVER="http://relay.brinxai.com:5002/status_update" \
    -e STATUS_INTERVAL="60" \
    $([ "$ENABLE_WATCHTOWER" = true ] && echo "--label=com.centurylinklabs.watchtower.enable=true") \
    "$IMAGE_TAG"

# Wait for container to start and initialize
echo "⏳ Waiting for relay server to initialize..."
sleep 30

# Test client config generation
echo "🧪 Testing client configuration generation..."
sleep 10  # Give more time for initialization
CLIENT_CONFIG=$($DOCKER_CMD exec $CONTAINER_NAME ovpn_getclient client1 2>/dev/null || echo "")
if [ ! -z "$CLIENT_CONFIG" ]; then
    echo "✅ Client configuration generated successfully"
    # Save client config for testing
    echo "$CLIENT_CONFIG" | sudo tee /tmp/brinxai_client.ovpn >/dev/null
    echo "💾 Client config saved to /tmp/brinxai_client.ovpn"
else
    echo "❌ Failed to generate client configuration"
fi

# Setup Watchtower if enabled
if [ "$ENABLE_WATCHTOWER" = true ]; then
    echo "📡 Setting up Watchtower auto-updater..."
    $DOCKER_CMD stop watchtower 2>/dev/null || true
    $DOCKER_CMD rm watchtower 2>/dev/null || true
    
    $DOCKER_CMD run -d \
        --name watchtower \
        --restart always \
        -v /var/run/docker.sock:/var/run/docker.sock \
        containrrr/watchtower \
        --include-restarting \
        --label-enable \
        --schedule "0 0 4 * * *"
    
    echo "✅ Watchtower will auto-update containers daily at 4 AM"
fi

# Display status and information
echo ""
echo "🎉 BrinxAI Relay Node Installation Complete!"
echo "==========================================="
echo ""
echo "📊 Container Status:"
$DOCKER_CMD ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(NAMES|$CONTAINER_NAME)"

echo ""
echo "🌐 Configuration Summary:"
echo "  - Node UUID: $NODE_UUID"
echo "  - Public IP: $PUBLIC_IP"
echo "  - VPN Port: $VPN_PORT/udp"
echo "  - VPN Subnet: $VPN_SUBNET"
echo "  - Agent Health Check: http://localhost:8080/health"

echo ""
echo "🔧 Management Commands:"
echo "  Check status:          docker ps --filter name=$CONTAINER_NAME"
echo "  View logs:             docker logs $CONTAINER_NAME"
echo "  Restart relay:         docker restart $CONTAINER_NAME"
echo "  Generate client config: docker exec $CONTAINER_NAME ovpn_getclient client1"
echo "  Add new client:        docker exec $CONTAINER_NAME easyrsa build-client-full CLIENT_NAME nopass"

echo ""
echo "🔍 Health Check:"
curl -s http://localhost:8080/health | python3 -m json.tool 2>/dev/null || echo "Agent health check endpoint not ready yet"

echo ""
echo "✅ Installation completed successfully!"
echo "   The agent will begin reporting to the central server shortly."
