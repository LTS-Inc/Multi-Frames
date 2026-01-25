#!/bin/bash
#
# Multi-Frames Installation Script
# Installs Multi-Frames as a systemd service on Linux
#
# Usage:
#   sudo ./install.sh [options]
#
# Options:
#   --port PORT     Port to run on (default: 80)
#   --user USER     User to run as (default: root)
#   --uninstall     Remove Multi-Frames
#   --no-start      Install but don't start
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Defaults
INSTALL_DIR="/opt/multi-frames"
SERVICE_NAME="multi-frames"
PORT=80
USER="root"
START_SERVICE=true
UNINSTALL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            PORT="$2"
            shift 2
            ;;
        --user)
            USER="$2"
            shift 2
            ;;
        --no-start)
            START_SERVICE=false
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Uninstall
if [ "$UNINSTALL" = true ]; then
    echo -e "${YELLOW}Uninstalling Multi-Frames...${NC}"
    
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    systemctl daemon-reload
    
    echo -e "${YELLOW}Remove installation directory $INSTALL_DIR? [y/N]${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -rf $INSTALL_DIR
        echo -e "${GREEN}Directory removed${NC}"
    else
        echo -e "${YELLOW}Directory kept (contains config)${NC}"
    fi
    
    echo -e "${GREEN}Multi-Frames uninstalled${NC}"
    exit 0
fi

echo -e "${GREEN}"
echo "  __  __       _ _   _       ______                         "
echo " |  \/  |     | | | (_)     |  ____|                        "
echo " | \  / |_   _| | |_ _ ___  | |__ _ __ __ _ _ __ ___   ___  "
echo " | |\/| | | | | | __| |___ \|  __| '__/ _\` | '_ \` _ \ / _ \ "
echo " | |  | | |_| | | |_| |___) | |  | | | (_| | | | | | |  __/ "
echo " |_|  |_|\__,_|_|\__|_|____/|_|  |_|  \__,_|_| |_| |_|\___| "
echo -e "${NC}"
echo "  Installation Script"
echo ""

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is required but not installed${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo -e "Found Python $PYTHON_VERSION"

# Create install directory
echo -e "${YELLOW}Creating installation directory...${NC}"
mkdir -p $INSTALL_DIR

# Copy files
echo -e "${YELLOW}Copying files...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/multi_frames.py" ]; then
    cp "$SCRIPT_DIR/multi_frames.py" $INSTALL_DIR/
else
    echo -e "${RED}multi_frames.py not found in $SCRIPT_DIR${NC}"
    exit 1
fi

chmod +x $INSTALL_DIR/multi_frames.py

# Preserve existing config
if [ -f "$INSTALL_DIR/multi_frames_config.json" ]; then
    echo -e "${GREEN}Existing configuration preserved${NC}"
fi

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Multi-Frames Dashboard Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/multi_frames.py --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Enable service
echo -e "${YELLOW}Enabling service...${NC}"
systemctl enable $SERVICE_NAME

# Start service
if [ "$START_SERVICE" = true ]; then
    echo -e "${YELLOW}Starting service...${NC}"
    systemctl start $SERVICE_NAME
    sleep 2
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}Service started successfully${NC}"
    else
        echo -e "${RED}Service failed to start. Check: journalctl -u $SERVICE_NAME${NC}"
        exit 1
    fi
fi

# Get IP
IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Multi-Frames installed successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Access your dashboard at:"
echo -e "    ${YELLOW}http://$IP:$PORT${NC}"
echo ""
echo -e "  Default credentials:"
echo -e "    Username: ${YELLOW}admin${NC}"
echo -e "    Password: ${YELLOW}admin123${NC}"
echo ""
echo -e "  ${RED}⚠ Change the default password immediately!${NC}"
echo ""
echo -e "  Service commands:"
echo -e "    sudo systemctl status $SERVICE_NAME"
echo -e "    sudo systemctl restart $SERVICE_NAME"
echo -e "    sudo journalctl -u $SERVICE_NAME -f"
echo ""
