#!/bin/bash
#
# Multi-Frames Installation Script
# Optimized for Raspberry Pi (also works on other Linux systems)
#
# Usage:
#   sudo ./install.sh [options]
#
# Options:
#   --port PORT       Port to run on (default: 80)
#   --user USER       User to run as (default: root)
#   --hostname NAME   Set system hostname
#   --install-deps    Install optional dependencies (zeroconf)
#   --kiosk           Enable kiosk mode (auto-start browser on boot)
#   --disable-blanking Disable screen blanking/sleep
#   --fix-wifi        Disable WiFi power management (fixes dropouts)
#   --no-start        Install but don't start
#   --update          Update existing installation
#   --uninstall       Remove Multi-Frames
#   --status          Show service status
#   --logs            Show recent logs
#
# Examples:
#   sudo ./install.sh                                    # Basic install
#   sudo ./install.sh --port 8080                        # Custom port
#   sudo ./install.sh --install-deps --fix-wifi          # Full Pi setup
#   sudo ./install.sh --kiosk --disable-blanking         # Kiosk display
#   sudo ./install.sh --hostname dashboard --install-deps # Named Pi with mDNS
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Defaults
INSTALL_DIR="/opt/multi-frames"
SERVICE_NAME="multi-frames"
CONFIG_FILE="multi_frames_config.json"
PORT=80
USER="root"
START_SERVICE=true
UNINSTALL=false
UPDATE_ONLY=false
INSTALL_DEPS=false
SET_HOSTNAME=""
SHOW_STATUS=false
SHOW_LOGS=false
KIOSK_MODE=false
DISABLE_BLANKING=false
FIX_WIFI=false

# Detect Raspberry Pi
IS_RASPBERRY_PI=false
PI_MODEL=""
PI_REVISION=""

detect_raspberry_pi() {
    if [ -f /proc/device-tree/model ]; then
        PI_MODEL=$(cat /proc/device-tree/model | tr -d '\0')
        if [[ "$PI_MODEL" == *"Raspberry Pi"* ]]; then
            IS_RASPBERRY_PI=true
        fi
    fi
    
    if [ "$IS_RASPBERRY_PI" = false ] && [ -f /proc/cpuinfo ]; then
        if grep -q "Raspberry Pi\|BCM" /proc/cpuinfo; then
            IS_RASPBERRY_PI=true
            PI_MODEL=$(grep "Model" /proc/cpuinfo | cut -d: -f2 | xargs 2>/dev/null || echo "Raspberry Pi")
        fi
        PI_REVISION=$(grep "Revision" /proc/cpuinfo | cut -d: -f2 | xargs 2>/dev/null || echo "")
    fi
}

detect_raspberry_pi

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
        --hostname)
            SET_HOSTNAME="$2"
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
        --update)
            UPDATE_ONLY=true
            shift
            ;;
        --install-deps)
            INSTALL_DEPS=true
            shift
            ;;
        --status)
            SHOW_STATUS=true
            shift
            ;;
        --logs)
            SHOW_LOGS=true
            shift
            ;;
        --kiosk)
            KIOSK_MODE=true
            shift
            ;;
        --disable-blanking)
            DISABLE_BLANKING=true
            shift
            ;;
        --fix-wifi)
            FIX_WIFI=true
            shift
            ;;
        --help|-h)
            echo -e "${CYAN}Multi-Frames Installation Script${NC}"
            echo -e "${DIM}Optimized for Raspberry Pi${NC}"
            echo ""
            echo "Usage: sudo ./install.sh [options]"
            echo ""
            echo -e "${BOLD}Basic Options:${NC}"
            echo "  --port PORT         Port to run on (default: 80)"
            echo "  --user USER         User to run as (default: root)"
            echo "  --hostname NAME     Set system hostname"
            echo "  --install-deps      Install dependencies (zeroconf for mDNS)"
            echo "  --no-start          Install but don't start service"
            echo "  --update            Update existing installation"
            echo "  --uninstall         Remove Multi-Frames completely"
            echo ""
            echo -e "${BOLD}Raspberry Pi Options:${NC}"
            echo "  --kiosk             Enable kiosk mode (auto-start browser)"
            echo "  --disable-blanking  Disable screen blanking/screensaver"
            echo "  --fix-wifi          Disable WiFi power management"
            echo ""
            echo -e "${BOLD}Monitoring:${NC}"
            echo "  --status            Show service status"
            echo "  --logs              Show recent logs (follow mode)"
            echo "  --help              Show this help"
            echo ""
            echo -e "${BOLD}Examples:${NC}"
            echo "  sudo ./install.sh                           # Basic install on port 80"
            echo "  sudo ./install.sh --port 8080               # Install on port 8080"
            echo "  sudo ./install.sh --install-deps --fix-wifi # Full Pi setup"
            echo "  sudo ./install.sh --kiosk --disable-blanking # Kiosk display mode"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Show status
if [ "$SHOW_STATUS" = true ]; then
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Multi-Frames Service Status${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    systemctl status $SERVICE_NAME --no-pager 2>/dev/null || echo -e "${YELLOW}Service not installed${NC}"
    echo ""
    
    if [ "$IS_RASPBERRY_PI" = true ]; then
        echo -e "${BOLD}Raspberry Pi Status:${NC}"
        # Temperature
        if command -v vcgencmd &> /dev/null; then
            TEMP=$(vcgencmd measure_temp 2>/dev/null | cut -d= -f2)
            echo -e "  Temperature: ${CYAN}$TEMP${NC}"
            
            # Throttling
            THROTTLE=$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)
            if [ "$THROTTLE" = "0x0" ]; then
                echo -e "  Throttling:  ${GREEN}None${NC}"
            else
                echo -e "  Throttling:  ${RED}$THROTTLE (check power supply)${NC}"
            fi
        fi
        
        # Memory
        FREE_MEM=$(free -m | awk '/Mem:/ {print $4}')
        TOTAL_MEM=$(free -m | awk '/Mem:/ {print $2}')
        echo -e "  Memory:      ${CYAN}${FREE_MEM}MB free / ${TOTAL_MEM}MB total${NC}"
        
        # Uptime
        UPTIME=$(uptime -p 2>/dev/null || uptime)
        echo -e "  System:      ${CYAN}$UPTIME${NC}"
        echo ""
    fi
    exit 0
fi

# Show logs
if [ "$SHOW_LOGS" = true ]; then
    echo -e "${CYAN}Multi-Frames Logs (Ctrl+C to exit)${NC}"
    echo ""
    journalctl -u $SERVICE_NAME -f --no-pager
    exit 0
fi

# Uninstall
if [ "$UNINSTALL" = true ]; then
    echo -e "${YELLOW}Uninstalling Multi-Frames...${NC}"
    
    # Stop and disable service
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    
    # Remove kiosk autostart if present
    rm -f /etc/xdg/autostart/multi-frames-kiosk.desktop 2>/dev/null || true
    rm -f /home/*/Desktop/multi-frames-kiosk.desktop 2>/dev/null || true
    
    systemctl daemon-reload
    
    echo -e "${YELLOW}Remove installation directory $INSTALL_DIR? [y/N]${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -rf $INSTALL_DIR
        echo -e "${GREEN}✓ Directory removed${NC}"
    else
        echo -e "${YELLOW}Directory kept (contains your config)${NC}"
    fi
    
    echo -e "${GREEN}✓ Multi-Frames uninstalled${NC}"
    exit 0
fi

# Banner
clear 2>/dev/null || true
echo ""
echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║                                                          ║"
echo "  ║   __  __       _ _   _       ______                      ║"
echo "  ║  |  \/  |     | | | (_)     |  ____|                     ║"
echo "  ║  | \  / |_   _| | |_ _ ___  | |__ _ __ __ _ _ __ ___     ║"
echo "  ║  | |\/| | | | | | __| / __| |  __| '__/ _\` | '_ \` _ \    ║"
echo "  ║  | |  | | |_| | | |_| \__ \ | |  | | | (_| | | | | | |   ║"
echo "  ║  |_|  |_|\__,_|_|\__|_|___/ |_|  |_|  \__,_|_| |_| |_|   ║"
echo "  ║                                                          ║"
echo "  ║           Dashboard & iFrame Display Server              ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$IS_RASPBERRY_PI" = true ]; then
    echo -e "  ${MAGENTA}🍓 Raspberry Pi Detected${NC}"
    echo -e "  ${DIM}   $PI_MODEL${NC}"
    if [ -n "$PI_REVISION" ]; then
        echo -e "  ${DIM}   Revision: $PI_REVISION${NC}"
    fi
    echo ""
else
    echo -e "  ${BLUE}🐧 Linux System${NC}"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════
# REQUIREMENTS CHECK
# ═══════════════════════════════════════════════════════════════════

echo -e "${BOLD}Checking requirements...${NC}"

# Python check
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 is required but not installed${NC}"
    echo -e "  Install with: ${CYAN}sudo apt install python3${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 6 ]); then
    echo -e "${RED}✗ Python 3.6+ required, found $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION"

# Git check (optional)
if command -v git &> /dev/null; then
    echo -e "${GREEN}✓${NC} Git available"
else
    echo -e "${YELLOW}○${NC} Git not installed (updates via git pull won't work)"
fi

# ═══════════════════════════════════════════════════════════════════
# OPTIONAL DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════

if [ "$INSTALL_DEPS" = true ]; then
    echo ""
    echo -e "${BOLD}Installing optional dependencies...${NC}"
    
    # Update package list
    echo -e "  ${DIM}Updating package list...${NC}"
    apt-get update -qq
    
    # Install pip if not present
    if ! command -v pip3 &> /dev/null; then
        echo -e "  Installing pip3..."
        apt-get install -y python3-pip >/dev/null 2>&1
    fi
    
    # Install zeroconf for mDNS
    echo -e "  Installing zeroconf (mDNS/Bonjour support)..."
    pip3 install zeroconf --quiet --break-system-packages 2>/dev/null || \
    pip3 install zeroconf --quiet 2>/dev/null || \
    echo -e "  ${YELLOW}Could not install zeroconf${NC}"
    
    # Install git if not present
    if ! command -v git &> /dev/null; then
        echo -e "  Installing git..."
        apt-get install -y git >/dev/null 2>&1
    fi
    
    echo -e "${GREEN}✓${NC} Dependencies installed"
fi

# Check mDNS availability
if python3 -c "import zeroconf" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} mDNS support available"
else
    echo -e "${YELLOW}○${NC} mDNS not available (use --install-deps to enable)"
fi

# ═══════════════════════════════════════════════════════════════════
# RASPBERRY PI OPTIMIZATIONS
# ═══════════════════════════════════════════════════════════════════

if [ "$IS_RASPBERRY_PI" = true ]; then
    echo ""
    echo -e "${BOLD}Raspberry Pi optimizations...${NC}"
    
    # Fix WiFi power management
    if [ "$FIX_WIFI" = true ]; then
        echo -e "  Disabling WiFi power management..."
        
        # Method 1: /etc/rc.local (persistent)
        if [ -f /etc/rc.local ]; then
            if ! grep -q "iwconfig wlan0 power off" /etc/rc.local; then
                sed -i '/^exit 0/i iwconfig wlan0 power off 2>/dev/null || true' /etc/rc.local
            fi
        fi
        
        # Method 2: Create a service
        cat > /etc/systemd/system/wifi-power-off.service << 'EOF'
[Unit]
Description=Disable WiFi Power Management
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iwconfig wlan0 power off
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable wifi-power-off >/dev/null 2>&1
        systemctl start wifi-power-off 2>/dev/null || true
        
        # Apply immediately
        iwconfig wlan0 power off 2>/dev/null || true
        
        echo -e "${GREEN}✓${NC} WiFi power management disabled"
    fi
    
    # Disable screen blanking
    if [ "$DISABLE_BLANKING" = true ]; then
        echo -e "  Disabling screen blanking..."
        
        # For console
        if [ -f /etc/kbd/config ]; then
            sed -i 's/BLANK_TIME=.*/BLANK_TIME=0/' /etc/kbd/config
            sed -i 's/POWERDOWN_TIME=.*/POWERDOWN_TIME=0/' /etc/kbd/config
        fi
        
        # For X11/lightdm
        mkdir -p /etc/lightdm/lightdm.conf.d/
        cat > /etc/lightdm/lightdm.conf.d/50-disable-blanking.conf << 'EOF'
[Seat:*]
xserver-command=X -s 0 -dpms
EOF
        
        # For current session
        xset s off 2>/dev/null || true
        xset -dpms 2>/dev/null || true
        xset s noblank 2>/dev/null || true
        
        # Add to autostart for desktop
        mkdir -p /etc/xdg/autostart/
        cat > /etc/xdg/autostart/disable-blanking.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=Disable Screen Blanking
Exec=sh -c "xset s off; xset -dpms; xset s noblank"
Hidden=false
NoDisplay=true
EOF
        
        echo -e "${GREEN}✓${NC} Screen blanking disabled"
    fi
    
    # Kiosk mode
    if [ "$KIOSK_MODE" = true ]; then
        echo -e "  Configuring kiosk mode..."
        
        # Determine browser
        BROWSER=""
        if command -v chromium-browser &> /dev/null; then
            BROWSER="chromium-browser"
        elif command -v chromium &> /dev/null; then
            BROWSER="chromium"
        elif command -v firefox-esr &> /dev/null; then
            BROWSER="firefox-esr"
        fi
        
        if [ -n "$BROWSER" ]; then
            # Get URL
            IP=$(hostname -I | awk '{print $1}')
            URL="http://127.0.0.1"
            [ "$PORT" != "80" ] && URL="$URL:$PORT"
            
            # Create autostart entry
            mkdir -p /etc/xdg/autostart/
            
            if [[ "$BROWSER" == *"chromium"* ]]; then
                cat > /etc/xdg/autostart/multi-frames-kiosk.desktop << EOF
[Desktop Entry]
Type=Application
Name=Multi-Frames Kiosk
Exec=/bin/bash -c "sleep 10 && $BROWSER --kiosk --noerrdialogs --disable-infobars --disable-session-crashed-bubble --incognito $URL"
Hidden=false
X-GNOME-Autostart-enabled=true
EOF
            else
                cat > /etc/xdg/autostart/multi-frames-kiosk.desktop << EOF
[Desktop Entry]
Type=Application
Name=Multi-Frames Kiosk
Exec=/bin/bash -c "sleep 10 && $BROWSER --kiosk $URL"
Hidden=false
X-GNOME-Autostart-enabled=true
EOF
            fi
            
            echo -e "${GREEN}✓${NC} Kiosk mode configured (browser: $BROWSER)"
            echo -e "  ${DIM}Browser will auto-start on next boot${NC}"
        else
            echo -e "${YELLOW}○${NC} No browser found for kiosk mode"
            echo -e "  ${DIM}Install with: sudo apt install chromium-browser${NC}"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# SET HOSTNAME
# ═══════════════════════════════════════════════════════════════════

if [ -n "$SET_HOSTNAME" ]; then
    echo ""
    echo -e "${BOLD}Setting hostname...${NC}"
    
    # Validate hostname (RFC 1123)
    if [[ ! "$SET_HOSTNAME" =~ ^[a-zA-Z0-9]([-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?$ ]]; then
        echo -e "${RED}✗ Invalid hostname: $SET_HOSTNAME${NC}"
        echo -e "  ${DIM}Use only letters, numbers, and hyphens (max 63 chars)${NC}"
        exit 1
    fi
    
    OLD_HOSTNAME=$(hostname)
    
    # Update hostname file
    echo "$SET_HOSTNAME" > /etc/hostname
    
    # Update /etc/hosts
    sed -i "s/127\.0\.1\.1.*/127.0.1.1\t$SET_HOSTNAME/" /etc/hosts
    if ! grep -q "127.0.1.1" /etc/hosts; then
        echo "127.0.1.1	$SET_HOSTNAME" >> /etc/hosts
    fi
    
    # Apply immediately
    hostnamectl set-hostname "$SET_HOSTNAME" 2>/dev/null || hostname "$SET_HOSTNAME"
    
    echo -e "${GREEN}✓${NC} Hostname changed: $OLD_HOSTNAME → ${CYAN}$SET_HOSTNAME${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# INSTALL FILES
# ═══════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Installing Multi-Frames...${NC}"

# Create install directory
mkdir -p $INSTALL_DIR

# Find source file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/multi_frames.py" ]; then
    SOURCE_FILE="$SCRIPT_DIR/multi_frames.py"
elif [ -f "./multi_frames.py" ]; then
    SOURCE_FILE="./multi_frames.py"
else
    echo -e "${RED}✗ multi_frames.py not found${NC}"
    echo -e "  ${DIM}Make sure install.sh is in the same directory as multi_frames.py${NC}"
    exit 1
fi

# Backup existing if updating
if [ -f "$INSTALL_DIR/multi_frames.py" ]; then
    if [ "$UPDATE_ONLY" = true ]; then
        BACKUP_NAME="multi_frames.py.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$INSTALL_DIR/multi_frames.py" "$INSTALL_DIR/$BACKUP_NAME"
        echo -e "  ${DIM}Backed up existing to: $BACKUP_NAME${NC}"
    fi
fi

# Copy main file
cp "$SOURCE_FILE" "$INSTALL_DIR/multi_frames.py"
chmod +x "$INSTALL_DIR/multi_frames.py"
echo -e "${GREEN}✓${NC} Installed multi_frames.py"

# Check for existing config
if [ -f "$INSTALL_DIR/$CONFIG_FILE" ]; then
    echo -e "${GREEN}✓${NC} Existing configuration preserved"
else
    echo -e "  ${DIM}New config will be created on first run${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# SYSTEMD SERVICE
# ═══════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}Configuring systemd service...${NC}"

# Platform-specific settings
if [ "$IS_RASPBERRY_PI" = true ]; then
    RESTART_SEC=10
    EXTRA_OPTS="
# Raspberry Pi Optimizations
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0

# Watchdog: restart if unresponsive for 5 min
WatchdogSec=300

# Memory limits for Pi
MemoryMax=256M
MemoryHigh=192M"
else
    RESTART_SEC=5
    EXTRA_OPTS=""
fi

# Create service file
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Multi-Frames Dashboard Server
Documentation=https://github.com/lts-inc/multi-frames
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR

# Main process
ExecStart=/usr/bin/python3 $INSTALL_DIR/multi_frames.py --host 0.0.0.0 --port $PORT

# Restart policy
Restart=always
RestartSec=$RESTART_SEC

# Environment
Environment=PYTHONUNBUFFERED=1
Environment=HOME=$INSTALL_DIR

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$INSTALL_DIR
PrivateTmp=true
$EXTRA_OPTS

[Install]
WantedBy=multi-user.target
EOF

# Reload and enable
systemctl daemon-reload
systemctl enable $SERVICE_NAME >/dev/null 2>&1

echo -e "${GREEN}✓${NC} Service configured and enabled"

# ═══════════════════════════════════════════════════════════════════
# FIREWALL
# ═══════════════════════════════════════════════════════════════════

if command -v ufw &> /dev/null; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow $PORT/tcp >/dev/null 2>&1
        echo -e "${GREEN}✓${NC} Firewall rule added for port $PORT"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# START SERVICE
# ═══════════════════════════════════════════════════════════════════

if [ "$START_SERVICE" = true ]; then
    echo ""
    echo -e "${BOLD}Starting service...${NC}"
    
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl start $SERVICE_NAME
    sleep 3
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}✓${NC} Service running"
    else
        echo -e "${RED}✗ Service failed to start${NC}"
        echo ""
        echo -e "  Check logs: ${CYAN}sudo journalctl -u $SERVICE_NAME -n 30${NC}"
        exit 1
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# SUCCESS MESSAGE
# ═══════════════════════════════════════════════════════════════════

IP=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname)
PORT_SUFFIX=""
[ "$PORT" != "80" ] && PORT_SUFFIX=":$PORT"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ Multi-Frames Installed Successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}🌐 Access your dashboard:${NC}"
echo -e "     ${CYAN}http://$IP$PORT_SUFFIX${NC}"
if python3 -c "import zeroconf" 2>/dev/null; then
    echo -e "     ${CYAN}http://$HOSTNAME.local$PORT_SUFFIX${NC} ${DIM}(mDNS)${NC}"
fi
echo ""
echo -e "  ${BOLD}🔑 Default login:${NC}"
echo -e "     Username: ${YELLOW}admin${NC}"
echo -e "     Password: ${YELLOW}admin123${NC}"
echo ""
echo -e "  ${RED}⚠  Change the default password immediately!${NC}"
echo -e "     ${DIM}Admin → Users → Change Password${NC}"
echo ""
echo -e "  ${BOLD}📋 Service commands:${NC}"
echo -e "     ${BLUE}sudo systemctl status $SERVICE_NAME${NC}   ${DIM}# Status${NC}"
echo -e "     ${BLUE}sudo systemctl restart $SERVICE_NAME${NC}  ${DIM}# Restart${NC}"
echo -e "     ${BLUE}sudo ./install.sh --logs${NC}              ${DIM}# View logs${NC}"
echo ""

if [ "$IS_RASPBERRY_PI" = true ]; then
    echo -e "  ${BOLD}🍓 Raspberry Pi:${NC}"
    echo -e "     • Check temp/throttling: ${DIM}Admin → System${NC}"
    echo -e "     • Hostname: ${CYAN}$HOSTNAME${NC}"
    if [ "$KIOSK_MODE" = true ]; then
        echo -e "     • Kiosk: ${GREEN}Enabled${NC} ${DIM}(reboot to start)${NC}"
    fi
    if [ "$FIX_WIFI" = true ]; then
        echo -e "     • WiFi power mgmt: ${GREEN}Disabled${NC}"
    fi
    if [ "$DISABLE_BLANKING" = true ]; then
        echo -e "     • Screen blanking: ${GREEN}Disabled${NC}"
    fi
    echo ""
fi

echo -e "  ${BOLD}🔄 Update:${NC}"
echo -e "     ${BLUE}sudo ./install.sh --update${NC}"
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
