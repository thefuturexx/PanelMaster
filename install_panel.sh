#!/usr/bin/env bash
set -e

REPO="https://github.com/chitaw2000/PanelMaster_6.git"
BRANCH="feature/switch-node-sync"
INSTALL_DIR="/root/PanelMaster_6"
DATA_DIR="/root/qito_master"
APP_DIR="/root/PanelMaster"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="panelmaster"
PORT=8888

echo "============================================"
echo "  PanelMaster Installer"
echo "============================================"

# 1) System packages
echo "[1/7] Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip git jq curl ufw openssh-client
echo "  -> Done"

# 2) Clone or update repo
echo "[2/7] Setting up PanelMaster code..."
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR"
    git fetch origin
    git checkout "$BRANCH"
    git pull origin "$BRANCH"
    echo "  -> Updated existing repo"
else
    rm -rf "$INSTALL_DIR"
    git clone -b "$BRANCH" "$REPO" "$INSTALL_DIR"
    echo "  -> Cloned fresh repo"
fi
cd "$INSTALL_DIR"

# 3) Python virtual environment + dependencies
echo "[3/7] Setting up Python venv and dependencies..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install flask requests werkzeug -q
echo "  -> Done"

# 4) Create data directories and empty data files if missing
echo "[4/7] Creating data directories..."
mkdir -p "$DATA_DIR" "$APP_DIR/backups"

[ -f "$DATA_DIR/users_db.json" ]   || echo '{}' > "$DATA_DIR/users_db.json"
[ -f "$DATA_DIR/nodes_list.txt" ]  || touch "$DATA_DIR/nodes_list.txt"
[ -f "$DATA_DIR/config.json" ]     || echo '{}' > "$DATA_DIR/config.json"
[ -f "$APP_DIR/auto_groups.json" ] || echo '{}' > "$APP_DIR/auto_groups.json"
[ -f "$APP_DIR/nodes_db.json" ]    || echo '{}' > "$APP_DIR/nodes_db.json"
[ -f "$APP_DIR/ips_db.json" ]      || echo '{}' > "$APP_DIR/ips_db.json"
echo "  -> Done"

# 5) Generate SSH key if missing (for node access)
echo "[5/7] Checking SSH key..."
if [ ! -f /root/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" -q
    echo "  -> Generated new SSH key"
    echo "  -> Public key (copy to nodes):"
    cat /root/.ssh/id_rsa.pub
else
    echo "  -> SSH key exists"
fi

# 6) Create systemd service
echo "[6/7] Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service <<UNIT
[Unit]
Description=PanelMaster Flask App
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python3 main.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}
echo "  -> Service created and started"

# 7) Firewall
echo "[7/7] Configuring firewall..."
ufw allow $PORT/tcp >/dev/null 2>&1 || true
ufw allow 22/tcp >/dev/null 2>&1 || true
echo "  -> Port $PORT opened"

echo ""
echo "============================================"
echo "  Installation Complete!"
echo "============================================"
echo ""
echo "  Panel URL:  http://$(curl -s ifconfig.me 2>/dev/null || echo '<YOUR_IP>'):$PORT"
echo "  Service:    systemctl status $SERVICE_NAME"
echo "  Logs:       journalctl -u $SERVICE_NAME -f"
echo "  Update:     cd $INSTALL_DIR && git pull && systemctl restart $SERVICE_NAME"
echo ""
echo "  Data dirs:"
echo "    $DATA_DIR    (users_db, nodes_list, config)"
echo "    $APP_DIR     (auto_groups, nodes_db, backups)"
echo ""
