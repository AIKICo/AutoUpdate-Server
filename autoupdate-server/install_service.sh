#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo ./install_service.sh)"
  exit 1
fi

INSTALL_DIR="/opt/autoupdate-server"
echo "==> Installing AutoUpdate-Server to ${INSTALL_DIR}..."

mkdir -p ${INSTALL_DIR}
cp -r ./* ${INSTALL_DIR}/
chmod +x ${INSTALL_DIR}/autoupdate-server 2>/dev/null || true
chmod +x ${INSTALL_DIR}/*.sh 2>/dev/null || true

cp autoupdater.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable autoupdater.service
systemctl restart autoupdater.service

echo "==> AutoUpdate-Server installed and active as systemd daemon!"
echo "    Status: systemctl status autoupdater.service"
echo "    Logs:   journalctl -u autoupdater.service -f"
echo "    Admin:  http://<SERVER_IP>:8000/admin/"
