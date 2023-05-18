#!/bin/bash

apt update && apt upgrade
apt install python3-pip
echo "Installing python module"
pip3 install scapy requests

read -p "Do you wan to create a cron task to reset iptables rules every hours (y/n) ? " choise
if [ "$choise" = "y" ]; then
  iptables-save > /root/cerberus/iptables.save
  if [ ! -f "/etc/crontab" ] || [ "$(stat -c %U "$file")" != "root" ]; then
    touch "/etc/crontab"
  fi
  echo "0 * * * * /sbin/iptables-restore < /root/cerberus/iptables.save" >> /etc/crontab
  echo "Crontab created"
fi

read -p "Do you want to create a service (y/n) ? " choise
if [ "$choise" = "y" ]; then
  echo "cd /root/cerberus
python3 cerberus_server.py config.ini" > /root/cerberus/start_cerberus_service
  echo "[Unit]
Description=Cerberus Service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=bash /root/cerberus/start_cerberus_service

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/cerberus.service
  systemctl daemon-reload
  systemctl enable cerberus.service
  systemctl start cerberus.service
  echo "Service cerberus.service created"
fi

echo "Installation completed"