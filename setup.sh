#!/bin/bash
# 콕콕 예약알림 리눅스 서버(Ubuntu) 설치 스크립트 — Oracle Cloud 무료 VM 등
# 사용:  bash setup.sh                     → 임시 주소(trycloudflare) 자동 생성
#        bash setup.sh kokkok.example.com  → 내 도메인 고정 주소 (HTTPS 자동 발급)
#          ※ 도메인 DNS에 A 레코드(→ 서버 IP)를 먼저 추가하고, 80·443 포트를 열어 두세요
set -euo pipefail
cd "$(dirname "$0")"
DIR=$(pwd)
DOMAIN=${1:-}

echo "▶ 패키지 설치"
sudo timedatectl set-timezone Asia/Seoul || true
sudo apt-get update -q
sudo apt-get install -y -q python3-venv curl
python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt

if [ -n "$DOMAIN" ]; then
  echo "▶ HTTPS 웹 서버(Caddy) 설치: $DOMAIN"
  sudo apt-get install -y -q caddy iptables-persistent
  printf '%s {\n\treverse_proxy 127.0.0.1:8000\n}\n' "$DOMAIN" | sudo tee /etc/caddy/Caddyfile >/dev/null
  # Oracle 우분투 이미지는 기본 방화벽이 22번 외에는 막고 있음 → 80·443 허용
  for p in 80 443; do
    sudo iptables -C INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport $p -j ACCEPT
  done
  sudo netfilter-persistent save
  sudo systemctl enable --now caddy
  sudo systemctl reload caddy
elif ! command -v cloudflared >/dev/null; then
  echo "▶ cloudflared 설치 (임시 주소용)"
  curl -fsSL -o /tmp/cloudflared.deb \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$(dpkg --print-architecture).deb"
  sudo dpkg -i /tmp/cloudflared.deb
fi

echo "▶ 자동 실행 등록 (재부팅해도 다시 켜짐)"
sudo tee /etc/systemd/system/kokkok.service >/dev/null <<EOF
[Unit]
Description=kokkok booking alert
After=network-online.target
Wants=network-online.target

[Service]
User=$USER
WorkingDirectory=$DIR
Environment=PYTHONUNBUFFERED=1
Environment=TUNNEL=${DOMAIN:+0}
ExecStart=$DIR/.venv/bin/python server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kokkok
sudo systemctl restart kokkok

echo
echo "✅ 설치 완료! 상태 확인: sudo systemctl status kokkok"
if [ -n "$DOMAIN" ]; then
  echo "   폰 주소: https://$DOMAIN/?code=$(cat invite.txt 2>/dev/null || echo '<초대코드>')"
else
  echo "   폰 주소 확인:  journalctl -u kokkok -n 50 | grep trycloudflare"
fi
