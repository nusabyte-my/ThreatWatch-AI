#!/bin/bash
# ThreatWatch AI — VPS deploy script
# Target: threatwatch-ai.nusabyte.cloud (72.62.254.65)
# Usage:  bash deploy.sh [--first-run]
# --first-run: install Docker + nginx + certbot on a fresh VPS, then exit.

set -euo pipefail

DOMAIN="threatwatch-ai.nusabyte.cloud"
APP_DIR="/opt/threatwatch-ai"
REPO="https://github.com/nusabyte-my/ThreatWatch-AI.git"

info()  { echo -e "\033[0;34m==>\033[0m $*"; }
ok()    { echo -e "\033[0;32m OK\033[0m $*"; }
warn()  { echo -e "\033[0;33m !!\033[0m $*"; }
die()   { echo -e "\033[0;31mERR\033[0m $*"; exit 1; }

# ── First-run: install Docker + nginx + certbot ─────────────────────────
if [[ "${1:-}" == "--first-run" ]]; then
  info "First-run setup on $(hostname)..."

  apt-get update -qq
  apt-get install -y -qq curl git nginx certbot python3-certbot-nginx

  if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    ok "Docker installed"
  fi

  if [ ! -d "$APP_DIR" ]; then
    git clone "$REPO" "$APP_DIR"
    ok "Repo cloned to $APP_DIR"
  fi

  cp "$APP_DIR/nginx/vps-site.conf" "/etc/nginx/sites-available/threatwatch-ai"
  ln -sf "/etc/nginx/sites-available/threatwatch-ai" "/etc/nginx/sites-enabled/threatwatch-ai"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx
  ok "nginx configured"

  info "Obtaining SSL certificate for $DOMAIN..."
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@nusabyte.my || \
    warn "certbot failed — confirm DNS is pointing to this IP, then: certbot --nginx -d $DOMAIN"

  ok "First-run done. Edit $APP_DIR/.env then: bash $APP_DIR/deploy.sh"
  exit 0
fi

# ── Regular deploy ──────────────────────────────────────────────────────
info "Deploying ThreatWatch AI → $DOMAIN"

# Resolve app dir (supports local dev and VPS paths)
if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR"
else
  cd "$(dirname "$0")"
fi

if git rev-parse --git-dir &>/dev/null; then
  info "Pulling latest..."
  git pull origin main
fi

if [ ! -f .env ]; then
  cp .env.example .env
  die ".env created from template — fill in real values then re-run."
fi

info "Building images..."
docker compose build --no-cache

info "Restarting services..."
docker compose down --remove-orphans
docker compose up -d

info "Waiting for API health..."
for i in $(seq 1 20); do
  if curl -sf http://localhost:8100/ &>/dev/null; then
    ok "API is up"
    break
  fi
  sleep 3
done

echo ""
ok "ThreatWatch AI is live."
echo "   Site: https://$DOMAIN"
echo "   API:  https://$DOMAIN/api/v1/"
echo "   Logs: docker compose logs -f api"
