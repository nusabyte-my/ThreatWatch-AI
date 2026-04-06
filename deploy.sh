#!/bin/bash
# ThreatWatch AI — VPS deployment script
# Usage: bash deploy.sh

set -e

echo "==> ThreatWatch AI deploy starting..."

# 1. Pull latest code (if git repo)
# git pull origin main

# 2. Copy .env if not exists
if [ ! -f .env ]; then
  cp .env.example .env
  echo "[!] .env created from example — set real values before production!"
fi

# 3. Build & start
docker compose down --remove-orphans
docker compose build --no-cache
docker compose up -d

echo ""
echo "==> ThreatWatch AI is up."
echo "    UI:  http://$(curl -s ifconfig.me)"
echo "    API: http://$(curl -s ifconfig.me)/api/v1/health"
echo "    Docs: http://$(curl -s ifconfig.me)/docs"
