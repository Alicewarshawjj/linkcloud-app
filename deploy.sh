#!/bin/bash
set -e

# ================================================
# LinkCloud - Hetzner Deployment Script
# ================================================
# Usage: ./deploy.sh yourdomain.com your@email.com
# ================================================

DOMAIN=${1:-""}
EMAIL=${2:-""}

if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
    echo "Usage: ./deploy.sh yourdomain.com your@email.com"
    exit 1
fi

echo "=========================================="
echo "  LinkCloud Deployment"
echo "  Domain: $DOMAIN"
echo "  Email: $EMAIL"
echo "=========================================="

# Step 1: Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "[1/6] Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "[1/6] Docker already installed ✓"
fi

# Step 2: Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "[2/6] Installing Docker Compose..."
    apt-get update && apt-get install -y docker-compose-plugin
else
    echo "[2/6] Docker Compose already installed ✓"
fi

# Step 3: Create .env if not exists
if [ ! -f .env ]; then
    echo "[3/6] Creating .env file..."
    DB_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
    JWT_SEC=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 48)
    cat > .env <<EOF
DB_PASSWORD=${DB_PASS}
JWT_SECRET=${JWT_SEC}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123
DOMAIN=${DOMAIN}
PORT=3000
NODE_ENV=production
EOF
    echo "   ⚠️  Default admin password is 'changeme123' — change it in .env!"
else
    echo "[3/6] .env already exists ✓"
fi

# Step 4: Update nginx config with domain
echo "[4/6] Configuring Nginx for $DOMAIN..."
sed -i "s/YOURDOMAIN.COM/$DOMAIN/g" nginx/conf.d/default.conf

# Step 5: Start services
echo "[5/6] Starting services..."
docker compose up -d --build

# Wait for services to be ready
echo "   Waiting for services to start..."
sleep 10

# Step 6: Get SSL certificate
echo "[6/6] Obtaining SSL certificate..."
docker compose run --rm certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN"

# Enable HTTPS in nginx config
echo "   Enabling HTTPS..."
cat > nginx/conf.d/default.conf <<NGINX
server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://app:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
NGINX

# Reload nginx with SSL config
docker compose restart nginx

echo ""
echo "=========================================="
echo "  ✅ LinkCloud is live!"
echo "=========================================="
echo ""
echo "  🌐 Site:  https://${DOMAIN}"
echo "  ⚙️  Admin: https://${DOMAIN}/admin"
echo "  👤 User:  admin"
echo "  🔑 Pass:  changeme123 (CHANGE IN .env!)"
echo ""
echo "  To change admin password:"
echo "    1. Edit .env → ADMIN_PASSWORD=newpassword"
echo "    2. Run: docker compose restart app"
echo ""
echo "=========================================="
