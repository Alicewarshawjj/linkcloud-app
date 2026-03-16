#!/bin/bash
set -e

# ====================================================
#  LinkCloud — One-Click Installer for Hetzner
#  Domain: cmehere.net
# ====================================================

DOMAIN="cmehere.net"
APP_DIR="/opt/linkcloud"
DB_PASS=$(openssl rand -hex 16)
JWT_SEC=$(openssl rand -hex 24)

echo ""
echo "============================================"
echo "  LinkCloud Installer"
echo "  Domain: $DOMAIN"
echo "============================================"
echo ""

# --- 1. Install Docker ---
echo "[1/7] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi
echo "  Docker $(docker --version | cut -d' ' -f3) ✓"

# --- 2. Docker Compose ---
echo "[2/7] Checking Docker Compose..."
if ! docker compose version &> /dev/null; then
    apt-get update -qq && apt-get install -y -qq docker-compose-plugin
fi
echo "  $(docker compose version) ✓"

# --- 3. Create project ---
echo "[3/7] Creating project files..."
rm -rf $APP_DIR
mkdir -p $APP_DIR/public $APP_DIR/nginx/conf.d

# --- .env ---
cat > $APP_DIR/.env <<EOF
DB_PASSWORD=$DB_PASS
JWT_SECRET=$JWT_SEC
ADMIN_USERNAME=admin
ADMIN_PASSWORD=LinkCloud2024!
DOMAIN=$DOMAIN
PORT=3000
NODE_ENV=production
EOF

# --- package.json ---
cat > $APP_DIR/package.json <<'PKGJSON'
{
  "name": "linkcloud",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {"start": "node server.js"},
  "dependencies": {
    "express": "^4.21.0",
    "pg": "^8.13.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "cookie-parser": "^1.4.6",
    "dotenv": "^16.4.5",
    "compression": "^1.7.4",
    "helmet": "^8.0.0",
    "express-rate-limit": "^7.4.0"
  },
  "engines": {"node": ">=18.0.0"}
}
PKGJSON

# --- Dockerfile ---
cat > $APP_DIR/Dockerfile <<'DOCKERFILE'
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
DOCKERFILE

# --- .dockerignore ---
cat > $APP_DIR/.dockerignore <<'DIGNORE'
node_modules
.env
.git
DIGNORE

# --- docker-compose.yml ---
cat > $APP_DIR/docker-compose.yml <<'COMPOSE'
version: '3.8'
services:
  app:
    build: .
    container_name: linkcloud-app
    restart: always
    env_file: .env
    environment:
      - DATABASE_URL=postgresql://linkcloud:${DB_PASSWORD}@db:5432/linkcloud
      - NODE_ENV=production
    depends_on:
      db:
        condition: service_healthy
    networks:
      - internal
      - web
  db:
    image: postgres:16-alpine
    container_name: linkcloud-db
    restart: always
    environment:
      POSTGRES_DB: linkcloud
      POSTGRES_USER: linkcloud
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U linkcloud"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - internal
  nginx:
    image: nginx:alpine
    container_name: linkcloud-nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - certbot-etc:/etc/letsencrypt
      - certbot-var:/var/lib/letsencrypt
      - webroot:/var/www/certbot
    depends_on:
      - app
    networks:
      - web
  certbot:
    image: certbot/certbot
    container_name: linkcloud-certbot
    volumes:
      - certbot-etc:/etc/letsencrypt
      - certbot-var:/var/lib/letsencrypt
      - webroot:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
volumes:
  pgdata:
  certbot-etc:
  certbot-var:
  webroot:
networks:
  internal:
  web:
COMPOSE

# --- nginx.conf ---
cat > $APP_DIR/nginx/nginx.conf <<'NGXMAIN'
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
events { worker_connections 1024; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 15M;
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml;
    gzip_min_length 1000;
    include /etc/nginx/conf.d/*.conf;
}
NGXMAIN

# --- nginx site config (HTTP first) ---
cat > $APP_DIR/nginx/conf.d/default.conf <<NGXSITE
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
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
NGXSITE

# --- server.js (full app) ---
cat > $APP_DIR/server.js <<'SERVERJS'
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sites (
        id SERIAL PRIMARY KEY, slug VARCHAR(100) UNIQUE NOT NULL DEFAULT 'main',
        content JSONB NOT NULL DEFAULT '{}', seo JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD || 'changeme123';
    const existing = await client.query('SELECT id FROM users WHERE username = $1', [adminUser]);
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash(adminPass, 12);
      await client.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [adminUser, hash]);
      console.log('Admin user created:', adminUser);
    }
    const site = await client.query('SELECT id FROM sites WHERE slug = $1', ['main']);
    if (site.rows.length === 0) {
      const def = {profile:{name:'Your Name',bio:'Your bio here',verified:false,coverUrl:'',avatarUrl:''},socials:[{type:'instagram',url:''},{type:'tiktok',url:''},{type:'youtube',url:''}],feats:[],cars:[]};
      await client.query('INSERT INTO sites (slug, content) VALUES ($1, $2)', ['main', JSON.stringify(def)]);
    }
    console.log('DB initialized');
  } finally { client.release(); }
}

app.use(compression());
app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false}));
app.use(express.json({limit:'10mb'}));
app.use(cookieParser());

const apiLimiter = rateLimit({windowMs:15*60*1000,max:100});

function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ','');
  if (!token) return res.status(401).json({error:'Unauthorized'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'Invalid token'}); }
}

app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/favicon.ico', express.static(path.join(__dirname, 'public', 'favicon.ico')));

app.post('/api/auth/login', apiLimiter, async (req, res) => {
  try {
    const {username, password} = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !await bcrypt.compare(password, user.password_hash))
      return res.status(401).json({error:'Invalid credentials'});
    const token = jwt.sign({id:user.id, username:user.username}, JWT_SECRET, {expiresIn:'7d'});
    res.cookie('token', token, {httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:7*24*60*60*1000});
    res.json({ok:true, token});
  } catch(e) { res.status(500).json({error:'Server error'}); }
});
app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ok:true}); });
app.get('/api/auth/check', requireAuth, (req, res) => { res.json({ok:true, user:req.user.username}); });

app.get('/api/content', async (req, res) => {
  try {
    const r = await pool.query('SELECT content FROM sites WHERE slug=$1', ['main']);
    res.json(r.rows.length ? r.rows[0].content : {});
  } catch(e) { res.status(500).json({error:'Server error'}); }
});

app.put('/api/content', requireAuth, async (req, res) => {
  try {
    await pool.query('UPDATE sites SET content=$1, updated_at=NOW() WHERE slug=$2', [JSON.stringify(req.body), 'main']);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:'Server error'}); }
});

app.get('/admin', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'admin.html')); });

app.get('/', async (req, res) => {
  try {
    const r = await pool.query('SELECT content, seo FROM sites WHERE slug=$1', ['main']);
    if (!r.rows.length) return res.redirect('/admin');
    res.send(renderProfile(r.rows[0].content, r.rows[0].seo || {}));
  } catch(e) { res.status(500).send('Error'); }
});

function renderProfile(data, seo) {
  const p = data.profile||{}, socials=data.socials||[], feats=data.feats||[], cars=data.cars||[];
  const esc = s => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const TYPES={onlyfans:{n:'OnlyFans',bg:'#003CFF'},instagram:{n:'Instagram',bg:'linear-gradient(45deg,#F77737,#FD1D1D 50%,#833AB4)'},instagram2:{n:'Instagram 2',bg:'linear-gradient(135deg,#F77737,#FD1D1D 50%,#C13584)'},tiktok:{n:'TikTok',bg:'linear-gradient(135deg,#25F4EE,#FD1D1D)'},snapchat:{n:'Snapchat',bg:'#FFFC00'},twitter:{n:'X / Twitter',bg:'#1a1a1a'},youtube:{n:'YouTube',bg:'#FF0000'},website:{n:'Website',bg:'#7B7B7B'},amazon:{n:'Amazon',bg:'#FF9500'},amazon2:{n:'Amazon 2',bg:'#FF7500'},facebook:{n:'Facebook',bg:'#1877F2'},linkedin:{n:'LinkedIn',bg:'#0A66C2'},spotify:{n:'Spotify',bg:'#1DB954'},telegram:{n:'Telegram',bg:'#26A5E4'},whatsapp:{n:'WhatsApp',bg:'#25D366'},pinterest:{n:'Pinterest',bg:'#E60023'},twitch:{n:'Twitch',bg:'#9146FF'},discord:{n:'Discord',bg:'#5865F2'},email:{n:'Email',bg:'#EA4335'},phone:{n:'Phone',bg:'#34C759'}};
  const SVG={onlyfans:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="white" stroke-width="2"/><circle cx="12" cy="12" r="4" fill="white"/></svg>',instagram:'<svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.756 0 8.331.012 7.052.07 3.656.262.262 3.656.07 7.052.012 8.331 0 8.756 0 12s.012 3.669.07 4.948c.192 3.396 3.586 6.79 6.982 6.982C8.331 23.988 8.756 24 12 24s3.669-.012 4.948-.07c3.397-.192 6.79-3.586 6.982-6.982.058-1.279.07-1.704.07-4.948s-.012-3.669-.07-4.948c-.192-3.397-3.586-6.79-6.982-6.982C15.669.012 15.244 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zm0 10.162a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 11-2.88 0 1.44 1.44 0 012.88 0z" fill="white"/></svg>',instagram2:'<svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.756 0 8.331.012 7.052.07 3.656.262.262 3.656.07 7.052.012 8.331 0 8.756 0 12s.012 3.669.07 4.948c.192 3.396 3.586 6.79 6.982 6.982C8.331 23.988 8.756 24 12 24s3.669-.012 4.948-.07c3.397-.192 6.79-3.586 6.982-6.982.058-1.279.07-1.704.07-4.948s-.012-3.669-.07-4.948c-.192-3.397-3.586-6.79-6.982-6.982C15.669.012 15.244 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zm0 10.162a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 11-2.88 0 1.44 1.44 0 012.88 0z" fill="white"/></svg>',tiktok:'<svg viewBox="0 0 24 24"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-5.1 1.75 2.9 2.9 0 012.31-4.64c.29 0 .58.03.88.14v-3.5a5.9 5.9 0 00-1-.1A6.11 6.11 0 005 13.75a6.49 6.49 0 006.5 6.5A6.41 6.41 0 0018 13.75V9.64a4.83 4.83 0 002.77 1.07V8.35c-.2-.02-.39-.06-.58-.06z" fill="white"/></svg>',snapchat:'<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 3a2 2 0 110 4 2 2 0 010-4zm0 14c-2.67 0-5-1.34-6.4-3.38l1.64-1.15A5.98 5.98 0 0012 17c2.05 0 3.85-1.03 4.76-2.53l1.64 1.15A7.97 7.97 0 0112 19z" fill="black"/></svg>',twitter:'<svg viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" fill="white"/></svg>',youtube:'<svg viewBox="0 0 24 24"><path d="M23.498 6.186a3.016 3.016 0 00-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 00.502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 002.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 002.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z" fill="white"/></svg>',website:'<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="white"/></svg>',amazon:'<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" fill="white"/></svg>',amazon2:'<svg viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" fill="white"/></svg>',facebook:'<svg viewBox="0 0 24 24"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" fill="white"/></svg>',linkedin:'<svg viewBox="0 0 24 24"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.064 2.064 0 110-4.128 2.064 2.064 0 010 4.128zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0z" fill="white"/></svg>',spotify:'<svg viewBox="0 0 24 24"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z" fill="white"/></svg>',telegram:'<svg viewBox="0 0 24 24"><path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" fill="white"/></svg>',whatsapp:'<svg viewBox="0 0 24 24"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z" fill="white"/></svg>',pinterest:'<svg viewBox="0 0 24 24"><path d="M12.017 0C5.396 0 .029 5.367.029 11.987c0 5.079 3.158 9.417 7.618 11.162-.105-.949-.199-2.403.041-3.439.219-.937 1.406-5.957 1.406-5.957s-.359-.72-.359-1.781c0-1.668.967-2.914 2.171-2.914 1.023 0 1.518.769 1.518 1.69 0 1.029-.655 2.568-.994 3.995-.283 1.194.599 2.169 1.777 2.169 2.133 0 3.772-2.249 3.772-5.495 0-2.873-2.064-4.882-5.012-4.882-3.414 0-5.418 2.561-5.418 5.207 0 1.031.397 2.138.893 2.738a.36.36 0 01.083.345l-.333 1.36c-.053.22-.174.267-.402.161-1.499-.698-2.436-2.889-2.436-4.649 0-3.785 2.75-7.262 7.929-7.262 4.163 0 7.398 2.967 7.398 6.931 0 4.136-2.607 7.464-6.227 7.464-1.216 0-2.359-.631-2.75-1.378l-.748 2.853c-.271 1.043-1.002 2.35-1.492 3.146C9.57 23.812 10.763 24 12.017 24c6.624 0 11.99-5.367 11.99-11.988C24.007 5.367 18.641 0 12.017 0z" fill="white"/></svg>',twitch:'<svg viewBox="0 0 24 24"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z" fill="white"/></svg>',discord:'<svg viewBox="0 0 24 24"><path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.865-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.618-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.078-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.076.076 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.086-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.332-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.086-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.332-.946 2.418-2.157 2.418z" fill="white"/></svg>',email:'<svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" fill="white"/></svg>',phone:'<svg viewBox="0 0 24 24"><path d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z" fill="white"/></svg>'};

  const socialsHTML = socials.map(s => {
    const t=TYPES[s.type]; if(!t) return '';
    const w = s.url ? [`<a href="${esc(s.url)}" target="_blank" rel="noopener" class="social-link">`,`</a>`] : ['<div class="social-link">','</div>'];
    return `${w[0]}<div class="social-icon" style="background:${t.bg}">${SVG[s.type]||''}</div>${w[1]}`;
  }).join('');

  const featsHTML = feats.map(f => {
    const bg = f.imgUrl ? `background-image:url('${f.imgUrl}');background-size:cover;background-position:center;` : `background:linear-gradient(135deg,${f.color||'#667eea'},${f.color||'#764ba2'}80);`;
    const w = f.url ? [`<a href="${esc(f.url)}" target="_blank" rel="noopener" class="feat-link">`,`</a>`] : ['<div class="feat-link">','</div>'];
    return `${w[0]}<div class="feat-card-d" style="${bg}"><div class="feat-ov"><div class="feat-ic" style="background:${f.color||'#667eea'}"><svg viewBox="0 0 24 24" style="width:22px;height:22px;fill:#fff"><circle cx="12" cy="12" r="10"/></svg></div><span class="feat-t">${esc(f.title)}</span></div></div>${w[1]}`;
  }).join('');

  const carsHTML = cars.map(c => {
    const svg = SVG[c.icon]||SVG.website||'';
    const w = c.url ? [`<a href="${esc(c.url)}" target="_blank" rel="noopener" class="car-link">`,`</a>`] : ['<div class="car-link">','</div>'];
    return `${w[0]}<div class="car-card" style="background:${c.grad||'linear-gradient(135deg,#667eea,#764ba2)'}"><div class="car-ic">${svg}</div><div class="car-t">${esc(c.title)}</div><div class="car-s">${esc(c.sub||'')}</div></div>${w[1]}`;
  }).join('');

  const badge = p.verified ? '<div class="vbadge"><svg viewBox="0 0 24 24" style="width:16px;height:16px;fill:#fff"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg></div>' : '';
  const cover = p.coverUrl ? `<img src="${esc(p.coverUrl)}" alt="Cover" class="cover-img">` : '<div class="cover-grad"></div>';
  const avatar = p.avatarUrl ? `<img src="${esc(p.avatarUrl)}" alt="${esc(p.name)}" class="avatar-img">` : '<div class="avatar-ph"></div>';

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>${esc(seo.title||p.name||'LinkCloud')}</title><meta name="description" content="${esc(seo.description||p.bio||'')}"><meta property="og:title" content="${esc(p.name||'')}"><meta property="og:description" content="${esc(p.bio||'')}"><meta property="og:type" content="profile">${p.avatarUrl?`<meta property="og:image" content="${esc(p.avatarUrl)}">`:''}
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;justify-content:center}.ctr{width:100%;max-width:480px;background:#fff;min-height:100vh;box-shadow:0 0 20px rgba(0,0,0,.08)}.cover{position:relative;height:180px;overflow:hidden}.cover-img{width:100%;height:100%;object-fit:cover}.cover-grad{width:100%;height:100%;background:linear-gradient(135deg,#667eea,#764ba2)}.av-sec{display:flex;flex-direction:column;align-items:center;margin-top:-55px;position:relative;z-index:2}.av-wr{position:relative}.avatar-img,.avatar-ph{width:110px;height:110px;border-radius:50%;border:4px solid #fff;box-shadow:0 4px 15px rgba(0,0,0,.15);object-fit:cover}.avatar-ph{background:linear-gradient(135deg,#667eea,#764ba2)}.vbadge{position:absolute;bottom:4px;right:4px;width:28px;height:28px;background:#1DA1F2;border-radius:50%;display:flex;align-items:center;justify-content:center;border:3px solid #fff}.pi{text-align:center;padding:16px 24px 0}.pn{font-size:24px;font-weight:800;color:#1a1a2e}.pb{color:#666;font-size:14px;margin-top:8px;line-height:1.5}.socs{display:flex;flex-wrap:wrap;justify-content:center;gap:12px;padding:24px 16px}.social-link{text-decoration:none}.social-icon{width:55px;height:55px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:transform .2s;cursor:pointer}.social-icon:hover{transform:scale(1.1)}.social-icon svg{width:24px;height:24px}.st{color:#667eea;text-align:center;font-size:13px;font-weight:700;letter-spacing:1px;text-transform:uppercase;padding:8px 0 16px}.feat-link{text-decoration:none;display:block;margin:0 16px 16px}.feat-card-d{height:200px;border-radius:16px;overflow:hidden;position:relative;transition:transform .2s}.feat-card-d:hover{transform:scale(1.02)}.feat-ov{position:absolute;bottom:0;left:0;right:0;height:80px;background:linear-gradient(to top,rgba(0,0,0,.65),transparent);display:flex;align-items:flex-end;padding:14px}.feat-ic{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin-right:12px}.feat-t{color:#fff;font-weight:700;font-size:15px}.carousel{display:flex;gap:12px;overflow-x:auto;padding:0 16px 16px;-webkit-overflow-scrolling:touch}.carousel::-webkit-scrollbar{display:none}.car-link{text-decoration:none;flex-shrink:0}.car-card{width:200px;height:200px;border-radius:16px;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;transition:transform .2s}.car-card:hover{transform:scale(1.03)}.car-ic{margin-bottom:12px}.car-ic svg{width:40px;height:40px;fill:#fff}.car-t{color:#fff;font-weight:700;font-size:15px;text-align:center}.car-s{color:rgba(255,255,255,.8);font-size:12px;text-align:center;margin-top:4px}.footer{text-align:center;padding:32px 0;border-top:1px solid #eee;margin:16px 24px 0}.fl{color:#999;font-size:12px;margin-bottom:6px}.fb{font-weight:800;font-size:14px;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}@keyframes fu{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}.an{animation:fu .6s ease forwards}.d1{animation-delay:.1s;opacity:0}.d2{animation-delay:.2s;opacity:0}.d3{animation-delay:.3s;opacity:0}.d4{animation-delay:.4s;opacity:0}.d5{animation-delay:.5s;opacity:0}.iab{display:none;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:14px 20px;text-align:center;font-size:13px;font-weight:600;cursor:pointer;position:fixed;top:0;left:0;right:0;z-index:1000}.iab.show{display:block}</style></head><body>
<div class="iab" id="iab" onclick="escIA()">Open in browser for best experience ↗</div>
<div class="ctr"><div class="cover an">${cover}</div><div class="av-sec an d1"><div class="av-wr">${avatar}${badge}</div></div><div class="pi an d2"><h1 class="pn">${esc(p.name||'Your Name')}</h1><p class="pb">${esc(p.bio||'')}</p></div><div class="socs an d3">${socialsHTML}</div>${feats.length?`<div class="an d4"><div class="st">Featured Links</div>${featsHTML}</div>`:''}${cars.length?`<div class="an d5"><div class="st" style="margin-top:8px">Featured Content</div><div class="carousel">${carsHTML}</div></div>`:''}<div class="footer"><div class="fl">Powered by</div><div class="fb">LINKCLOUD</div></div></div>
<script>!function(){var u=navigator.userAgent||'';if(/Instagram|FBAN|FBAV|BytedanceWebview|TikTok|LinkedInApp/i.test(u)){document.getElementById('iab').classList.add('show');document.body.style.paddingTop='48px'}}();function escIA(){var u=location.href,i=/iPad|iPhone|iPod/.test(navigator.userAgent);if(i)location='x-safari-'+u;else try{location='intent://'+u.replace(/https?:\\/\\//,'')+'#Intent;scheme=https;end'}catch(e){window.open(u,'_system')}}</script></body></html>`;
}

initDB().then(() => {
  app.listen(PORT, () => console.log('LinkCloud running on port ' + PORT));
}).catch(err => { console.error('DB init failed:', err); process.exit(1); });
SERVERJS

echo "  server.js ✓"

# --- 4. Create admin.html ---
echo "[4/7] Creating admin panel..."
# Download admin.html (it's too large to embed in heredoc, so we create a minimal bootstrap)
cat > $APP_DIR/public/admin.html <<'ADMINEOF'
<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LinkCloud Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0a14;color:#e0e0e0;min-height:100vh}::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:rgba(255,255,255,.03)}::-webkit-scrollbar-thumb{background:rgba(102,126,234,.35);border-radius:3px}.layout{display:grid;grid-template-columns:1fr 380px;min-height:100vh}@media(max-width:860px){.layout{grid-template-columns:1fr}.preview-side{display:none}}.editor{padding:28px 32px;overflow-y:auto;max-height:100vh}.topbar{display:flex;align-items:center;gap:10px;margin-bottom:28px;padding-bottom:18px;border-bottom:1px solid rgba(255,255,255,.06)}.topbar h1{font-size:20px;font-weight:800;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.topbar .tag{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;font-size:9px;font-weight:700;padding:2px 8px;border-radius:10px}.topbar .status-dot{width:8px;height:8px;border-radius:50%;margin-right:auto}.topbar .status-dot.online{background:#4ade80;box-shadow:0 0 6px #4ade80}.topbar .status-dot.offline{background:#ff4757}.topbar .status-text{font-size:10px;color:#666;margin-right:auto}.card{background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.07);border-radius:14px;padding:20px;margin-bottom:16px}.card:hover{border-color:rgba(102,126,234,.25)}.card-head{display:flex;align-items:center;justify-content:space-between;cursor:pointer;margin-bottom:14px}.card-title{font-size:14px;font-weight:700;color:#bbb;display:flex;align-items:center;gap:8px}.card-title i{font-style:normal}.card.closed .card-body{display:none}.card.closed .arrow{transform:rotate(-90deg)}.arrow{color:#667eea;font-size:14px;transition:transform .2s}label{display:block;font-size:11px;font-weight:700;color:#666;margin-bottom:5px;letter-spacing:.4px;text-transform:uppercase}input[type=text],input[type=url],input[type=password],textarea,select{width:100%;padding:9px 12px;background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.09);border-radius:9px;color:#ddd;font-size:13px;font-family:inherit;outline:none;transition:border-color .2s;margin-bottom:12px;direction:ltr;text-align:left}input:focus,textarea:focus,select:focus{border-color:#667eea}textarea{resize:vertical;min-height:50px}select{cursor:pointer}select option{background:#15152a}.upload-zone{position:relative;border:2px dashed rgba(255,255,255,.12);border-radius:12px;overflow:hidden;cursor:pointer;transition:border-color .2s;margin-bottom:12px;display:flex;align-items:center;justify-content:center;background:rgba(255,255,255,.02)}.upload-zone:hover{border-color:#667eea}.upload-zone.has-image{border-style:solid}.upload-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}.upload-zone img{width:100%;height:100%;object-fit:cover;display:block}.upload-zone .placeholder{text-align:center;padding:16px;color:#555;font-size:12px}.upload-zone .placeholder span{font-size:24px;display:block;margin-bottom:4px}.cover-upload{height:100px}.avatar-upload{width:80px;height:80px;border-radius:50%;margin:0 auto}.item-row{display:flex;align-items:center;gap:8px;padding:8px 10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;margin-bottom:6px}.item-row:hover{background:rgba(255,255,255,.06)}.item-row .grip{cursor:grab;color:#444;font-size:14px}.item-row .mini-icon{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0}.item-row .mini-icon svg{width:14px;height:14px;fill:#fff}.item-row .info{flex:1;min-width:0}.item-row .info .name{font-size:12px;font-weight:600;color:#bbb}.item-row .info input{margin:3px 0 0;padding:5px 8px;font-size:11px;margin-bottom:0}.del-btn{background:none;border:none;color:#ff4757;cursor:pointer;font-size:14px;padding:4px 6px;border-radius:6px}.del-btn:hover{background:rgba(255,71,87,.12)}.add-btn{width:100%;padding:9px;background:rgba(102,126,234,.08);border:1px dashed rgba(102,126,234,.25);border-radius:10px;color:#667eea;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;margin-top:4px}.add-btn:hover{background:rgba(102,126,234,.16)}.feat-card{padding:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;margin-bottom:8px}.feat-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}.feat-head span{font-size:12px;font-weight:700;color:#aaa}.feat-img-upload{height:70px;border-radius:8px;margin-bottom:8px}.row2{display:grid;grid-template-columns:1fr 1fr;gap:8px}.btn-save{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);border:none;border-radius:12px;color:#fff;font-size:15px;font-weight:800;cursor:pointer;font-family:inherit;margin-top:8px}.btn-save:hover{opacity:.9}.btn-save:disabled{opacity:.4;cursor:not-allowed}.btn-sec{width:100%;padding:11px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;color:#aaa;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;margin-top:8px}.btn-sec:hover{background:rgba(255,255,255,.08)}.preview-side{background:#12121f;border-right:1px solid rgba(255,255,255,.06);display:flex;flex-direction:column;align-items:center;padding:20px 0;overflow-y:auto;max-height:100vh}.preview-label{font-size:10px;font-weight:800;color:#444;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:10px}.phone{width:345px;height:690px;border:2px solid rgba(255,255,255,.08);border-radius:30px;overflow:hidden;background:#f0f2f5}.phone iframe{width:100%;height:100%;border:none}.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;z-index:100}.modal-bg.open{display:flex}.modal-box{background:#15152a;border:1px solid rgba(255,255,255,.08);border-radius:18px;padding:24px;width:90%;max-width:400px;max-height:75vh;overflow-y:auto}.modal-box h3{font-size:16px;margin-bottom:14px;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.icon-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.ico-opt{display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;cursor:pointer}.ico-opt:hover{background:rgba(102,126,234,.12)}.ico-opt .ioc{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center}.ico-opt .ioc svg{width:16px;height:16px;fill:#fff}.ico-opt .ion{font-size:9px;color:#777;text-align:center}.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(80px);background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:10px 24px;border-radius:10px;font-weight:700;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.3);transition:transform .3s;z-index:200}.toast.show{transform:translateX(-50%) translateY(0)}.login-screen{display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:40px}.login-box{max-width:360px;width:100%}.login-box h2{font-size:24px;margin-bottom:8px;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.login-box p{color:#666;font-size:13px;margin-bottom:24px}.login-box .error{color:#ff4757;font-size:12px;margin-top:-8px;margin-bottom:12px;display:none}
</style>
</head>
<body>
<div id="loginScreen" class="login-screen"><div class="login-box"><h2>LinkCloud Admin</h2><p>Sign in to manage your page</p><label>Username</label><input type="text" id="loginUser" placeholder="admin"><label>Password</label><input type="password" id="loginPass" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()"><div class="error" id="loginError">Wrong username or password</div><button class="btn-save" onclick="doLogin()">Sign In</button></div></div>
<div id="mainApp" style="display:none"><div class="layout"><div class="editor" id="editor"><div class="topbar"><h1>LinkCloud</h1><span class="tag">ADMIN</span><div class="status-dot online" id="statusDot"></div><span class="status-text" id="statusText">Connected</span></div><div class="card" id="secProfile"><div class="card-head" onclick="tog('secProfile')"><div class="card-title"><i>&#128100;</i> Profile</div><span class="arrow">&#9662;</span></div><div class="card-body"><label>Name</label><input type="text" id="fName" oninput="markDirty()"><label>Bio</label><input type="text" id="fBio" oninput="markDirty()"><label>Cover Image</label><div class="upload-zone cover-upload" id="coverZone"><img id="coverImg" style="display:none"><div class="placeholder" id="coverPlaceholder"><span>&#128247;</span>Drop image or click</div><input type="file" accept="image/*" onchange="uploadImage(this,'cover')"></div><label>Avatar</label><div class="upload-zone avatar-upload" id="avatarZone"><img id="avatarImg" style="display:none"><div class="placeholder" id="avatarPlaceholder"><span>&#128247;</span>Drop</div><input type="file" accept="image/*" onchange="uploadImage(this,'avatar')"></div><label>Verified Badge</label><select id="fVerified" onchange="markDirty()"><option value="yes">Show</option><option value="no">Hide</option></select></div></div><div class="card" id="secSocial"><div class="card-head" onclick="tog('secSocial')"><div class="card-title"><i>&#128279;</i> Social Icons</div><span class="arrow">&#9662;</span></div><div class="card-body"><div id="socialList"></div><button class="add-btn" onclick="openModal()">+ Add Icon</button></div></div><div class="card" id="secFeat"><div class="card-head" onclick="tog('secFeat')"><div class="card-title"><i>&#11088;</i> Featured Links</div><span class="arrow">&#9662;</span></div><div class="card-body"><div id="featList"></div><button class="add-btn" onclick="addFeat()">+ Add Link</button></div></div><div class="card" id="secCar"><div class="card-head" onclick="tog('secCar')"><div class="card-title"><i>&#127904;</i> Carousel Cards</div><span class="arrow">&#9662;</span></div><div class="card-body"><div id="carList"></div><button class="add-btn" onclick="addCar()">+ Add Card</button></div></div><button class="btn-save" id="saveBtn" onclick="saveContent()">&#128190; Save Changes</button><button class="btn-sec" onclick="refreshPreview()">&#8635; Refresh Preview</button><button class="btn-sec" onclick="doLogout()" style="margin-top:16px;color:#ff4757;border-color:rgba(255,71,87,.2)">&#128682; Logout</button><p style="text-align:center;color:#333;font-size:10px;margin-top:12px">Changes save to database &rarr; landing page updates instantly</p></div><div class="preview-side"><div class="preview-label">Live Preview</div><div class="phone"><iframe id="previewFrame"></iframe></div></div></div></div>
<div class="modal-bg" id="modal"><div class="modal-box"><h3>Choose Icon</h3><div class="icon-grid" id="iconGrid"></div><button class="btn-sec" onclick="closeModal()" style="margin-top:12px">Cancel</button></div></div>
<div class="toast" id="toast"></div>
<script>
const TYPES={onlyfans:{n:'OnlyFans',bg:'#003CFF'},instagram:{n:'Instagram',bg:'linear-gradient(45deg,#F77737,#FD1D1D 50%,#833AB4)'},instagram2:{n:'Instagram 2',bg:'linear-gradient(135deg,#F77737,#FD1D1D 50%,#C13584)'},tiktok:{n:'TikTok',bg:'linear-gradient(135deg,#25F4EE,#FD1D1D)'},snapchat:{n:'Snapchat',bg:'#FFFC00'},twitter:{n:'X / Twitter',bg:'#1a1a1a'},youtube:{n:'YouTube',bg:'#FF0000'},website:{n:'Website',bg:'#7B7B7B'},amazon:{n:'Amazon',bg:'#FF9500'},amazon2:{n:'Amazon 2',bg:'#FF7500'},facebook:{n:'Facebook',bg:'#1877F2'},linkedin:{n:'LinkedIn',bg:'#0A66C2'},spotify:{n:'Spotify',bg:'#1DB954'},telegram:{n:'Telegram',bg:'#26A5E4'},whatsapp:{n:'WhatsApp',bg:'#25D366'},pinterest:{n:'Pinterest',bg:'#E60023'},twitch:{n:'Twitch',bg:'#9146FF'},discord:{n:'Discord',bg:'#5865F2'},email:{n:'Email',bg:'#EA4335'},phone:{n:'Phone',bg:'#34C759'}};
const SVG={onlyfans:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="white" stroke-width="2"/><circle cx="12" cy="12" r="4" fill="white"/></svg>',instagram:'<svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.756 0 8.331.012 7.052.07 3.656.262.262 3.656.07 7.052.012 8.331 0 8.756 0 12s.012 3.669.07 4.948c.192 3.396 3.586 6.79 6.982 6.982C8.331 23.988 8.756 24 12 24s3.669-.012 4.948-.07c3.397-.192 6.79-3.586 6.982-6.982.058-1.279.07-1.704.07-4.948s-.012-3.669-.07-4.948c-.192-3.397-3.586-6.79-6.982-6.982C15.669.012 15.244 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zm0 10.162a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 11-2.88 0 1.44 1.44 0 012.88 0z" fill="white"/></svg>',instagram2:'<svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.756 0 8.331.012 7.052.07 3.656.262.262 3.656.07 7.052.012 8.331 0 8.756 0 12s.012 3.669.07 4.948c.192 3.396 3.586 6.79 6.982 6.982C8.331 23.988 8.756 24 12 24s3.669-.012 4.948-.07c3.397-.192 6.79-3.586 6.982-6.982.058-1.279.07-1.704.07-4.948s-.012-3.669-.07-4.948c-.192-3.397-3.586-6.79-6.982-6.982C15.669.012 15.244 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zm0 10.162a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 11-2.88 0 1.44 1.44 0 012.88 0z" fill="white"/></svg>',tiktok:'<svg viewBox="0 0 24 24"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-5.1 1.75 2.9 2.9 0 012.31-4.64c.29 0 .58.03.88.14v-3.5a5.9 5.9 0 00-1-.1A6.11 6.11 0 005 13.75a6.49 6.49 0 006.5 6.5A6.41 6.41 0 0018 13.75V9.64a4.83 4.83 0 002.77 1.07V8.35c-.2-.02-.39-.06-.58-.06z" fill="white"/></svg>',snapchat:'<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 3a2 2 0 110 4 2 2 0 010-4zm0 14c-2.67 0-5-1.34-6.4-3.38l1.64-1.15A5.98 5.98 0 0012 17c2.05 0 3.85-1.03 4.76-2.53l1.64 1.15A7.97 7.97 0 0112 19z" fill="black"/></svg>',twitter:'<svg viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" fill="white"/></svg>',youtube:'<svg viewBox="0 0 24 24"><path d="M23.498 6.186a3.016 3.016 0 00-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 00.502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 002.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 002.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z" fill="white"/></svg>',website:'<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="white"/></svg>',amazon:'<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" fill="white"/></svg>',amazon2:'<svg viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" fill="white"/></svg>',facebook:'<svg viewBox="0 0 24 24"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" fill="white"/></svg>',linkedin:'<svg viewBox="0 0 24 24"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.064 2.064 0 110-4.128 2.064 2.064 0 010 4.128zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0z" fill="white"/></svg>',spotify:'<svg viewBox="0 0 24 24"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z" fill="white"/></svg>',telegram:'<svg viewBox="0 0 24 24"><path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" fill="white"/></svg>',whatsapp:'<svg viewBox="0 0 24 24"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z" fill="white"/></svg>',pinterest:'<svg viewBox="0 0 24 24"><path d="M12.017 0C5.396 0 .029 5.367.029 11.987c0 5.079 3.158 9.417 7.618 11.162-.105-.949-.199-2.403.041-3.439.219-.937 1.406-5.957 1.406-5.957s-.359-.72-.359-1.781c0-1.668.967-2.914 2.171-2.914 1.023 0 1.518.769 1.518 1.69 0 1.029-.655 2.568-.994 3.995-.283 1.194.599 2.169 1.777 2.169 2.133 0 3.772-2.249 3.772-5.495 0-2.873-2.064-4.882-5.012-4.882-3.414 0-5.418 2.561-5.418 5.207 0 1.031.397 2.138.893 2.738a.36.36 0 01.083.345l-.333 1.36c-.053.22-.174.267-.402.161-1.499-.698-2.436-2.889-2.436-4.649 0-3.785 2.75-7.262 7.929-7.262 4.163 0 7.398 2.967 7.398 6.931 0 4.136-2.607 7.464-6.227 7.464-1.216 0-2.359-.631-2.75-1.378l-.748 2.853c-.271 1.043-1.002 2.35-1.492 3.146C9.57 23.812 10.763 24 12.017 24c6.624 0 11.99-5.367 11.99-11.988C24.007 5.367 18.641 0 12.017 0z" fill="white"/></svg>',twitch:'<svg viewBox="0 0 24 24"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z" fill="white"/></svg>',discord:'<svg viewBox="0 0 24 24"><path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.865-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.618-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.078-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.076.076 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.086-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.332-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.086-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.332-.946 2.418-2.157 2.418z" fill="white"/></svg>',email:'<svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" fill="white"/></svg>',phone:'<svg viewBox="0 0 24 24"><path d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z" fill="white"/></svg>'};
let socials=[],feats=[],cars=[],isDirty=false;
async function doLogin(){const u=document.getElementById('loginUser').value,p=document.getElementById('loginPass').value;try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});const d=await r.json();if(d.ok){document.getElementById('loginScreen').style.display='none';document.getElementById('mainApp').style.display='block';loadContent()}else{document.getElementById('loginError').style.display='block'}}catch(e){document.getElementById('loginError').style.display='block'}}
async function doLogout(){await fetch('/api/auth/logout',{method:'POST'});document.getElementById('loginScreen').style.display='flex';document.getElementById('mainApp').style.display='none'}
async function checkAuth(){try{const r=await fetch('/api/auth/check');if(r.ok){document.getElementById('loginScreen').style.display='none';document.getElementById('mainApp').style.display='block';loadContent()}}catch(e){}}
async function loadContent(){try{const r=await fetch('/api/content');const d=await r.json();if(!d||!d.profile){document.getElementById('fName').value='Your Name';document.getElementById('fBio').value='Your bio here';socials=[{type:'instagram',url:''},{type:'tiktok',url:''},{type:'youtube',url:''}];feats=[];cars=[];renderAll();refreshPreview();return}document.getElementById('fName').value=d.profile.name||'';document.getElementById('fBio').value=d.profile.bio||'';document.getElementById('fVerified').value=d.profile.verified?'yes':'no';if(d.profile.coverUrl){const c=document.getElementById('coverImg');c.src=d.profile.coverUrl;c.style.display='block';document.getElementById('coverPlaceholder').style.display='none';document.getElementById('coverZone').classList.add('has-image')}if(d.profile.avatarUrl){const a=document.getElementById('avatarImg');a.src=d.profile.avatarUrl;a.style.display='block';document.getElementById('avatarPlaceholder').style.display='none';document.getElementById('avatarZone').classList.add('has-image')}socials=d.socials||[];feats=d.feats||[];cars=d.cars||[];renderAll();refreshPreview();toast('Content loaded')}catch(e){toast('Error loading')}}
async function saveContent(){const b=document.getElementById('saveBtn');b.disabled=true;b.textContent='Saving...';try{const c={profile:{name:document.getElementById('fName').value,bio:document.getElementById('fBio').value,verified:document.getElementById('fVerified').value==='yes',coverUrl:document.getElementById('coverImg').src||'',avatarUrl:document.getElementById('avatarImg').src||''},socials,feats,cars};const r=await fetch('/api/content',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(c)});const d=await r.json();if(d.ok){isDirty=false;b.textContent='Saved!';toast('Saved! Page updated.')}else throw new Error(d.error)}catch(e){b.textContent='Error';toast('Save failed')}setTimeout(()=>{b.textContent='Save Changes';b.disabled=false},2000)}
function markDirty(){isDirty=true;refreshPreview()}
function resizeAndConvert(f,mW,mH){return new Promise(r=>{const rd=new FileReader;rd.onload=e=>{const i=new Image;i.onload=()=>{const c=document.createElement('canvas');let w=i.width,h=i.height;if(w>mW||h>mH){const rt=Math.min(mW/w,mH/h);w=Math.round(w*rt);h=Math.round(h*rt)}c.width=w;c.height=h;c.getContext('2d').drawImage(i,0,0,w,h);r(c.toDataURL('image/jpeg',.7))};i.src=e.target.result};rd.readAsDataURL(f)})}
async function uploadImage(i,t){const f=i.files[0];if(!f)return;const z=document.getElementById(t+'Zone'),im=document.getElementById(t+'Img'),p=document.getElementById(t+'Placeholder');const mW=t==='cover'?800:200,mH=t==='cover'?300:200;const d=await resizeAndConvert(f,mW,mH);im.src=d;im.style.display='block';p.style.display='none';z.classList.add('has-image');markDirty();toast('Image ready!')}
async function uploadFeatImage(i,x){const f=i.files[0];if(!f)return;const d=await resizeAndConvert(f,600,300);feats[x].imgUrl=d;renderFeats();markDirty();toast('Image ready!')}
function renderAll(){renderSocials();renderFeats();renderCars()}
function renderSocials(){const e=document.getElementById('socialList');e.innerHTML=socials.map((s,i)=>{const t=TYPES[s.type]||{n:s.type,bg:'#666'};return`<div class="item-row" draggable="true" data-idx="${i}" ondragstart="dS(event)" ondragover="dO(event)" ondrop="dD(event)" ondragend="dE(event)"><span class="grip">\u2807</span><div class="mini-icon" style="background:${t.bg}">${SVG[s.type]||''}</div><div class="info"><div class="name">${t.n}</div><input type="url" placeholder="https://..." value="${esc(s.url)}" onchange="socials[${i}].url=this.value;markDirty()"></div><button class="del-btn" onclick="socials.splice(${i},1);renderSocials();markDirty()">&#10005;</button></div>`}).join('')}
function renderFeats(){const e=document.getElementById('featList');e.innerHTML=feats.map((f,i)=>{const s=f.imgUrl||'';return`<div class="feat-card"><div class="feat-head"><span>${f.title||'Link '+(i+1)}</span><button class="del-btn" onclick="feats.splice(${i},1);renderFeats();markDirty()">&#10005;</button></div><label>Card Image</label><div class="upload-zone feat-img-upload ${s?'has-image':''}">${s?`<img src="${s}">`:'<div class="placeholder"><span>&#128247;</span>Drop or click</div>'}<input type="file" accept="image/*" onchange="uploadFeatImage(this,${i})"></div><div class="row2"><div><label>Title</label><input type="text" value="${esc(f.title)}" onchange="feats[${i}].title=this.value;renderFeats();markDirty()"></div><div><label>Color</label><input type="color" value="${f.color||'#667eea'}" onchange="feats[${i}].color=this.value;markDirty()" style="width:100%;height:36px;border:none;border-radius:8px;cursor:pointer;margin-bottom:12px"></div></div><label>Link URL</label><input type="url" value="${esc(f.url)}" onchange="feats[${i}].url=this.value;markDirty()" placeholder="https://..."></div>`}).join('')}
function renderCars(){const e=document.getElementById('carList');e.innerHTML=cars.map((c,i)=>`<div class="feat-card"><div class="feat-head"><span>${c.title||'Card '+(i+1)}</span><button class="del-btn" onclick="cars.splice(${i},1);renderCars();markDirty()">&#10005;</button></div><label>Title</label><input type="text" value="${esc(c.title)}" onchange="cars[${i}].title=this.value;renderCars();markDirty()"><label>Subtitle</label><input type="text" value="${esc(c.sub||'')}" onchange="cars[${i}].sub=this.value;markDirty()"><label>Gradient</label><input type="text" value="${esc(c.grad||'')}" onchange="cars[${i}].grad=this.value;markDirty()" placeholder="linear-gradient(...)"><label>Link URL</label><input type="url" value="${esc(c.url||'')}" onchange="cars[${i}].url=this.value;markDirty()" placeholder="https://..."><label>Icon</label><select onchange="cars[${i}].icon=this.value;markDirty()">${Object.entries(TYPES).map(([k,v])=>`<option value="${k}" ${c.icon===k?'selected':''}>${v.n}</option>`).join('')}</select></div>`).join('')}
function addFeat(){feats.push({title:'New Link',imgUrl:'',url:'',color:'#667eea'});renderFeats();markDirty()}
function addCar(){cars.push({title:'New Card',sub:'',grad:'linear-gradient(135deg,#667eea,#764ba2)',url:'',icon:'website'});renderCars();markDirty()}
let dragIdx=null;function dS(e){dragIdx=+e.currentTarget.dataset.idx;e.currentTarget.style.opacity='.4'}function dO(e){e.preventDefault();e.currentTarget.style.borderColor='#667eea'}function dD(e){e.preventDefault();e.currentTarget.style.borderColor='';const t=+e.currentTarget.dataset.idx;if(dragIdx!==null&&dragIdx!==t){const m=socials.splice(dragIdx,1)[0];socials.splice(t,0,m);renderSocials();markDirty()}dragIdx=null}function dE(e){e.currentTarget.style.opacity='1';document.querySelectorAll('.item-row').forEach(r=>r.style.borderColor='')}
function openModal(){const g=document.getElementById('iconGrid');g.innerHTML=Object.entries(TYPES).map(([k,v])=>`<div class="ico-opt" onclick="socials.push({type:'${k}',url:''});renderSocials();markDirty();closeModal()"><div class="ioc" style="background:${v.bg}">${SVG[k]||''}</div><div class="ion">${v.n}</div></div>`).join('');document.getElementById('modal').classList.add('open')}
function closeModal(){document.getElementById('modal').classList.remove('open')}
function tog(id){document.getElementById(id).classList.toggle('closed')}
function esc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;')}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500)}
function refreshPreview(){const f=document.getElementById('previewFrame'),n=document.getElementById('fName').value,b=document.getElementById('fBio').value,co=document.getElementById('coverImg').src||'',av=document.getElementById('avatarImg').src||'',v=document.getElementById('fVerified').value==='yes';const sH=socials.map(s=>{const t=TYPES[s.type];if(!t)return'';const sv=SVG[s.type]||'';const w=s.url?[`<a href="${esc(s.url)}" target="_blank" style="text-decoration:none">`,`</a>`]:['',''];return`${w[0]}<div style="width:55px;height:55px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:${t.bg}">${sv}</div>${w[1]}`}).join('');const fH=feats.map(ft=>{const is=ft.imgUrl||'';const ws=ft.url?`<a href="${esc(ft.url)}" target="_blank" style="text-decoration:none;display:block">`:'';const we=ft.url?'</a>':'';const bg=is?`background-image:url('${is}');`:'background:#333;';return`${ws}<div style="${bg}background-size:cover;background-position:center;height:200px;border-radius:12px;margin-bottom:16px;position:relative;overflow:hidden"><div style="position:absolute;bottom:0;left:0;right:0;height:80px;background:linear-gradient(to top,rgba(0,0,0,.6),transparent);display:flex;align-items:flex-end;padding:12px"><div style="display:flex;align-items:center;gap:10px;color:#fff;font-weight:600;font-size:14px"><div style="width:40px;height:40px;background:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center"><svg viewBox="0 0 24 24" style="width:22px;height:22px;fill:${ft.color||'#667eea'}"><circle cx="12" cy="12" r="10"/></svg></div>${esc(ft.title)}</div></div></div>${we}`}).join('');const cH=cars.map(c=>{const sv=SVG[c.icon]||SVG.youtube;const ws=c.url?`<a href="${esc(c.url)}" target="_blank" style="text-decoration:none">`:'';const we=c.url?'</a>':'';return`${ws}<div style="flex-shrink:0;width:220px;height:220px;border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;background:${c.grad||'linear-gradient(135deg,#667eea,#764ba2)'}"><div style="width:60px;height:60px;display:flex;align-items:center;justify-content:center">${sv}</div><div style="color:#fff;font-weight:600;text-align:center;font-size:14px;margin-top:8px">${esc(c.title)}</div><div style="color:rgba(255,255,255,.8);font-size:12px;text-align:center">${esc(c.sub||'')}</div></div>${we}`}).join('');const vB=v?`<div style="position:absolute;bottom:10px;right:50%;transform:translateX(50px);width:28px;height:28px;background:#1DA1F2;border-radius:50%;display:flex;align-items:center;justify-content:center;border:3px solid #fff"><svg viewBox="0 0 24 24" style="width:16px;height:16px;fill:#fff"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg></div>`:'';const cT=co&&co!=='about:blank'&&!co.endsWith('admin.html')?`<img src="${co}" style="width:100%;height:150px;object-fit:cover;border-radius:12px 12px 0 0">`:`<div style="width:100%;height:150px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:12px 12px 0 0"></div>`;const aT=av&&av!=='about:blank'&&!av.endsWith('admin.html')?`<img src="${av}" style="width:100px;height:100px;border-radius:50%;border:4px solid #fff;object-fit:cover;position:absolute;top:-50px">`:`<div style="width:100px;height:100px;border-radius:50%;background:linear-gradient(135deg,#667eea,#764ba2);position:absolute;top:-50px;border:4px solid #fff"></div>`;f.srcdoc=`<!DOCTYPE html><html><head><meta charset="UTF-8"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}</style></head><body><div style="background:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);width:100%;max-width:400px;overflow:hidden">${cT}<div style="position:relative;height:100px;display:flex;justify-content:center;margin-bottom:20px">${aT}${vB}</div><div style="padding:0 24px 24px"><h1 style="font-size:22px;font-weight:700;color:#2d3748;text-align:center">${esc(n)}</h1><p style="color:#718096;text-align:center;font-size:13px;margin:8px 0 0">${esc(b)}</p><div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:30px auto;max-width:320px">${sH}</div>${feats.length?`<h2 style="color:#667eea;text-align:center;font-size:13px;font-weight:600;margin:24px 0 16px">FEATURED LINKS</h2>${fH}`:''}${cars.length?`<div style="margin:24px 0 16px"><h2 style="color:#4a5568;font-size:16px;font-weight:600">Featured Content</h2></div><div style="display:flex;gap:12px;overflow-x:auto;padding-bottom:10px">${cH}</div>`:''}<div style="margin-top:32px;padding:24px 0;text-align:center;border-top:1px solid #e2e8f0"><div style="color:#718096;font-size:12px;margin-bottom:8px">Powered by</div><div style="font-weight:700;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:14px">LINKCLOUD</div></div></div></div></body></html>`}
checkAuth();
window.addEventListener('beforeunload',e=>{if(isDirty){e.preventDefault();e.returnValue=''}});
</script>
</body></html>
ADMINEOF

echo "  admin.html ✓"

# --- 5. Start Docker Compose ---
echo "[5/7] Building and starting services..."
cd $APP_DIR
docker compose up -d --build

echo "  Waiting for services..."
sleep 15

# Check if running
echo "[6/7] Checking services..."
docker ps --format "table {{.Names}}\t{{.Status}}"

# Test
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80 2>/dev/null || echo "000")
echo "  HTTP status: $HTTP_CODE"

# --- 7. SSL ---
echo "[7/7] Getting SSL certificate..."
docker compose run --rm certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email admin@$DOMAIN \
    --agree-tos \
    --no-eff-email \
    -d $DOMAIN 2>&1 || echo "  SSL will be configured after DNS is set up"

# Try to enable HTTPS
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] || docker compose exec -T certbot test -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem 2>/dev/null; then
    cat > $APP_DIR/nginx/conf.d/default.conf <<SSLCONF
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000" always;
    location / {
        proxy_pass http://app:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
SSLCONF
    docker compose restart nginx
    echo "  HTTPS enabled! ✓"
fi

echo ""
echo "============================================"
echo "  ✅ LinkCloud is LIVE!"
echo "============================================"
echo ""
echo "  🌐 Site:  http://$DOMAIN"
echo "  ⚙️  Admin: http://$DOMAIN/admin"
echo ""
echo "  👤 Username: admin"
echo "  🔑 Password: LinkCloud2024!"
echo ""
echo "  ⚠️  Make sure DNS A record points"
echo "     $DOMAIN → 89.167.7.156"
echo ""
echo "  After DNS is set, run this for SSL:"
echo "  cd /opt/linkcloud && docker compose run --rm certbot certonly --webroot --webroot-path=/var/www/certbot --email admin@$DOMAIN --agree-tos --no-eff-email -d $DOMAIN && docker compose restart nginx"
echo ""
echo "============================================"
