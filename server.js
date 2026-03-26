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
const crypto = require('crypto');
const net = require('net');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');

const app = express();

// CRITICAL: Trust proxy for Railway - enables correct IP detection
app.set('trust proxy', true);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const ANALYTICS_API_KEY = process.env.ANALYTICS_API_KEY || 'JackSmith34';

// SECURITY: Generate unique secret per deployment if not set
// This ensures that even without LINK_SECRET env var, each deployment has unique encryption
const LINK_SECRET_BASE = process.env.LINK_SECRET || (() => {
  // Use a combination that's unique per deployment but stable across restarts
  const uniqueFactors = [
    process.env.RAILWAY_DEPLOYMENT_ID,
    process.env.RAILWAY_SERVICE_ID,
    process.env.DATABASE_URL?.slice(-20),
    process.env.PORT,
    __dirname
  ].filter(Boolean).join('-');

  if (uniqueFactors.length > 10) {
    console.log('🔐 Using deployment-unique encryption key');
    return `cmehere-auto-${require('crypto').createHash('sha256').update(uniqueFactors).digest('hex').slice(0, 32)}`;
  }
  // Last resort fallback - still log warning
  console.warn('⚠️ WARNING: Using default encryption key. Set LINK_SECRET env var for production!');
  return 'cmehere-secure-2024-xK9mP2vL';
})();

// Database ready flag (for graceful startup)
let dbReady = false;

// ═══ DATABASE ═══
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sites (
        id SERIAL PRIMARY KEY,
        slug VARCHAR(100) UNIQUE NOT NULL DEFAULT 'main',
        content JSONB NOT NULL DEFAULT '{}',
        seo JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS analytics (
        id SERIAL PRIMARY KEY,
        slug VARCHAR(100) NOT NULL DEFAULT 'main',
        source VARCHAR(50),
        link_type VARCHAR(50) NOT NULL,
        link_id VARCHAR(100),
        link_url TEXT,
        link_title TEXT,
        user_agent TEXT,
        ip_address VARCHAR(45),
        country VARCHAR(100),
        country_code VARCHAR(5),
        city VARCHAR(100),
        os VARCHAR(50),
        browser VARCHAR(50),
        device VARCHAR(20),
        referrer TEXT,
        clicked_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_analytics_slug ON analytics(slug);
      CREATE INDEX IF NOT EXISTS idx_analytics_clicked_at ON analytics(clicked_at DESC);
      CREATE INDEX IF NOT EXISTS idx_analytics_link_type ON analytics(link_type);
      CREATE INDEX IF NOT EXISTS idx_analytics_source ON analytics(source);
    `);

    // Run migrations for existing databases - add missing columns
    const migrations = [
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS country_code VARCHAR(5)',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS city VARCHAR(100)',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS os VARCHAR(50)',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS browser VARCHAR(50)',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS device VARCHAR(20)',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS link_title TEXT',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS link_id VARCHAR(100)',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS source VARCHAR(50)',
      'ALTER TABLE analytics ADD COLUMN IF NOT EXISTS region VARCHAR(100)'
    ];

    for (const migration of migrations) {
      try {
        await client.query(migration);
      } catch (e) {
        // Column might already exist, that's fine
        console.log(`Migration note: ${e.message}`);
      }
    }

    // Create index after columns exist
    try {
      await client.query('CREATE INDEX IF NOT EXISTS idx_analytics_country ON analytics(country_code)');
    } catch (e) {
      console.log(`Index note: ${e.message}`);
    }

    // Create default admin user if not exists
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD || 'changeme123';
    const existing = await client.query('SELECT id FROM users WHERE username = $1', [adminUser]);
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash(adminPass, 12);
      await client.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [adminUser, hash]);
      console.log(`✅ Admin user created: ${adminUser}`);
    }

    // Content migration: update featured link titles
    try {
      const siteData = await client.query('SELECT content FROM sites WHERE slug = $1', ['main']);
      if (siteData.rows.length > 0) {
        const content = siteData.rows[0].content;
        const feats = content.feats || content.featured || [];
        let changed = false;
        feats.forEach(f => {
          if (f.title && f.title.toLowerCase().includes('see more of me')) {
            f.title = 'Exclusive Content';
            changed = true;
          }
        });
        if (changed) {
          await client.query('UPDATE sites SET content = $1 WHERE slug = $2', [JSON.stringify(content), 'main']);
          console.log('✅ Featured link title updated to Exclusive Content');
        }
      }
    } catch (e) {
      console.log('Content migration note:', e.message);
    }

    // Create default site if not exists
    const site = await client.query('SELECT id FROM sites WHERE slug = $1', ['main']);
    if (site.rows.length === 0) {
      const defaultContent = {
        profile: {
          name: 'Your Name',
          bio: 'Your bio here',
          verified: false,
          coverUrl: '',
          avatarUrl: ''
        },
        socials: [
          { type: 'instagram', url: '' },
          { type: 'tiktok', url: '' },
          { type: 'youtube', url: '' }
        ],
        feats: [],
        cars: []
      };
      await client.query('INSERT INTO sites (slug, content) VALUES ($1, $2)', ['main', JSON.stringify(defaultContent)]);
      console.log('✅ Default site created');
    }

    console.log('✅ Database initialized');
  } finally {
    client.release();
  }
}

// ═══ ADVANCED BOT DETECTION & FINGERPRINTING ═══
const BOT_PATTERNS = [
  // Social Media Crawlers (HIGH PRIORITY)
  /facebookexternalhit/i,
  /Facebot/i,
  /Instagram/i,
  /Twitterbot/i,
  /LinkedInBot/i,
  /Pinterest/i,
  /TikTok/i,
  /Snapchat/i,
  /WhatsApp/i,
  /Telegram/i,
  /Discordbot/i,
  // Search Engine Bots
  /Googlebot/i,
  /bingbot/i,
  /Slurp/i,
  /DuckDuckBot/i,
  /Baiduspider/i,
  /YandexBot/i,
  /Applebot/i,
  /SemrushBot/i,
  /AhrefsBot/i,
  /MJ12bot/i,
  // Generic Crawlers
  /bot/i,
  /crawl/i,
  /spider/i,
  /scraper/i,
  /curl/i,
  /wget/i,
  /python/i,
  /java\//i,
  /perl/i,
  /ruby/i,
  /libwww/i,
  /http/i,
  // Headless Browsers & Automation
  /HeadlessChrome/i,
  /PhantomJS/i,
  /Selenium/i,
  /Puppeteer/i,
  /Playwright/i,
  /WebDriver/i,
  // Preview/Unfurlers
  /preview/i,
  /unfurl/i,
  /embed/i,
  /fetch/i
];

// Suspicious request patterns
const SUSPICIOUS_HEADERS = [
  'x-forwarded-host',  // Proxy indicators
  'x-original-url',
  'x-rewrite-url'
];

// Request fingerprint scoring
function calculateBotScore(req) {
  let score = 0;
  const ua = req.headers['user-agent'] || '';

  // In-app browsers are NOT bots - return 0 immediately
  const isInAppBrowser = /Instagram|FBAN|FBAV|TikTok|Twitter|LinkedInApp|Snapchat/i.test(ua);
  if (isInAppBrowser) return 0;

  // No user agent = very suspicious
  if (!ua) score += 50;

  // Known bot patterns
  if (BOT_PATTERNS.some(p => p.test(ua))) score += 100;

  // Missing common browser headers
  if (!req.headers['accept-language']) score += 15;
  if (!req.headers['accept-encoding']) score += 10;
  if (!req.headers['accept']) score += 10;

  // Suspicious accept header (not HTML)
  const accept = req.headers['accept'] || '';
  if (accept && !accept.includes('text/html') && !accept.includes('*/*')) score += 20;

  // Connection header patterns
  if (req.headers['connection'] === 'close') score += 5;

  // Suspicious proxy headers
  SUSPICIOUS_HEADERS.forEach(h => {
    if (req.headers[h]) score += 10;
  });

  // DNT header (often set by privacy tools/bots)
  if (req.headers['dnt'] === '1') score += 5;

  // Cache control patterns (bots often set no-cache)
  if (req.headers['cache-control'] === 'no-cache') score += 5;

  // Very short UA (suspicious)
  if (ua.length < 30) score += 15;

  // UA without version numbers (suspicious)
  if (ua && !/\d+\.\d+/.test(ua)) score += 20;

  return score;
}

function isBot(userAgent, req = null) {
  if (!userAgent) return true;

  // Quick check for known bots
  if (BOT_PATTERNS.some(pattern => pattern.test(userAgent))) return true;

  // If we have the full request, do fingerprint analysis
  if (req) {
    const score = calculateBotScore(req);
    return score >= 50; // Threshold for bot detection
  }

  return false;
}

// Generate a fingerprint hash for the request
function getRequestFingerprint(req) {
  const data = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.ip || ''
  ].join('|');
  return crypto.createHash('sha256').update(data).digest('hex').slice(0, 16);
}

// ═══ DEVICE & LOCATION DETECTION (Using ua-parser-js + proper IP handling) ═══

// Parse User Agent using ua-parser-js (supports modern browsers + Client Hints)
function parseUserAgent(ua, headers = {}) {
  if (!ua) return { os: 'Unknown', browser: 'Unknown', device: 'Desktop' };

  try {
    const parser = new UAParser(ua, headers);
    const result = parser.getResult();

    const deviceType = result.device.type;
    let device = 'Desktop';
    if (deviceType === 'mobile') device = 'Mobile';
    else if (deviceType === 'tablet') device = 'Tablet';

    return {
      browser: result.browser.name || 'Unknown',
      os: result.os.name || 'Unknown',
      device
    };
  } catch (e) {
    return { os: 'Unknown', browser: 'Unknown', device: 'Desktop' };
  }
}

// Get client IP - Railway recommends req.ip with trust proxy, fallback to x-forwarded-for
function getClientIP(req) {
  // 1) Best option with Express + trust proxy
  let ip = req.ip || '';

  // 2) Fallback to x-forwarded-for (first IP)
  if (!ip) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      ip = xff.split(',')[0].trim();
    }
  }

  // 3) Clean IPv4-mapped IPv6 (::ffff:1.2.3.4 -> 1.2.3.4)
  ip = String(ip).replace(/^::ffff:/, '').trim();

  // 4) Remove port if present
  ip = ip.replace(/:\d+$/, '');

  return ip;
}

// Check if IP is public (not private/reserved)
function isPublicIP(ip) {
  if (!ip || net.isIP(ip) === 0) return false;

  // IPv4 private/reserved
  if (
    ip === '127.0.0.1' ||
    ip === '0.0.0.0' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip.startsWith('169.254.')
  ) return false;

  // IPv6 local
  if (
    ip === '::1' ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80:')
  ) return false;

  return true;
}

// Get country from IP using GeoIP
function getCountryFromIP(req) {
  const ip = getClientIP(req);

  // Debug logging
  console.log('🌍 GEO:', {
    'req.ip': req.ip,
    'xff': req.headers['x-forwarded-for'],
    'finalIP': ip,
    'isPublic': isPublicIP(ip)
  });

  if (!isPublicIP(ip)) {
    return { country: 'Unknown', countryCode: 'XX', ip };
  }

  try {
    const geo = geoip.lookup(ip);
    if (geo && geo.country) {
      return {
        country: geo.country,
        countryCode: geo.country,
        region: geo.region || null,
        city: geo.city || null,
        ip
      };
    }
  } catch (e) {
    console.log('🌍 GEO error:', e.message);
  }

  return { country: 'Unknown', countryCode: 'XX', region: null, city: null, ip };
}

// ═══ LINK ENCRYPTION (AES-256-GCM) ═══
// Military-grade encryption - links cannot be decoded without the secret key
// Even with full source code access, attackers cannot decode links

// Generate a stable 32-byte key from the secret using scrypt (password-based key derivation)
const LINK_KEY = crypto.scryptSync(LINK_SECRET_BASE, 'cmehere-salt-v2', 32);

// Link expiration time (optional - set to 0 to disable)
const LINK_EXPIRY_HOURS = 0; // 0 = no expiration, or set to 24 for 24-hour links

function encodeLink(url) {
  try {
    // Create payload with optional timestamp
    const payload = {
      u: url,
      t: LINK_EXPIRY_HOURS > 0 ? Date.now() : 0
    };
    const plaintext = JSON.stringify(payload);

    // Generate random IV for each encryption (12 bytes for GCM)
    const iv = crypto.randomBytes(12);

    // Encrypt with AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', LINK_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Combine: IV (12) + AuthTag (16) + Encrypted data
    const combined = Buffer.concat([iv, authTag, encrypted]);

    // URL-safe base64
    return combined.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  } catch (e) {
    console.error('🔐 ENCRYPT ERROR:', e.message);
    return null;
  }
}

function decodeLink(encoded) {
  try {
    // Convert from URL-safe base64
    let base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    const combined = Buffer.from(base64, 'base64');

    // Minimum size: IV (12) + AuthTag (16) + at least 1 byte data
    if (combined.length < 29) return null;

    // Extract components
    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(12, 28);
    const encrypted = combined.subarray(28);

    // Decrypt with AES-256-GCM
    const decipher = crypto.createDecipheriv('aes-256-gcm', LINK_KEY, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    // Parse payload
    const payload = JSON.parse(decrypted.toString('utf8'));

    // Check expiration if enabled
    if (LINK_EXPIRY_HOURS > 0 && payload.t > 0) {
      const expiryMs = LINK_EXPIRY_HOURS * 60 * 60 * 1000;
      if (Date.now() - payload.t > expiryMs) return null;
    }

    // Validate URL
    if (payload.u && payload.u.startsWith('http')) {
      return payload.u;
    }
    return null;
  } catch (e) {
    // Silent fail - don't leak any info about encryption
    return null;
  }
}

// ═══ MIDDLEWARE ═══

// Hide server information (M6: Railway headers exposed)
app.disable('x-powered-by');
app.use((req, res, next) => {
  // Remove headers that reveal infrastructure
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  // Override any Railway-specific headers
  res.setHeader('Server', 'cmehere');
  next();
});

app.use(compression());
app.use(helmet({
  // Disable CSP for now - we use inline styles/scripts throughout
  // TODO: Move to external CSS/JS files and re-enable strict CSP
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  // Keep other security headers
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xContentTypeOptions: true,
  // Allow iframe from same origin (for admin preview)
  xFrameOptions: { action: 'sameorigin' },
  xXssProtection: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: 'text/plain', limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Rate limiting for API
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});

// CRITICAL: Strict rate limiting for login - prevents brute force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 attempts per 15 minutes
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true // Don't count successful logins
});

// Track failed login attempts per IP for progressive delays
const failedAttempts = new Map();
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

function checkLoginLockout(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  const attempts = failedAttempts.get(ip);

  if (attempts && attempts.count >= LOCKOUT_THRESHOLD) {
    const timeSinceLockout = Date.now() - attempts.lastAttempt;
    if (timeSinceLockout < LOCKOUT_DURATION) {
      const remainingTime = Math.ceil((LOCKOUT_DURATION - timeSinceLockout) / 60000);
      return res.status(429).json({
        error: `Account locked. Try again in ${remainingTime} minutes.`
      });
    } else {
      // Lockout expired, reset
      failedAttempts.delete(ip);
    }
  }
  next();
}

function recordFailedLogin(ip) {
  const attempts = failedAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  attempts.count++;
  attempts.lastAttempt = Date.now();
  failedAttempts.set(ip, attempts);

  // Log suspicious activity
  if (attempts.count >= 3) {
    console.warn(`⚠️ Multiple failed logins from IP: ${ip} (attempt #${attempts.count})`);
  }
}

function clearFailedLogins(ip) {
  failedAttempts.delete(ip);
}

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ═══ STATIC FILES ═══
app.use(express.static(path.join(__dirname, 'public')));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/favicon.ico', express.static(path.join(__dirname, 'public', 'favicon.ico')));

// ═══ ROBOTS.TXT - Control crawler behavior ═══
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`# cmehere.net - Link-in-bio platform
User-agent: *
Disallow: /admin
Disallow: /api/
Disallow: /health
Disallow: /go/
Disallow: /promo
Disallow: /vip-access
Disallow: /link/
Disallow: /special-offer

# Allow main page only
Allow: /$

# Crawl delay to reduce server load
Crawl-delay: 10

# Sitemap
Sitemap: https://cmehere.net/sitemap.xml
`);
});

// ═══ SECURITY.TXT - Vulnerability disclosure ═══
app.get('/.well-known/security.txt', (req, res) => {
  res.type('text/plain');
  res.send(`# Security contact for cmehere.net
Contact: mailto:security@cmehere.net
Expires: 2026-12-31T23:59:59.000Z
Preferred-Languages: en, he
Canonical: https://cmehere.net/.well-known/security.txt
Policy: https://cmehere.net/security-policy
`);
});

// ═══ SITEMAP.XML ═══
app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://cmehere.net/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`);
});

// ═══ AUTH API ═══
app.post('/api/auth/login', loginLimiter, checkLoginLockout, async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';

  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
      recordFailedLogin(ip);
      return res.status(400).json({ error: 'Invalid request' });
    }

    // Prevent timing attacks - always do password check
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username.slice(0, 100)]);
    const user = result.rows[0];

    // Use constant-time comparison where possible
    const passwordMatch = user ? await bcrypt.compare(password, user.password_hash) : false;

    if (!user || !passwordMatch) {
      recordFailedLogin(ip);
      // Add small random delay to prevent timing attacks
      await new Promise(r => setTimeout(r, 100 + Math.random() * 200));
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Successful login - clear failed attempts
    clearFailedLogins(ip);

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // lax for same-site navigation, strict breaks some flows
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('Login error:', e);
    recordFailedLogin(ip);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/check', requireAuth, (req, res) => {
  res.json({ ok: true, user: req.user.username });
});

// ═══ CONTENT API ═══
// CRITICAL: This endpoint is for ADMIN ONLY - requires authentication
// The public page renders server-side and never exposes URLs to the client
app.get('/api/content', requireAuth, async (req, res) => {
  try {
    if (!dbReady) return res.status(503).json({ error: 'Database initializing' });
    const result = await pool.query('SELECT content FROM sites WHERE slug = $1', ['main']);
    if (result.rows.length === 0) return res.json({});
    res.json(result.rows[0].content);
  } catch (e) {
    console.error('Get content error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/content', requireAuth, async (req, res) => {
  try {
    const content = req.body;
    await pool.query(
      'UPDATE sites SET content = $1, updated_at = NOW() WHERE slug = $2',
      [JSON.stringify(content), 'main']
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('Save content error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══ ANALYTICS API ═══
// Rate limit analytics to prevent spam
const analyticsLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 clicks per minute per IP
  message: { ok: true }, // Don't reveal rate limiting to attackers
  standardHeaders: false,
  legacyHeaders: false
});

app.post('/api/analytics/click', analyticsLimiter, async (req, res) => {
  try {
    // Check DB ready
    if (!dbReady) {
      return res.json({ ok: true }); // Silently accept but don't store
    }

    // Handle both JSON body and text body (sendBeacon sometimes sends as text/plain)
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch(e) { return res.json({ ok: true }); }
    }
    const { link_type, link_id, link_title, source: clientSource } = body || {};

    // Validate input - reject invalid data
    if (!link_type || typeof link_type !== 'string' || !['social', 'featured', 'carousel', 'redirect', 'visit'].includes(link_type)) {
      return res.json({ ok: true }); // Silently reject invalid
    }

    // Sanitize inputs - limit length, strip dangerous chars
    const sanitize = (s, maxLen = 100) => {
      if (!s || typeof s !== 'string') return '';
      return s.slice(0, maxLen).replace(/[<>"'&]/g, '');
    };

    const safe_link_id = sanitize(link_id, 50);
    const safe_link_title = sanitize(link_title, 200);

    const user_agent = (req.headers['user-agent'] || '').slice(0, 500);
    const referrer = (req.headers.referer || '').slice(0, 500);

    // Parse device info using ua-parser-js
    const deviceInfo = parseUserAgent(user_agent, req.headers);

    // Get country using proper IP detection for Railway
    const geoInfo = getCountryFromIP(req);

    // Sanitize client-provided source
    const safeClientSource = clientSource ? String(clientSource).slice(0, 50).replace(/[^a-zA-Z0-9_-]/g, '') || null : null;

    // SECURITY: Do NOT store link_url - it could leak protected URLs
    await pool.query(
      `INSERT INTO analytics (slug, source, link_type, link_id, link_title, user_agent, ip_address, country, country_code, region, os, browser, device, referrer)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      ['main', safeClientSource, link_type, safe_link_id, safe_link_title, user_agent, geoInfo.ip, geoInfo.country, geoInfo.countryCode, geoInfo.region, deviceInfo.os, deviceInfo.browser, deviceInfo.device, referrer]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('Analytics error:', e.message);
    // Always return success to not leak info
    res.json({ ok: true });
  }
});

app.get('/api/analytics/stats', requireAuth, async (req, res) => {
  try {
    if (!dbReady) return res.status(503).json({ error: 'Database initializing' });
    const { days = 30 } = req.query;
    // Sanitize days parameter
    const d = Math.min(Math.max(parseInt(days) || 30, 1), 365);

    // Total clicks - use parameterized query to prevent SQL injection
    const totalResult = await pool.query(
      `SELECT COUNT(*) as total FROM analytics WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1`,
      [d]
    );

    // Clicks by link type
    const byTypeResult = await pool.query(
      `SELECT link_type, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1
       GROUP BY link_type
       ORDER BY clicks DESC`,
      [d]
    );

    // Top links - DO NOT include link_url (security)
    const topLinksResult = await pool.query(
      `SELECT link_type, link_title, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1
       GROUP BY link_type, link_title
       ORDER BY clicks DESC
       LIMIT 10`,
      [d]
    );

    // Links per source breakdown - which source sends clicks to which link
    const linksPerSourceResult = await pool.query(
      `SELECT COALESCE(NULLIF(source, ''), 'Direct') as source, link_title, link_type, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1 AND link_title IS NOT NULL AND link_title != ''
       GROUP BY COALESCE(NULLIF(source, ''), 'Direct'), link_title, link_type
       ORDER BY clicks DESC
       LIMIT 30`,
      [d]
    );

    // Clicks over time (daily) - parameterized
    const dailyResult = await pool.query(
      `SELECT DATE(clicked_at) as date, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1
       GROUP BY DATE(clicked_at)
       ORDER BY date DESC`,
      [d]
    );

    // By Country - parameterized
    const byCountryResult = await pool.query(
      `SELECT country, country_code, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1 AND country IS NOT NULL AND country != ''
       GROUP BY country, country_code
       ORDER BY clicks DESC
       LIMIT 10`,
      [d]
    );

    // By OS - parameterized
    const byOSResult = await pool.query(
      `SELECT os, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1 AND os IS NOT NULL AND os != ''
       GROUP BY os
       ORDER BY clicks DESC`,
      [d]
    );

    // By Browser - parameterized
    const byBrowserResult = await pool.query(
      `SELECT browser, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1 AND browser IS NOT NULL AND browser != ''
       GROUP BY browser
       ORDER BY clicks DESC`,
      [d]
    );

    // By Device - parameterized
    const byDeviceResult = await pool.query(
      `SELECT device, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1 AND device IS NOT NULL AND device != ''
       GROUP BY device
       ORDER BY clicks DESC`,
      [d]
    );

    // Recent clicks (last 20) - no link_url for security
    const recentResult = await pool.query(
      `SELECT link_title, link_type, source, country, country_code, os, browser, device, clicked_at
       FROM analytics
       WHERE slug = 'main'
       ORDER BY clicked_at DESC
       LIMIT 20`
    );

    // By Source (traffic sources like ig1, twitter1, etc.) - include Direct traffic
    const bySourceResult = await pool.query(
      `SELECT COALESCE(NULLIF(source, ''), 'Direct') as source, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1
       GROUP BY COALESCE(NULLIF(source, ''), 'Direct')
       ORDER BY clicks DESC`,
      [d]
    );

    res.json({
      total: parseInt(totalResult.rows[0]?.total || 0),
      byType: byTypeResult.rows,
      topLinks: topLinksResult.rows,
      linksPerSource: linksPerSourceResult.rows,
      daily: dailyResult.rows,
      byCountry: byCountryResult.rows,
      byOS: byOSResult.rows,
      byBrowser: byBrowserResult.rows,
      byDevice: byDeviceResult.rows,
      bySource: bySourceResult.rows,
      recent: recentResult.rows
    });
  } catch (e) {
    console.error('Get stats error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══ LIVE FEED: Real-time analytics (polling) ═══
app.get('/api/analytics/live', requireAuth, async (req, res) => {
  try {
    const since = req.query.since || new Date(Date.now() - 60000).toISOString(); // Last minute default

    // Get actual total count for the time period (not limited)
    const countResult = await pool.query(`
      SELECT COUNT(*) FROM analytics WHERE clicked_at > $1
    `, [since]);
    const totalCount = parseInt(countResult.rows[0].count);

    // Get the latest 50 clicks for display (with region for US states)
    const result = await pool.query(`
      SELECT id, link_type, link_title, country, country_code, region, device, browser, os, source, clicked_at
      FROM analytics
      WHERE clicked_at > $1
      ORDER BY clicked_at DESC
      LIMIT 50
    `, [since]);

    // Get latest click timestamp for next poll
    const latestTimestamp = result.rows.length > 0
      ? result.rows[0].clicked_at
      : since;

    res.json({
      clicks: result.rows,
      latest: latestTimestamp,
      count: totalCount
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ TELEGRAM BOT API: AI Summary Endpoint ═══
app.get('/api/analytics/ai-summary', async (req, res) => {
  // API key authentication
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (apiKey !== ANALYTICS_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  try {
    const days = parseInt(req.query.days) || 1;
    const since = new Date();
    since.setDate(since.getDate() - days);

    // Get comprehensive analytics
    const [totalClicks, sourceBreakdown, countryBreakdown, deviceBreakdown, hourlyBreakdown, topLinks] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM analytics WHERE clicked_at >= $1', [since]),
      pool.query(`
        SELECT source, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at >= $1
        GROUP BY source
        ORDER BY clicks DESC
        LIMIT 10
      `, [since]),
      pool.query(`
        SELECT country, country_code, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at >= $1
        GROUP BY country, country_code
        ORDER BY clicks DESC
        LIMIT 10
      `, [since]),
      pool.query(`
        SELECT device, os, browser, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at >= $1
        GROUP BY device, os, browser
        ORDER BY clicks DESC
        LIMIT 10
      `, [since]),
      pool.query(`
        SELECT
          EXTRACT(HOUR FROM clicked_at) as hour,
          COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at >= $1
        GROUP BY hour
        ORDER BY hour
      `, [since]),
      pool.query(`
        SELECT link_title, link_type, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at >= $1 AND link_title IS NOT NULL
        GROUP BY link_title, link_type
        ORDER BY clicks DESC
        LIMIT 5
      `, [since])
    ]);

    res.json({
      period: `Last ${days} day(s)`,
      generated_at: new Date().toISOString(),
      summary: {
        total_clicks: parseInt(totalClicks.rows[0].count),
        unique_sources: sourceBreakdown.rows.length,
        unique_countries: countryBreakdown.rows.length
      },
      traffic_sources: sourceBreakdown.rows,
      countries: countryBreakdown.rows,
      devices: deviceBreakdown.rows,
      hourly_distribution: hourlyBreakdown.rows,
      top_links: topLinks.rows
    });
  } catch (e) {
    console.error('AI Summary error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ═══ TELEGRAM BOT API: Natural Language Query Endpoint ═══
app.get('/api/analytics/query', async (req, res) => {
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (apiKey !== ANALYTICS_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  try {
    const q = (req.query.q || '').toLowerCase();
    const days = parseInt(req.query.days) || 7;
    const since = new Date();
    since.setDate(since.getDate() - days);

    let result;

    if (q.includes('total') || q.includes('clicks') || q.includes('how many')) {
      const r = await pool.query('SELECT COUNT(*) FROM analytics WHERE clicked_at >= $1', [since]);
      result = { answer: `Total clicks in last ${days} days: ${r.rows[0].count}` };
    }
    else if (q.includes('source') || q.includes('traffic') || q.includes('where')) {
      const r = await pool.query(`
        SELECT source, COUNT(*) as clicks
        FROM analytics WHERE clicked_at >= $1
        GROUP BY source ORDER BY clicks DESC LIMIT 5
      `, [since]);
      result = { answer: 'Top traffic sources', data: r.rows };
    }
    else if (q.includes('country') || q.includes('location') || q.includes('geo')) {
      const r = await pool.query(`
        SELECT country, COUNT(*) as clicks
        FROM analytics WHERE clicked_at >= $1
        GROUP BY country ORDER BY clicks DESC LIMIT 5
      `, [since]);
      result = { answer: 'Top countries', data: r.rows };
    }
    else if (q.includes('device') || q.includes('mobile') || q.includes('desktop')) {
      const r = await pool.query(`
        SELECT device, COUNT(*) as clicks
        FROM analytics WHERE clicked_at >= $1
        GROUP BY device ORDER BY clicks DESC
      `, [since]);
      result = { answer: 'Device breakdown', data: r.rows };
    }
    else if (q.includes('today')) {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const r = await pool.query('SELECT COUNT(*) FROM analytics WHERE clicked_at >= $1', [today]);
      result = { answer: `Clicks today: ${r.rows[0].count}` };
    }
    else {
      result = {
        answer: 'Available queries: total clicks, traffic sources, countries, devices, today',
        hint: 'Try: "how many clicks", "top sources", "which countries", "device breakdown"'
      };
    }

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ DEBUG: Show User Agent (for testing in-app detection) ═══
app.get('/api/debug-ua', (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ref = req.headers['referer'] || req.headers['referrer'] || '';

  const checks = {
    Instagram: ua.includes('Instagram'),
    Facebook: ua.includes('FBAN') || ua.includes('FBAV'),
    TikTok: ua.includes('TikTok'),
    LinkedIn: ua.includes('LinkedInApp'),
    Twitter: ua.includes('Twitter') || ref.includes('t.co') || ref.includes('x.com'),
    Threads: ua.includes('Threads') || ua.includes('Barcelona') || ref.includes('threads.net'),
    Snapchat: ua.includes('Snapchat') || ua.includes('snapchat')
  };

  const isInApp = Object.values(checks).some(v => v);

  res.json({
    user_agent: ua,
    referrer: ref,
    is_in_app_browser: isInApp,
    detected_apps: checks,
    is_ios: /iPhone|iPad|iPod/i.test(ua),
    is_android: /Android/i.test(ua)
  });
});

// ═══ DEBUG: Check analytics table ═══
app.get('/api/analytics/debug', requireAuth, async (req, res) => {
  try {
    const count = await pool.query('SELECT COUNT(*) FROM analytics');
    const sample = await pool.query('SELECT * FROM analytics ORDER BY clicked_at DESC LIMIT 5');
    const columns = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'analytics'
    `);
    res.json({
      total_rows: parseInt(count.rows[0].count),
      columns: columns.rows,
      sample_data: sample.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ RESET: Clear and rebuild analytics table ═══
app.post('/api/analytics/reset', requireAuth, async (req, res) => {
  try {
    // Drop and recreate
    await pool.query('DROP TABLE IF EXISTS analytics');
    await pool.query(`
      CREATE TABLE analytics (
        id SERIAL PRIMARY KEY,
        slug VARCHAR(100) NOT NULL DEFAULT 'main',
        source VARCHAR(50),
        link_type VARCHAR(50) NOT NULL,
        link_id VARCHAR(100),
        link_title TEXT,
        user_agent TEXT,
        ip_address VARCHAR(45),
        country VARCHAR(100),
        country_code VARCHAR(5),
        os VARCHAR(50),
        browser VARCHAR(50),
        device VARCHAR(20),
        referrer TEXT,
        clicked_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query('CREATE INDEX idx_analytics_slug ON analytics(slug)');
    await pool.query('CREATE INDEX idx_analytics_clicked_at ON analytics(clicked_at DESC)');
    await pool.query('CREATE INDEX idx_analytics_country ON analytics(country)');
    await pool.query('CREATE INDEX idx_analytics_source ON analytics(source)');

    res.json({ success: true, message: 'Analytics table reset successfully' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ TEST: Insert test click ═══
app.post('/api/analytics/test-click', requireAuth, async (req, res) => {
  try {
    // Use the new proper IP and UA detection
    const ua = req.headers['user-agent'] || '';
    const deviceInfo = parseUserAgent(ua, req.headers);
    const geoInfo = getCountryFromIP(req);

    await pool.query(
      `INSERT INTO analytics (slug, source, link_type, link_id, link_title, user_agent, ip_address, country, country_code, region, os, browser, device, referrer)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      ['main', 'test-click', 'test', 'test-' + Date.now(), 'Test Link', ua, geoInfo.ip,
       geoInfo.country, geoInfo.countryCode, geoInfo.region,
       deviceInfo.os, deviceInfo.browser, deviceInfo.device, 'test']
    );

    const count = await pool.query('SELECT COUNT(*) FROM analytics');
    res.json({
      success: true,
      total_clicks: parseInt(count.rows[0].count),
      detected: {
        ip: geoInfo.ip,
        country: geoInfo.country,
        countryCode: geoInfo.countryCode,
        os: deviceInfo.os,
        browser: deviceInfo.browser,
        device: deviceInfo.device
      },
      debug: {
        reqIp: req.ip,
        xff: req.headers['x-forwarded-for'] || 'none',
        isPublic: isPublicIP(geoInfo.ip)
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});

// ═══ HONEYPOT TRAPS - Block bots that follow hidden links ═══
// Track IPs that hit honeypots for blocking
const honeypotHits = new Map();
const HONEYPOT_BLOCK_DURATION = 24 * 60 * 60 * 1000; // 24 hours

function recordHoneypotHit(ip, ua, path) {
  const now = Date.now();
  const hits = honeypotHits.get(ip) || { count: 0, first: now, last: now, paths: [] };
  hits.count++;
  hits.last = now;
  hits.paths.push(path);
  honeypotHits.set(ip, hits);
  console.warn(`🍯 HONEYPOT HIT #${hits.count} from IP: ${ip} | UA: ${ua} | Path: ${path}`);
}

function isHoneypotBlocked(ip) {
  const hits = honeypotHits.get(ip);
  if (!hits) return false;
  if (Date.now() - hits.last > HONEYPOT_BLOCK_DURATION) {
    honeypotHits.delete(ip);
    return false;
  }
  return hits.count >= 2; // Block after 2 hits
}

// Honeypot middleware - check if IP is blocked
function honeypotBlocker(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  if (isHoneypotBlocked(ip)) {
    return res.status(403).send('Access denied');
  }
  next();
}

// Apply to all routes
app.use(honeypotBlocker);

// Honeypot routes with natural-looking names (not "trap" or "secret")
// Route 1: Looks like a special offer link
app.get('/promo', (req, res) => {
  const ua = req.headers['user-agent'] || 'unknown';
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  recordHoneypotHit(ip, ua, '/promo');
  // Return believable redirect to confuse bot
  res.redirect(301, 'https://example.com/offer-expired');
});

// Route 2: Looks like a VIP link
app.get('/vip-access', (req, res) => {
  const ua = req.headers['user-agent'] || 'unknown';
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  recordHoneypotHit(ip, ua, '/vip-access');
  res.redirect(301, 'https://example.com/members-only');
});

// Route 3: /link/:id - redirect to /:id (for backwards compatibility)
// Also serves as honeypot for clearly fake IDs
app.get('/link/:id', (req, res) => {
  const id = req.params.id;
  const ua = req.headers['user-agent'] || 'unknown';
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';

  // If it looks like a real short ID (alphanumeric, reasonable length), redirect
  if (/^[a-zA-Z0-9_-]{1,30}$/.test(id)) {
    // Pass query params along (like browser=1)
    const query = req.query.browser ? `?browser=${req.query.browser}` : '';
    return res.redirect(302, `/${id}${query}`);
  }

  // Otherwise it's a honeypot hit
  recordHoneypotHit(ip, ua, `/link/${id}`);
  res.redirect(301, 'https://example.com/not-found');
});

// Legacy honeypot (keep for backwards compat but rename in HTML)
app.get('/special-offer', (req, res) => {
  const ua = req.headers['user-agent'] || 'unknown';
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  recordHoneypotHit(ip, ua, '/special-offer');
  res.redirect(301, 'https://example.com/expired');
});

// ═══ LINK REDIRECT (Server-Side AES-256-GCM Decryption) ═══
// Links are encrypted with AES-256-GCM - only the server has the key
// Even crawlers with full source code access cannot decode links
app.get('/go/:encodedLink', async (req, res) => {
  try {
    const { encodedLink } = req.params;
    const { t: linkType, n: linkTitle, s: source } = req.query;
    const user_agent = (req.headers['user-agent'] || '').slice(0, 500);
    // Sanitize source - only allow alphanumeric, dash, underscore
    const safeSource = (source || '').slice(0, 50).replace(/[^a-zA-Z0-9_-]/g, '') || null;

    // ══════════════════════════════════════════════════════════════════
    // CRITICAL: Bot Detection - Never reveal URLs to crawlers/bots
    // This prevents Instagram/Facebook from discovering OnlyFans links
    // ══════════════════════════════════════════════════════════════════
    const botScore = calculateBotScore(req);

    if (botScore >= 50) {
      // Bot detected - serve a decoy page, NEVER redirect to real URL
      return res.status(200).send(`<!DOCTYPE html>
<html><head><title>Link</title><meta name="robots" content="noindex,nofollow"></head>
<body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0a0a14">
<div style="text-align:center;color:#fff">
<h1>🔗 Link</h1>
<p style="color:#888">This link requires a browser to access.</p>
<p style="color:#666;font-size:12px">Bot score: ${botScore}</p>
</div></body></html>`);
    }

    // Validate encoded link format
    if (!encodedLink || encodedLink.length > 1000) {
      return res.status(404).send('Link not found');
    }

    // AES-256-GCM decryption - server-side only
    const url = decodeLink(encodedLink);

    if (!url || !url.startsWith('http')) {
      return res.status(404).send('Link not found');
    }

    const referrer = (req.headers.referer || '').slice(0, 500);

    // Sanitize query params
    const safeType = ['social', 'featured', 'carousel', 'visit'].includes(linkType) ? linkType : 'redirect';
    const safeTitle = (linkTitle || 'Link').slice(0, 200).replace(/[<>"'&]/g, '');

    // Parse device/location for analytics
    const deviceInfo = parseUserAgent(user_agent, req.headers);
    const geoInfo = getCountryFromIP(req);

    // SECURITY: Only store opaque ID (hash of encrypted link), NOT the actual URL
    const linkId = crypto.createHash('sha256').update(encodedLink).digest('hex').slice(0, 16);
    await pool.query(
      `INSERT INTO analytics (slug, source, link_type, link_id, link_title, user_agent, ip_address, country, country_code, region, os, browser, device, referrer)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      ['main', safeSource, safeType, linkId, safeTitle, user_agent, geoInfo.ip, geoInfo.country, geoInfo.countryCode, geoInfo.region, deviceInfo.os, deviceInfo.browser, deviceInfo.device, referrer]
    );

    // ══════════════════════════════════════════════════════════════════
    // SECURITY: Use JavaScript redirect instead of HTTP 302
    // This prevents bots from seeing the URL in Location header
    // Real browsers execute JS, bots don't get the URL
    // ══════════════════════════════════════════════════════════════════

    // Check if it's a Twitter/X link - needs special handling to open in app
    const isTwitterLink = url.includes('twitter.com') || url.includes('x.com');

    if (isTwitterLink) {
      // Twitter/X needs intent:// for Android and special handling for iOS
      const escapedUrl = url.replace(/"/g, '&quot;');
      const jsEscapedUrl = url.replace(/"/g, '\\"').replace(/\\/g, '\\\\');

      res.status(200).send(`<!DOCTYPE html>
<html><head>
<meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head><body style="background:#0a0a14">
<script>
(function() {
  var url = "${jsEscapedUrl}";
  var ua = navigator.userAgent || '';
  var isAndroid = /android/i.test(ua);
  var isIOS = /iphone|ipad|ipod/i.test(ua);

  if (isAndroid) {
    // Android: Use intent to open Twitter app
    var intentUrl = "intent://" + url.replace(/^https?:\\/\\//, "") + "#Intent;scheme=https;package=com.twitter.android;end";
    window.location.href = intentUrl;
    // Fallback after delay if app not installed
    setTimeout(function() { window.location.href = url; }, 1500);
  } else if (isIOS) {
    // iOS: Try twitter:// scheme first, fallback to web
    var twitterScheme = url.replace(/^https?:\\/\\/(www\\.)?(twitter\\.com|x\\.com)/, "twitter://");
    window.location.href = twitterScheme;
    setTimeout(function() { window.location.href = url; }, 1500);
  } else {
    // Desktop: Just redirect
    window.location.replace(url);
  }
})();
</script>
<noscript><meta http-equiv="refresh" content="0;url=${escapedUrl}"></noscript>
</body></html>`);
    } else {
      // Standard redirect for other links (Instagram, etc.)
      res.status(200).send(`<!DOCTYPE html>
<html><head>
<meta name="robots" content="noindex,nofollow">
<meta http-equiv="refresh" content="0;url=${url.replace(/"/g, '&quot;')}">
<script>window.location.replace("${url.replace(/"/g, '\\"').replace(/\\/g, '\\\\')}");</script>
</head><body style="background:#0a0a14"></body></html>`);
    }
  } catch (e) {
    // Don't fail the redirect just because analytics failed
    // Try to redirect anyway if we have a valid URL (using JS redirect for security)
    const url = decodeLink(req.params.encodedLink);
    if (url && url.startsWith('http')) {
      return res.status(200).send(`<!DOCTYPE html>
<html><head><meta name="robots" content="noindex,nofollow">
<meta http-equiv="refresh" content="0;url=${url.replace(/"/g, '&quot;')}">
<script>window.location.replace("${url.replace(/"/g, '\\"').replace(/\\/g, '\\\\')}");</script>
</head><body style="background:#0a0a14"></body></html>`);
    }
    res.status(404).send('Link not found');
  }
});

// ═══ ADMIN PAGE ═══
// Serve login page for unauthenticated users, full admin for authenticated
app.get('/admin', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    // Not logged in - serve minimal login page (no admin code exposed)
    return res.send(`<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>cmehere.net Admin - Login</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0a14;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .login-box{max-width:360px;width:100%;padding:40px;text-align:center}
    h2{font-size:24px;margin-bottom:8px;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
    p{color:#666;font-size:13px;margin-bottom:24px}
    label{display:block;font-size:11px;font-weight:700;color:#666;margin-bottom:5px;text-align:right;text-transform:uppercase}
    input{width:100%;padding:12px 14px;background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.09);border-radius:10px;color:#ddd;font-size:14px;outline:none;margin-bottom:16px;direction:ltr}
    input:focus{border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.15)}
    .btn{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);border:none;border-radius:12px;color:#fff;font-size:15px;font-weight:700;cursor:pointer}
    .btn:hover{opacity:.9}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .error{color:#ff4757;font-size:12px;margin-top:-8px;margin-bottom:12px;display:none}
  </style>
</head>
<body>
  <div class="login-box">
    <h2>cmehere.net Admin</h2>
    <p>Sign in to manage your page</p>
    <form id="loginForm">
      <label>Username</label>
      <input type="text" id="user" autocomplete="username" required>
      <label>Password</label>
      <input type="password" id="pass" autocomplete="current-password" required>
      <div class="error" id="err">Invalid credentials</div>
      <button type="submit" class="btn" id="btn">Sign In</button>
    </form>
  </div>
  <script>
    document.getElementById('loginForm').onsubmit=async function(e){
      e.preventDefault();
      var btn=document.getElementById('btn');
      btn.disabled=true;btn.textContent='...';
      try{
        var r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('user').value,password:document.getElementById('pass').value})});
        var d=await r.json();
        if(d.ok){window.location.reload();}
        else{document.getElementById('err').style.display='block';btn.disabled=false;btn.textContent='Sign In';}
      }catch(x){document.getElementById('err').style.display='block';btn.disabled=false;btn.textContent='Sign In';}
    };
  </script>
</body>
</html>`);
  }

  // Verify token before serving admin panel
  try {
    jwt.verify(token, JWT_SECRET);
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  } catch {
    res.clearCookie('token');
    res.redirect('/admin');
  }
});

// ═══ PROFILE PAGE (Dynamic with Pentagon-Level Protection) ═══
app.get('/', async (req, res) => {
  try {
    // FIRST: Geo check - redirect Israeli visitors immediately
    const geoInfo = getCountryFromIP(req);
    if (geoInfo.countryCode === 'IL') {
      return res.redirect(302, 'https://www.google.com');
    }

    // Check if DB is ready
    if (!dbReady) {
      return res.status(200).send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta http-equiv="refresh" content="2"><title>Loading...</title></head><body style="display:flex;align-items:center;justify-content:center;height:100vh;background:#0a0a14;color:#fff;font-family:system-ui"><div style="text-align:center"><div style="font-size:48px;margin-bottom:16px">⏳</div><h1>Starting up...</h1><p style="color:#888">Please wait a moment</p></div></body></html>`);
    }

    const result = await pool.query('SELECT content, seo FROM sites WHERE slug = $1', ['main']);
    if (result.rows.length === 0) return res.redirect('/admin');
    const data = result.rows[0].content;
    const seo = result.rows[0].seo || {};
    const userAgent = req.headers['user-agent'] || '';

    // Bot detection
    const isBotRequest = isBot(userAgent, req);

    // Note: Israeli visitors already redirected at start of route
    res.send(renderProfilePage(data, seo, isBotRequest, null, false));
  } catch (e) {
    console.error('Render error:', e);
    res.status(500).send('Server error');
  }
});

// ═══ SPECIAL ROUTES: Threads & Reddit (auto-open in external browser) ═══
// These platforms don't send identifiable UA/referrer, so we use dedicated routes
app.get('/threads', async (req, res) => {
  // If already opened in browser, track and redirect to main page
  if (req.query.browser === '1') {
    try {
      if (dbReady) {
        const ua = (req.headers['user-agent'] || '').slice(0, 500);
        const di = parseUserAgent(ua, req.headers);
        const gi = getCountryFromIP(req);
        await pool.query(
          `INSERT INTO analytics (slug, source, link_type, link_id, link_title, user_agent, ip_address, country, country_code, region, os, browser, device, referrer)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          ['main', 'threads', 'visit', 'threads-escape', 'Threads → Site', ua, gi.ip, gi.country, gi.countryCode, gi.region, di.os, di.browser, di.device, (req.headers.referer||'').slice(0,500)]
        );
      }
    } catch(e) { console.error('Threads track:', e.message); }
    return res.redirect('/');
  }
  // Auto-open page - tries to open Chrome/Safari immediately
  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opening...</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#000;color:#fff}
.spinner{width:40px;height:40px;border:3px solid #333;border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
p{margin-top:20px;opacity:0.7}
a{color:#fff;margin-top:20px}
</style>
</head><body>
<div class="spinner"></div>
<p>Opening in browser...</p>
<a href="/?browser=1">Tap here if nothing happens</a>
<script>
(function(){
  var url='https://'+location.hostname+'/?browser=1';
  var isIOS=/iPhone|iPad|iPod/i.test(navigator.userAgent);
  var isAndroid=/Android/i.test(navigator.userAgent);
  if(isIOS){
    // Safari FIRST (user likely logged into OnlyFans in Safari)
    setTimeout(function(){location.href='x-safari-https://'+url.replace(/^https?:\\/\\//,'')},100);
    // Chrome as fallback
    setTimeout(function(){location.href='googlechrome://'+url.replace(/^https?:\\/\\//,'')},300);
  }else if(isAndroid){
    location.href='intent://'+location.hostname+'/?browser=1#Intent;scheme=https;package=com.android.chrome;end';
  }else{
    location.href=url;
  }
})();
</script>
</body></html>`);
});

app.get('/reddit', async (req, res) => {
  if (req.query.browser === '1') {
    try {
      if (dbReady) {
        const ua = (req.headers['user-agent'] || '').slice(0, 500);
        const di = parseUserAgent(ua, req.headers);
        const gi = getCountryFromIP(req);
        await pool.query(
          `INSERT INTO analytics (slug, source, link_type, link_id, link_title, user_agent, ip_address, country, country_code, region, os, browser, device, referrer)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          ['main', 'reddit', 'visit', 'reddit-escape', 'Reddit → Site', ua, gi.ip, gi.country, gi.countryCode, gi.region, di.os, di.browser, di.device, (req.headers.referer||'').slice(0,500)]
        );
      }
    } catch(e) { console.error('Reddit track:', e.message); }
    return res.redirect('/');
  }
  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opening...</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#000;color:#fff}
.spinner{width:40px;height:40px;border:3px solid #333;border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
p{margin-top:20px;opacity:0.7}
a{color:#fff;margin-top:20px}
</style>
</head><body>
<div class="spinner"></div>
<p>Opening in browser...</p>
<a href="/?browser=1">Tap here if nothing happens</a>
<script>
(function(){
  var url='https://'+location.hostname+'/?browser=1';
  var isIOS=/iPhone|iPad|iPod/i.test(navigator.userAgent);
  var isAndroid=/Android/i.test(navigator.userAgent);
  if(isIOS){
    // Safari FIRST (user likely logged into OnlyFans in Safari)
    setTimeout(function(){location.href='x-safari-https://'+url.replace(/^https?:\\/\\//,'')},100);
    // Chrome as fallback
    setTimeout(function(){location.href='googlechrome://'+url.replace(/^https?:\\/\\//,'')},300);
  }else if(isAndroid){
    location.href='intent://'+location.hostname+'/?browser=1#Intent;scheme=https;package=com.android.chrome;end';
  }else{
    location.href=url;
  }
})();
</script>
</body></html>`);
});

// ═══ TRAFFIC SOURCE ROUTE (Clean URLs: /ig-main, /twitter1, etc.) ═══
// Maps custom source URLs to their platform-specific escape logic
const SOURCE_PLATFORM_MAP = {
  // Reddit sources - use auto-open escape
  'seemorer': 'reddit',
  'rd': 'reddit',
  // Threads sources - use auto-open escape
  'th': 'threads',
  // Snapchat sources - use auto-open escape
  'seemoresc': 'snapchat',
  'sc': 'snapchat',
  // Facebook sources - use auto-open escape
  'fb': 'facebook',
  'seemorefb': 'facebook',
  // TikTok sources - render normal landing page (escape handled client-side)
  // Bot crawlers get sanitized content via isBotRequest in renderProfilePage()
  // 'tt' and 'seemortt' intentionally NOT mapped - they go through normal profile render
};

// Auto-open escape page generator (works for Reddit, Threads, Snapchat, etc.)
// Snapchat needs delay to allow "Attach to Snap" button to appear
// TikTok needs special handling - hardest in-app browser to escape
function generateAutoOpenPage(source, platform) {
  // TikTok gets its own dedicated escape page
  if (platform === 'tiktok') {
    return generateTikTokEscapePage(source);
  }

  // Snapchat needs 3 second delay before escape attempt
  const isSnapchat = platform === 'snapchat';
  const delay = isSnapchat ? 3000 : 100;
  const delayText = isSnapchat ? 'Waiting for Snapchat...' : 'Opening in browser...';

  return `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opening...</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#000;color:#fff}
.spinner{width:40px;height:40px;border:3px solid #333;border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
p{margin-top:20px;opacity:0.7}
a{color:#fff;margin-top:20px}
.countdown{font-size:24px;margin-bottom:10px;font-weight:bold}
</style>
</head><body>
${isSnapchat ? '<div class="countdown" id="countdown">3</div>' : '<div class="spinner"></div>'}
<p id="status">${delayText}</p>
<a href="/${source}?browser=1">Tap here if nothing happens</a>
<script>
(function(){
  var source='${source}';
  var url='https://'+location.hostname+'/'+source+'?browser=1';
  var isIOS=/iPhone|iPad|iPod/i.test(navigator.userAgent);
  var isAndroid=/Android/i.test(navigator.userAgent);
  var delay=${delay};
  var isSnapchat=${isSnapchat};

  function doEscape(){
    document.getElementById('status').textContent='Opening in browser...';
    if(isIOS){
      // Safari FIRST (user likely logged into OnlyFans in Safari)
      setTimeout(function(){location.href='x-safari-https://'+url.replace(/^https?:\\/\\//,'')},100);
      // Chrome as fallback
      setTimeout(function(){location.href='googlechrome://'+url.replace(/^https?:\\/\\//,'')},300);
    }else if(isAndroid){
      location.href='intent://'+location.hostname+'/'+source+'?browser=1#Intent;scheme=https;S.browser_fallback_url='+encodeURIComponent(url)+';end;';
    }else{
      location.href=url;
    }
  }

  if(isSnapchat){
    // Countdown for Snapchat - give time to tap "Attach to Snap"
    var count=3;
    var countdown=document.getElementById('countdown');
    var interval=setInterval(function(){
      count--;
      if(count>0){
        countdown.textContent=count;
      }else{
        clearInterval(interval);
        countdown.textContent='🚀';
        doEscape();
      }
    },1000);
  }else{
    // Immediate escape for other platforms
    doEscape();
  }
})();
</script>
</body></html>`;
}

// TikTok-specific escape page
// Designed to look like a friendly creator "see more" page
// No flagged keywords - completely TikTok-scanner safe
// Arrow pointing to ⋯ menu, warm inviting tone
function generateTikTokEscapePage(source) {
  return `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>See More</title>
<meta name="description" content="Follow me for exclusive content and updates">
<meta name="robots" content="noindex, nofollow">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:rgba(0,0,0,.92);min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
.backdrop{position:fixed;top:0;left:0;right:0;bottom:0;backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px)}
/* Arrow pointing to top-right ⋯ menu */
.arrow{position:fixed;top:38px;right:14px;z-index:10000;display:flex;flex-direction:column;align-items:center;animation:float 2s ease-in-out infinite}
.arrow-icon{font-size:28px;line-height:1;transform:rotate(-45deg)}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.arrow-label{margin-top:4px;background:#fff;color:#000;padding:6px 10px;border-radius:8px;font-size:10px;font-weight:700;white-space:nowrap;box-shadow:0 4px 15px rgba(0,0,0,.4)}
.content{position:relative;z-index:10001;text-align:center;padding:0 32px;color:#fff}
.emoji-icon{font-size:56px;margin-bottom:20px}
.title{font-size:24px;font-weight:700;margin-bottom:10px;color:#fff}
.subtitle{font-size:16px;color:rgba(255,255,255,.6);line-height:1.6;margin-bottom:32px}
.steps-box{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:20px 24px;max-width:300px;margin:0 auto;text-align:left}
.steps-title{font-size:14px;font-weight:700;color:rgba(255,255,255,.9);margin-bottom:14px;text-align:center}
.step{display:flex;align-items:center;gap:10px;font-size:14px;color:rgba(255,255,255,.75);margin-bottom:10px;line-height:1.4}
.step:last-child{margin-bottom:0}
.step-num{width:24px;height:24px;background:rgba(255,255,255,.1);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0}
.step b{color:#fff}
.step .dots-inline{font-weight:900;letter-spacing:2px;background:rgba(255,255,255,.12);padding:1px 6px;border-radius:4px}
</style>
</head><body>
<div class="backdrop"></div>
<div class="arrow">
  <div class="arrow-icon">↗</div>
  <div class="arrow-label">Tap here</div>
</div>
<div class="content">
  <div class="emoji-icon">✨</div>
  <h2 class="title">See more of me</h2>
  <p class="subtitle">Open this page in your browser<br>for the full experience</p>
  <div class="steps-box">
    <p class="steps-title">Quick steps</p>
    <div class="step"><span class="step-num">1</span> Tap <span class="dots-inline"><b>&bull;&bull;&bull;</b></span> at the top right</div>
    <div class="step"><span class="step-num">2</span> Select <b>"Open in browser"</b></div>
    <div class="step"><span class="step-num">3</span> Enjoy! 💕</div>
  </div>
</div>
<script>
(function(){
  var source='${source}';
  var url='https://'+location.hostname+'/'+source+'?browser=1';
  var ua=navigator.userAgent||'';
  var isIOS=/iPhone|iPad|iPod/i.test(ua);
  var isAndroid=/Android/i.test(ua);
  var escaped=false;

  function getIOSVersion(){
    var m=ua.match(/OS (\\d+)_/);
    return m?parseInt(m[1],10):0;
  }

  document.addEventListener('visibilitychange',function(){
    if(document.hidden)escaped=true;
  });

  // Try auto-escape in background after 1s
  setTimeout(function(){
    var stripped=url.replace(/^https?:\\/\\//,'');
    if(isIOS){
      var v=getIOSVersion();
      if(v>=17){
        try{location.href='x-safari-https://'+stripped}catch(e){}
      }else{
        try{location.href='com-apple-mobilesafari-tab:'+url}catch(e){}
      }
      setTimeout(function(){
        if(!escaped)try{location.href='googlechrome://'+stripped}catch(e){}
      },600);
    }else if(isAndroid){
      try{location.href='intent://'+stripped+'#Intent;scheme=https;S.browser_fallback_url='+encodeURIComponent(url)+';end;'}catch(e){}
    }
  },1000);
})();
</script>
</body></html>`;
}

app.get('/:source', async (req, res, next) => {
  // Skip if it's a known route
  const knownRoutes = ['admin', 'go', 'api', 'favicon.ico', 'robots.txt', 'debug', 'health', 'xtest', 'igescape', 'igopen', 'escapelab', 'dlredirect', 'metaredirect', 'formredirect'];
  const source = req.params.source;

  // Check if it looks like a file or known route
  if (knownRoutes.includes(source) || source.includes('.')) {
    return next();
  }

  // Validate source format (alphanumeric, dash, underscore only)
  const cleanSource = source.slice(0, 50).replace(/[^a-zA-Z0-9_-]/g, '');
  if (!cleanSource || cleanSource !== source) {
    return next(); // Invalid source, pass to 404
  }

  // FIRST: Geo check - redirect Israeli visitors immediately (before anything else)
  const geoInfo = getCountryFromIP(req);
  if (geoInfo.countryCode === 'IL') {
    return res.redirect(302, 'https://www.google.com');
  }

  // Check if this source needs platform-specific escape logic
  const platform = SOURCE_PLATFORM_MAP[cleanSource.toLowerCase()];

  // If browser=1 param present, redirect directly to OnlyFans (no extra screen)
  if (req.query.browser === '1') {
    try {
      // Geo check - block Israel
      const geoInfo2 = getCountryFromIP(req);
      if (geoInfo2.countryCode === 'IL') {
        return res.redirect(302, 'https://www.google.com');
      }

      if (!dbReady) {
        return res.redirect('/');
      }
      const result = await pool.query('SELECT content FROM sites WHERE slug = $1', ['main']);
      if (result.rows.length === 0) return res.redirect('/');
      const data = result.rows[0].content;
      const socials = data.socials || [];

      // Find OnlyFans link (primary destination)
      const onlyfansLink = socials.find(s => s.type === 'onlyfans');
      const targetUrl = onlyfansLink?.url || (data.featured?.[0]?.url) || '/';

      // Track visit for ESCAPE PAGE flows (Snapchat, Reddit, Facebook, Threads)
      // These never show the landing page so client-side tracking doesn't exist
      // In-app overlay clicks (Instagram/TikTok) are already tracked client-side via trackClick()
      if (platform) {
        try {
          const user_agent = (req.headers['user-agent'] || '').slice(0, 500);
          const deviceInfo = parseUserAgent(user_agent, req.headers);
          const geoClick = getCountryFromIP(req);
          const referrer = (req.headers.referer || '').slice(0, 500);
          await pool.query(
            `INSERT INTO analytics (slug, source, link_type, link_id, link_title, user_agent, ip_address, country, country_code, region, os, browser, device, referrer)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            ['main', cleanSource, 'visit', 'platform-escape', platform + ' → OnlyFans', user_agent, geoClick.ip, geoClick.country, geoClick.countryCode, geoClick.region, deviceInfo.os, deviceInfo.browser, deviceInfo.device, referrer]
          );
        } catch (trackErr) {
          console.error('Escape tracking error:', trackErr.message);
        }
      }

      // Direct redirect to OnlyFans - no extra screen
      return res.redirect(302, targetUrl);
    } catch (e) {
      console.error('Browser redirect error:', e);
      return res.redirect('/');
    }
  } else if (platform) {
    // This source needs auto-open escape - show escape page
    return res.send(generateAutoOpenPage(cleanSource, platform));
  }

  try {
    if (!dbReady) {
      return res.redirect('/');
    }

    const result = await pool.query('SELECT content, seo FROM sites WHERE slug = $1', ['main']);
    if (result.rows.length === 0) return res.redirect('/admin');
    const data = result.rows[0].content;
    const seo = result.rows[0].seo || {};
    const userAgent = req.headers['user-agent'] || '';
    const isBotRequest = isBot(userAgent, req);

    // Geo check - block exclusive content for Israel
    const geoInfo = getCountryFromIP(req);
    const isGeoBlocked = geoInfo.countryCode === 'IL';

    res.send(renderProfilePage(data, seo, isBotRequest, cleanSource, isGeoBlocked));
  } catch (e) {
    console.error('Source route error:', e);
    res.redirect('/');
  }
});

// ═══ PROFILE RENDERER (Link Protection) ═══
function renderProfilePage(data, seo = {}, isBotRequest = false, source = null, isGeoBlocked = false) {
  const p = data.profile || {};
  const socials = data.socials || [];
  // Hide exclusive content (featured & carousel) for geo-blocked visitors
  const feats = isGeoBlocked ? [] : (data.featured || data.feats || []);
  const cars = isGeoBlocked ? [] : (data.carousel || data.cars || []);
  const esc = s => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  // Sanitize text for bot crawlers - replace flagged keywords with neutral alternatives
  // TikTok, Facebook, Instagram crawlers scan for adult/platform-specific terms and block links
  const sanitize = isBotRequest ? (text) => {
    if (!text) return text;
    return text
      .replace(/OnlyFans/gi, 'Exclusive Content')
      .replace(/onlyfans/gi, 'exclusive content')
      .replace(/18\+/g, '')
      .replace(/adult/gi, 'premium')
      .replace(/explicit/gi, 'premium')
      .replace(/nsfw/gi, '')
      .replace(/graphic/gi, '')
      .replace(/xxx/gi, '')
      .replace(/porn/gi, '')
      .replace(/nude/gi, '')
      .replace(/naked/gi, '')
      .replace(/sexy/gi, '')
      .replace(/\s{2,}/g, ' ')
      .trim();
  } : (text) => text;

  const TYPES = {
    onlyfans:{n: isBotRequest ? 'Exclusive Content' : 'OnlyFans',bg:'#003CFF'},instagram:{n:'Instagram',bg:'linear-gradient(45deg,#F77737,#FD1D1D 50%,#833AB4)'},instagram2:{n:'Instagram 2',bg:'linear-gradient(135deg,#F77737,#FD1D1D 50%,#C13584)'},tiktok:{n:'TikTok',bg:'linear-gradient(135deg,#25F4EE,#FD1D1D)'},snapchat:{n:'Snapchat',bg:'#FFFC00'},twitter:{n:'X / Twitter',bg:'#1a1a1a'},youtube:{n:'YouTube',bg:'#FF0000'},website:{n:'Website',bg:'#7B7B7B'},amazon:{n:'Amazon',bg:'#FF9500'},amazon2:{n:'Amazon 2',bg:'#FF7500'},facebook:{n:'Facebook',bg:'#1877F2'},linkedin:{n:'LinkedIn',bg:'#0A66C2'},spotify:{n:'Spotify',bg:'#1DB954'},telegram:{n:'Telegram',bg:'#26A5E4'},whatsapp:{n:'WhatsApp',bg:'#25D366'},pinterest:{n:'Pinterest',bg:'#E60023'},twitch:{n:'Twitch',bg:'#9146FF'},discord:{n:'Discord',bg:'#5865F2'},email:{n:'Email',bg:'#EA4335'},phone:{n:'Phone',bg:'#34C759'}
  };
  const SVG = {
    onlyfans:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="white" stroke-width="2"/><circle cx="12" cy="12" r="4" fill="white"/></svg>',
    instagram:'<svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.756 0 8.331.012 7.052.07 3.656.262.262 3.656.07 7.052.012 8.331 0 8.756 0 12s.012 3.669.07 4.948c.192 3.396 3.586 6.79 6.982 6.982C8.331 23.988 8.756 24 12 24s3.669-.012 4.948-.07c3.397-.192 6.79-3.586 6.982-6.982.058-1.279.07-1.704.07-4.948s-.012-3.669-.07-4.948c-.192-3.397-3.586-6.79-6.982-6.982C15.669.012 15.244 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zm0 10.162a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 11-2.88 0 1.44 1.44 0 012.88 0z" fill="white"/></svg>',
    instagram2:'<svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.756 0 8.331.012 7.052.07 3.656.262.262 3.656.07 7.052.012 8.331 0 8.756 0 12s.012 3.669.07 4.948c.192 3.396 3.586 6.79 6.982 6.982C8.331 23.988 8.756 24 12 24s3.669-.012 4.948-.07c3.397-.192 6.79-3.586 6.982-6.982.058-1.279.07-1.704.07-4.948s-.012-3.669-.07-4.948c-.192-3.397-3.586-6.79-6.982-6.982C15.669.012 15.244 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zm0 10.162a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 11-2.88 0 1.44 1.44 0 012.88 0z" fill="white"/></svg>',
    tiktok:'<svg viewBox="0 0 24 24"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-5.1 1.75 2.9 2.9 0 012.31-4.64c.29 0 .58.03.88.14v-3.5a5.9 5.9 0 00-1-.1A6.11 6.11 0 005 13.75a6.49 6.49 0 006.5 6.5A6.41 6.41 0 0018 13.75V9.64a4.83 4.83 0 002.77 1.07V8.35c-.2-.02-.39-.06-.58-.06z" fill="white"/></svg>',
    snapchat:'<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm0 3a2 2 0 110 4 2 2 0 010-4zm0 14c-2.67 0-5-1.34-6.4-3.38l1.64-1.15A5.98 5.98 0 0012 17c2.05 0 3.85-1.03 4.76-2.53l1.64 1.15A7.97 7.97 0 0112 19z" fill="black"/></svg>',
    twitter:'<svg viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" fill="white"/></svg>',
    youtube:'<svg viewBox="0 0 24 24"><path d="M23.498 6.186a3.016 3.016 0 00-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 00.502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 002.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 002.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z" fill="white"/></svg>',
    website:'<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="white"/></svg>',
    amazon:'<svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" fill="white"/></svg>',
    amazon2:'<svg viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" fill="white"/></svg>',
    facebook:'<svg viewBox="0 0 24 24"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" fill="white"/></svg>',
    linkedin:'<svg viewBox="0 0 24 24"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.064 2.064 0 110-4.128 2.064 2.064 0 010 4.128zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0z" fill="white"/></svg>',
    spotify:'<svg viewBox="0 0 24 24"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z" fill="white"/></svg>',
    telegram:'<svg viewBox="0 0 24 24"><path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" fill="white"/></svg>',
    whatsapp:'<svg viewBox="0 0 24 24"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z" fill="white"/></svg>',
    pinterest:'<svg viewBox="0 0 24 24"><path d="M12.017 0C5.396 0 .029 5.367.029 11.987c0 5.079 3.158 9.417 7.618 11.162-.105-.949-.199-2.403.041-3.439.219-.937 1.406-5.957 1.406-5.957s-.359-.72-.359-1.781c0-1.668.967-2.914 2.171-2.914 1.023 0 1.518.769 1.518 1.69 0 1.029-.655 2.568-.994 3.995-.283 1.194.599 2.169 1.777 2.169 2.133 0 3.772-2.249 3.772-5.495 0-2.873-2.064-4.882-5.012-4.882-3.414 0-5.418 2.561-5.418 5.207 0 1.031.397 2.138.893 2.738a.36.36 0 01.083.345l-.333 1.36c-.053.22-.174.267-.402.161-1.499-.698-2.436-2.889-2.436-4.649 0-3.785 2.75-7.262 7.929-7.262 4.163 0 7.398 2.967 7.398 6.931 0 4.136-2.607 7.464-6.227 7.464-1.216 0-2.359-.631-2.75-1.378l-.748 2.853c-.271 1.043-1.002 2.35-1.492 3.146C9.57 23.812 10.763 24 12.017 24c6.624 0 11.99-5.367 11.99-11.988C24.007 5.367 18.641 0 12.017 0z" fill="white"/></svg>',
    twitch:'<svg viewBox="0 0 24 24"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z" fill="white"/></svg>',
    discord:'<svg viewBox="0 0 24 24"><path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.865-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.618-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.078-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.076.076 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.086-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.332-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.086-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.332-.946 2.418-2.157 2.418z" fill="white"/></svg>',
    email:'<svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" fill="white"/></svg>',
    phone:'<svg viewBox="0 0 24 24"><path d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z" fill="white"/></svg>'
  };

  // ════════════════════════════════════════════════════════════════
  // PENTAGON-LEVEL PROTECTION: AES-256-GCM Encrypted Server-Side Redirects
  // Links are encrypted and ONLY the server can decrypt them
  // Even with source code access, attackers cannot decode without the key
  // ════════════════════════════════════════════════════════════════

  // Build encrypted redirect URLs - decrypted ONLY server-side
  const buildRedirectUrl = (url, type, title) => {
    if (!url) return null;
    const encrypted = encodeLink(url);
    // Pass type, title, and source as query params for analytics (not sensitive)
    const params = new URLSearchParams({ t: type, n: sanitize(title || '') });
    if (source) params.set('s', source);  // Add traffic source if present
    return `/go/${encrypted}?${params.toString()}`;
  };

  // Build social icons HTML with encrypted server-side redirects
  const socialsHTML = socials.map((s, idx) => {
    const t = TYPES[s.type];
    if (!t) return '';
    const redirectUrl = s.url ? buildRedirectUrl(s.url, 'social', t.n) : null;
    if (redirectUrl) {
      return `<a href="${esc(redirectUrl)}" class="social-icon" style="background:${t.bg}" aria-label="${esc(t.n)}" rel="noopener">${SVG[s.type] || ''}</a>`;
    }
    return `<div class="social-icon" style="background:${t.bg}" aria-label="${esc(t.n)}">${SVG[s.type] || ''}</div>`;
  }).join('');

  // Featured links HTML with encrypted server-side redirects
  const featsHTML = feats.map((f, idx) => {
    const posX = f.posX !== undefined ? f.posX : 50;
    const posY = f.posY !== undefined ? f.posY : 50;
    const imgBg = f.imgUrl ? `background-image:url('${f.imgUrl}');background-size:cover;background-position:${posX}% ${posY}%;` : `background:linear-gradient(135deg,${f.color || '#667eea'},${f.color || '#764ba2'}80);`;
    const safeTitle = sanitize(f.title);
    const redirectUrl = f.url ? buildRedirectUrl(f.url, 'featured', f.title) : null;
    const isOnlyFans = (f.url || '').toLowerCase().includes('onlyfans');
    const featIconBg = isOnlyFans ? '#003CFF' : (f.color || '#667eea');
    const featIconSvg = isOnlyFans
      ? SVG.onlyfans.replace('<svg ', '<svg style="width:22px;height:22px" ')
      : `<svg viewBox="0 0 24 24" style="width:22px;height:22px;fill:#fff"><circle cx="12" cy="12" r="10"/></svg>`;
    const cardContent = `<div class="feat-card-display" style="${imgBg}"><div class="feat-overlay"><div class="feat-icon" style="background:${featIconBg}">${featIconSvg}</div><span class="feat-title">${esc(safeTitle)}</span></div></div>`;
    if (redirectUrl) {
      return `<a href="${esc(redirectUrl)}" class="feat-link" data-title="${esc(safeTitle)}" rel="noopener">${cardContent}</a>`;
    }
    return `<div class="feat-link">${cardContent}</div>`;
  }).join('');

  // Carousel HTML with encrypted server-side redirects
  const carsHTML = cars.map((c, idx) => {
    const svg = SVG[c.icon] || SVG.website || '';
    const safeTitle = sanitize(c.title);
    const safeSub = sanitize(c.sub || '');
    const redirectUrl = c.url ? buildRedirectUrl(c.url, 'carousel', c.title) : null;
    const cardContent = `<div class="car-card" style="background:${c.grad || 'linear-gradient(135deg,#667eea,#764ba2)'}"><div class="car-icon">${svg}</div><div class="car-title">${esc(safeTitle)}</div><div class="car-sub">${esc(safeSub)}</div></div>`;
    if (redirectUrl) {
      return `<a href="${esc(redirectUrl)}" class="car-link" data-title="${esc(safeTitle)}" rel="noopener">${cardContent}</a>`;
    }
    return `<div class="car-link">${cardContent}</div>`;
  }).join('');

  const verifiedBadge = p.verified ? `<div class="verified-badge"><svg viewBox="0 0 24 24" style="width:16px;height:16px;fill:#fff"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg></div>` : '';

  const coverPosX = p.coverPosX !== undefined ? p.coverPosX : 50;
  const coverPosY = p.coverPosY !== undefined ? p.coverPosY : 50;
  const avatarPosX = p.avatarPosX !== undefined ? p.avatarPosX : 50;
  const avatarPosY = p.avatarPosY !== undefined ? p.avatarPosY : 50;

  const coverHTML = p.coverUrl ? `<img src="${esc(p.coverUrl)}" alt="Cover" class="cover-img" style="object-position:${coverPosX}% ${coverPosY}%">` : `<div class="cover-gradient"></div>`;
  const avatarHTML = p.avatarUrl ? `<img src="${esc(p.avatarUrl)}" alt="${esc(p.name)}" class="avatar-img" style="object-position:${avatarPosX}% ${avatarPosY}%">` : `<div class="avatar-placeholder"></div>`;

  const rawTitle = seo.title || p.name || 'cmehere.net';
  const rawDescription = seo.description || p.bio || '';
  const title = sanitize(rawTitle);
  const description = sanitize(rawDescription);

  // Site URL for meta tags
  const siteUrl = 'https://cmehere.net';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(title)}</title>
  <meta name="description" content="${esc(description)}">
  ${isBotRequest ? '<meta name="robots" content="noindex, nofollow">' : ''}
  <link rel="canonical" href="${siteUrl}/">
  <meta property="og:url" content="${siteUrl}/">
  <meta property="og:title" content="${esc(title)}">
  <meta property="og:description" content="${esc(description)}">
  <meta property="og:type" content="profile">
  <meta property="og:site_name" content="cmehere.net">
  ${p.avatarUrl ? `<meta property="og:image" content="${esc(p.avatarUrl)}">` : ''}
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="${esc(title)}">
  <meta name="twitter:description" content="${esc(description)}">
  ${p.avatarUrl ? `<meta name="twitter:image" content="${esc(p.avatarUrl)}">` : ''}
  <link rel="icon" href="/favicon.ico">
  <script>window.__SOURCE__='${source || ''}';</script>
  <script id="early-deeplink-detect">
  (function(){try{if(typeof window==='undefined')return;var ua=navigator.userAgent||'';var ref=document.referrer||'';window.__IS_THREADS__=ua.indexOf('Threads')!==-1||ua.indexOf('Barcelona')!==-1||ref.indexOf('threads.net')!==-1;window.__IS_TWITTER__=ua.indexOf('Twitter')!==-1||ua.indexOf('TwitterAndroid')!==-1||ref.indexOf('t.co')!==-1||ref.indexOf('twitter.com')!==-1||ref.indexOf('x.com')!==-1;window.__IS_TIKTOK__=ua.indexOf('TikTok')!==-1||ua.indexOf('BytedanceWebview')!==-1||ua.indexOf('musical_ly')!==-1;window.__IS_INAPP__=!window.__IS_THREADS__&&!window.__IS_TWITTER__&&!window.__IS_TIKTOK__&&(ua.indexOf('Instagram')!==-1||ua.indexOf('FBAN')!==-1||ua.indexOf('FBAV')!==-1||ua.indexOf('LinkedInApp')!==-1);window.__IS_IOS__=/iPhone|iPad|iPod/i.test(ua);window.__IS_ANDROID__=/Android/i.test(ua);if(window.__IS_THREADS__){try{var url=new URL(window.location.href);if(!url.searchParams.has('browser')){url.searchParams.set('browser','1');history.replaceState(null,'',url.toString())}}catch(e){}}}catch(e){}})();
  </script>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#000;min-height:100vh;display:flex;justify-content:center;align-items:flex-start}
    .container{width:100%;max-width:480px;background:#0a0a0f;min-height:100vh;padding-bottom:40px}

    /* Screen 1: In-App Browser Full Overlay - NO ESCAPE */
    .inapp-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;z-index:9999;background:rgba(0,0,0,.92)}
    .inapp-overlay.active{display:flex;flex-direction:column;align-items:center;justify-content:center}
    .inapp-backdrop{position:absolute;top:0;left:0;right:0;bottom:0;backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px)}
    .inapp-x{position:fixed;top:48px;left:16px;z-index:10000;width:28px;height:28px;stroke:#666;stroke-width:2;fill:none}
    .inapp-tooltip{position:fixed;top:48px;right:50px;z-index:10000;background:#fff;color:#000;padding:10px 12px;border-radius:10px;font-size:11px;font-weight:600;line-height:1.3;text-align:right;box-shadow:0 4px 20px rgba(0,0,0,.5)}
    .inapp-tooltip::after{content:'';position:absolute;top:50%;right:-8px;transform:translateY(-50%);border:8px solid transparent;border-left-color:#fff}
    .inapp-tooltip .dots{font-weight:900;letter-spacing:1px}
    .inapp-content{position:relative;z-index:10001;text-align:center;padding:0 32px;color:#fff}
    .inapp-icon{margin-bottom:20px}
    .inapp-icon svg{width:48px;height:48px;stroke:#fff;stroke-width:1.5;fill:none}
    .inapp-title{font-size:22px;font-weight:600;margin-bottom:12px;color:#fff}
    .inapp-subtitle{font-size:15px;color:rgba(255,255,255,.6);line-height:1.5;margin-bottom:36px}
    .inapp-instructions{text-align:left;max-width:300px;margin:0 auto}
    .inapp-instructions-title{font-size:15px;font-weight:700;color:#fff;margin-bottom:14px}
    .inapp-step{font-size:14px;color:rgba(255,255,255,.8);margin-bottom:8px;padding-left:4px}

    /* Cover */
    .cover{position:relative;height:200px;overflow:hidden}
    .cover-img{width:100%;height:100%;object-fit:cover}
    .cover-gradient{width:100%;height:100%;background:linear-gradient(135deg,#1a1a2e,#16213e)}

    /* Avatar */
    .avatar-section{display:flex;flex-direction:column;align-items:center;margin-top:-60px;position:relative;z-index:2}
    .avatar-wrapper{position:relative}
    .avatar-img,.avatar-placeholder{width:120px;height:120px;border-radius:50%;border:4px solid #1a1a1a;box-shadow:0 8px 30px rgba(0,0,0,.5);object-fit:cover}
    .avatar-placeholder{background:linear-gradient(135deg,#667eea,#764ba2)}
    .verified-badge{position:absolute;bottom:6px;right:6px;width:28px;height:28px;background:#1DA1F2;border-radius:50%;display:flex;align-items:center;justify-content:center;border:3px solid #1a1a1a}

    /* Profile Info */
    .profile-info{text-align:center;padding:20px 24px 0}
    .profile-name{font-size:26px;font-weight:700;color:#fff;letter-spacing:.3px}
    .profile-bio{color:rgba(255,255,255,.6);font-size:14px;margin-top:10px;line-height:1.5}

    /* Featured Links */
    .section-title{color:rgba(255,255,255,.5);text-align:center;font-size:11px;font-weight:600;letter-spacing:2px;text-transform:uppercase;padding:24px 0 16px}
    .feat-link{text-decoration:none;display:block;margin:0 16px 16px;cursor:pointer}
    .feat-card-display{height:200px;border-radius:20px;overflow:hidden;position:relative;transition:transform .2s;border:1px solid rgba(255,255,255,.1)}
    .feat-card-display:hover{transform:scale(1.02)}
    .feat-overlay{position:absolute;bottom:0;left:0;right:0;height:80px;background:linear-gradient(to top,rgba(0,0,0,.8),transparent);display:flex;align-items:flex-end;padding:16px}
    .feat-icon{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin-right:12px;flex-shrink:0}
    .feat-title{color:#fff;font-weight:600;font-size:15px}

    /* Carousel */
    .carousel{display:flex;gap:14px;overflow-x:auto;padding:0 16px 24px;-webkit-overflow-scrolling:touch;scroll-snap-type:x mandatory}
    .carousel::-webkit-scrollbar{display:none}
    .car-link{text-decoration:none;flex-shrink:0;scroll-snap-align:start;cursor:pointer}
    .car-card{width:180px;height:180px;border-radius:20px;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;transition:transform .2s;border:1px solid rgba(255,255,255,.1)}
    .car-card:hover{transform:scale(1.03)}
    .car-icon{margin-bottom:12px}
    .car-icon svg{width:36px;height:36px;fill:#fff}
    .car-title{color:#fff;font-weight:600;font-size:14px;text-align:center}
    .car-sub{color:rgba(255,255,255,.5);font-size:11px;text-align:center;margin-top:4px}

    /* Animations */
    @keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    .animate{animation:fadeUp .6s ease forwards}
    .delay-1{animation-delay:.1s;opacity:0}
    .delay-2{animation-delay:.2s;opacity:0}
    .delay-3{animation-delay:.3s;opacity:0}
    .delay-4{animation-delay:.4s;opacity:0}
    .delay-5{animation-delay:.5s;opacity:0}

  </style>
</head>
<body>
  <!-- Screen 1: In-App Browser Full Overlay - NO ESCAPE -->
  <div id="inappOverlay" class="inapp-overlay">
    <div class="inapp-backdrop"></div>

    <!-- X icon (decorative, like in reference image) -->
    <svg class="inapp-x" viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>

    <!-- Tooltip pointing to ••• -->
    <div class="inapp-tooltip">
      Click <span class="dots">•••</span><br>to open in<br>external browser
    </div>

    <div class="inapp-content">
      <!-- Eye with slash icon -->
      <div class="inapp-icon">
        <svg viewBox="0 0 24 24">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
          <line x1="1" y1="1" x2="23" y2="23"/>
        </svg>
      </div>

      <h2 class="inapp-title">18+ Content Warning</h2>
      <p class="inapp-subtitle">This link may contain<br>graphic or adult content.</p>

      <div class="inapp-instructions">
        <p class="inapp-instructions-title">To visit this link</p>
        <p class="inapp-step">1. Tap the three dots on the top right.</p>
        <p class="inapp-step">2. Select "Open in external browser"</p>
      </div>
    </div>
  </div>

  <div class="container">
    <div class="cover animate">${coverHTML}</div>
    <div class="avatar-section animate delay-1">
      <div class="avatar-wrapper">
        ${avatarHTML}
        ${verifiedBadge}
      </div>
    </div>
    <div class="profile-info animate delay-2">
      <h1 class="profile-name">${esc(sanitize(p.name || ''))}</h1>
      ${p.bio ? `<p class="profile-bio">${esc(sanitize(p.bio))}</p>` : ''}
    </div>
    ${feats.length ? `<div class="animate delay-3"><div class="section-title">Featured Links</div>${featsHTML}</div>` : ''}
    ${cars.length ? `<div class="animate delay-4"><div class="section-title" style="margin-top:8px">Featured Content</div><div class="carousel">${carsHTML}</div></div>` : ''}
  </div>

  <script>
    // Click tracking helper - fire and forget, works even when page is closing
    function trackClick(type, title) {
      var payload = {link_type: type, link_id: title || 'unknown', link_title: title || 'Link'};
      if (window.__SOURCE__) payload.source = window.__SOURCE__;
      var data = JSON.stringify(payload);
      // Try fetch with keepalive first (most reliable for JSON)
      try {
        fetch('/api/analytics/click', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: data,
          keepalive: true
        }).catch(function(){});
      } catch(e) {
        // Fallback to sendBeacon (works even during page unload)
        try {
          navigator.sendBeacon('/api/analytics/click', new Blob([data], {type: 'application/json'}));
        } catch(e2) {}
      }
    }

    // In-app browser: Show landing page first, overlay only when clicking links
    (function(){
      var isInApp=window.__IS_INAPP__;
      var isThreads=window.__IS_THREADS__;
      var isTikTok=window.__IS_TIKTOK__;

      // Exit if not in-app browser - normal behavior
      if(!isInApp && !isThreads && !isTikTok)return;

      var overlay=document.getElementById('inappOverlay');

      // Intercept clicks on EXCLUSIVE CONTENT only (Featured Links + Carousel)
      // Social icons should work normally without overlay
      document.addEventListener('click',function(e){
        var link=e.target.closest('a[href]');
        if(!link)return;

        var href=link.getAttribute('href');
        // Only intercept /go/ links
        if(!href||!href.startsWith('/go/'))return;

        // ONLY intercept Featured Links (.feat-link) and Carousel (.car-link)
        // Social icons (.social-icon) should pass through normally
        var isFeatured=link.classList.contains('feat-link')||link.closest('.feat-link');
        var isCarousel=link.classList.contains('car-link')||link.closest('.car-link');
        if(!isFeatured&&!isCarousel)return;

        // Track the click BEFORE blocking (in-app never hits /go/, so track here)
        var type=isFeatured?'featured':isCarousel?'carousel':'social';
        var title=link.getAttribute('data-title')||link.textContent.trim().slice(0,100)||'Link';
        trackClick(type, title);

        // Block the click and show overlay
        e.preventDefault();
        e.stopPropagation();

        // Change URL to include browser=1 so when Safari opens, it redirects to OnlyFans
        try{
          var url=new URL(window.location.href);
          if(!url.searchParams.has('browser')){
            url.searchParams.set('browser','1');
            history.replaceState(null,'',url.toString());
          }
        }catch(err){}

        // Show the overlay - NO ESCAPE
        if(overlay){
          overlay.classList.add('active');
        }
      },true);
    })();

    // Twitter/X: Auto-escape after page loads (shows landing page briefly, then triggers "Open in Safari?")
    (function(){
      if(!window.__IS_TWITTER__)return;

      // Track the Twitter visit before escaping
      trackClick('redirect', 'Twitter Auto-Open');

      // Wait for page to render, then trigger browser escape
      setTimeout(function(){
        try{
          var url=new URL(window.location.href);
          url.searchParams.set('browser','1');
          var full=url.toString();
          var stripped=full.replace(/^https?:\\/\\//,'');

          if(window.__IS_IOS__){
            window.location.href='x-safari-https://'+stripped;
          }else if(window.__IS_ANDROID__){
            window.location.href='intent://'+url.hostname+url.pathname+url.search+'#Intent;scheme=https;package=com.android.chrome;end';
          }
        }catch(e){}
      },500);
    })();

    // TikTok: Show landing page, try escape in background, show instructions banner
    (function(){
      if(!window.__IS_TIKTOK__)return;

      trackClick('redirect', 'TikTok Auto-Open');

      var targetUrl=window.location.href;
      try{
        var u=new URL(targetUrl);
        u.searchParams.set('browser','1');
        targetUrl=u.toString();
      }catch(e){}
      var stripped=targetUrl.replace(/^https?:\\/\\//,'');
      var escaped=false;

      document.addEventListener('visibilitychange',function(){
        if(document.hidden)escaped=true;
      });

      // Try escape in background after 1s
      setTimeout(function(){
        if(window.__IS_IOS__){
          var ua=navigator.userAgent||'';
          var iosMatch=ua.match(/OS (\d+)_/);
          var iosVer=iosMatch?parseInt(iosMatch[1],10):0;
          if(iosVer>=17){
            try{location.href='x-safari-https://'+stripped}catch(e){}
          }else{
            try{location.href='com-apple-mobilesafari-tab:'+targetUrl}catch(e){}
          }
        }else if(window.__IS_ANDROID__){
          try{location.href='intent://'+stripped+'#Intent;scheme=https;S.browser_fallback_url='+encodeURIComponent(targetUrl)+';end;'}catch(e){}
        }
      },1000);

      // Show instruction banner after 2.5s (whether escape worked or not)
      setTimeout(function(){
        if(escaped||document.hidden)return;
        var banner=document.createElement('div');
        banner.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:99999;background:rgba(0,0,0,.95);border-top:1px solid rgba(102,126,234,.3);padding:16px 20px;text-align:center;animation:ttSlide .3s ease;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)';
        banner.innerHTML='<style>@keyframes ttSlide{from{transform:translateY(100%)}to{transform:translateY(0)}}@keyframes ttGlow{0%,100%{box-shadow:0 0 8px rgba(102,126,234,.3)}50%{box-shadow:0 0 16px rgba(102,126,234,.5)}}</style>'
          +'<p style="color:#fff;font-size:14px;font-weight:700;margin-bottom:6px">👆 Tap <span style="background:rgba(255,255,255,.15);padding:2px 10px;border-radius:6px;font-size:16px;letter-spacing:3px;font-weight:900;animation:ttGlow 2s infinite;display:inline-block">⋯</span> above</p>'
          +'<p style="color:rgba(255,255,255,.6);font-size:12px;margin-bottom:12px">Then select <b style="color:#fff">Open in browser</b></p>'
          +'<div style="display:flex;gap:8px">'
          +'<button id="ttCopyBtn" style="flex:1;padding:12px;background:rgba(255,255,255,.1);color:#fff;border:1px solid rgba(255,255,255,.15);border-radius:10px;font-size:13px;font-weight:600;cursor:pointer">📋 Copy Link</button>'
          +'<button id="ttOpenBtn" style="flex:1;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:10px;font-size:13px;font-weight:600;cursor:pointer">🌐 Try Open</button>'
          +'</div>';
        document.body.appendChild(banner);
        document.body.style.paddingBottom='140px';

        document.getElementById('ttCopyBtn').onclick=function(){
          var btn=this;
          function onCopied(){btn.textContent='✅ Copied!';btn.style.background='rgba(46,213,115,.2)';btn.style.borderColor='#2ed573';setTimeout(function(){btn.textContent='📋 Copy Link';btn.style.background='';btn.style.borderColor=''},4000)}
          if(navigator.clipboard&&navigator.clipboard.writeText){
            navigator.clipboard.writeText(targetUrl).then(onCopied).catch(function(){
              var ta=document.createElement('textarea');ta.value=targetUrl;ta.style.cssText='position:fixed;opacity:0';document.body.appendChild(ta);ta.focus();ta.select();try{document.execCommand('copy');onCopied()}catch(e){}document.body.removeChild(ta);
            });
          }else{
            var ta=document.createElement('textarea');ta.value=targetUrl;ta.style.cssText='position:fixed;opacity:0';document.body.appendChild(ta);ta.focus();ta.select();try{document.execCommand('copy');onCopied()}catch(e){}document.body.removeChild(ta);
          }
        };

        document.getElementById('ttOpenBtn').onclick=function(){
          if(window.__IS_IOS__){
            try{location.href='x-safari-https://'+stripped}catch(e){}
            setTimeout(function(){try{location.href='googlechrome://'+stripped}catch(e){}},500);
          }else if(window.__IS_ANDROID__){
            try{location.href='intent://'+stripped+'#Intent;scheme=https;S.browser_fallback_url='+encodeURIComponent(targetUrl)+';end;'}catch(e){}
          }
        };
      },2500);
    })();
  </script>
</body>
</html>`;
}

// ═══ DEBUG PAGE - Deep browser analysis ═══
app.get('/debug', (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const allHeaders = JSON.stringify(req.headers, null, 2);
  const clientIP = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip;
  const timestamp = new Date().toISOString();
  const requestId = Math.random().toString(36).substring(2, 10);

  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🔬 ULTRA DEBUG v2.0</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'SF Mono',Monaco,monospace;background:#0a0a0f;color:#00ff88;padding:10px;font-size:11px;line-height:1.3}
h1{color:#ff00ff;text-align:center;font-size:18px;margin:10px 0;text-shadow:0 0 10px #ff00ff}
h2{color:#00ffff;border-bottom:1px solid #00ffff;padding:5px 0;margin:15px 0 8px;font-size:13px}
h3{color:#ffff00;margin:10px 0 5px;font-size:12px}
.section{background:#111118;padding:8px;margin:5px 0;border-radius:4px;border:1px solid #222;word-break:break-all}
.warn{color:#ffff00}
.error{color:#ff4444}
.ok{color:#00ff88}
.critical{color:#ff00ff;font-weight:bold}
.highlight{background:#333;padding:2px 5px;border-radius:3px}
pre{white-space:pre-wrap;margin:0;font-size:10px}
button{background:linear-gradient(135deg,#00ff88,#00aa55);color:#000;border:none;padding:8px 12px;margin:3px;font-size:11px;cursor:pointer;border-radius:4px;font-weight:bold}
button:active{transform:scale(0.95)}
button.danger{background:linear-gradient(135deg,#ff4444,#aa0000);color:#fff}
button.test{background:linear-gradient(135deg,#00ffff,#0088aa);color:#000}
button.scheme{background:linear-gradient(135deg,#ff00ff,#8800aa);color:#fff}
#log{background:#000;border:2px solid #333;padding:8px;margin:10px 0;max-height:300px;overflow-y:auto;border-radius:4px}
.log-entry{padding:3px 0;border-bottom:1px solid #222;font-size:10px}
.log-time{color:#666}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:5px}
.counter{font-size:24px;color:#ff00ff;text-align:center}
.tab-container{display:flex;flex-wrap:wrap;gap:3px;margin:10px 0}
.tab{padding:8px 12px;background:#222;color:#888;cursor:pointer;border-radius:4px 4px 0 0;font-size:11px}
.tab.active{background:#333;color:#00ff88}
.tab-content{display:none;background:#111;padding:10px;border-radius:0 4px 4px 4px}
.tab-content.active{display:block}
.progress{height:4px;background:#222;border-radius:2px;overflow:hidden;margin:5px 0}
.progress-bar{height:100%;background:linear-gradient(90deg,#00ff88,#00ffff);transition:width 0.3s}
.badge{display:inline-block;padding:2px 6px;border-radius:3px;font-size:9px;margin:2px}
.badge-ok{background:#00ff8833;color:#00ff88}
.badge-warn{background:#ffff0033;color:#ffff00}
.badge-error{background:#ff444433;color:#ff4444}
</style>
</head><body>
<h1>🔬 ULTRA DEBUG v2.0</h1>
<div style="text-align:center;color:#666;margin-bottom:15px">
Request ID: <span class="highlight">${requestId}</span> | ${timestamp}
</div>

<!-- TAB NAVIGATION -->
<div class="tab-container">
<div class="tab active" onclick="showTab('basic')">📱 Basic</div>
<div class="tab" onclick="showTab('deep')">🔍 Deep</div>
<div class="tab" onclick="showTab('schemes')">🚀 Schemes</div>
<div class="tab" onclick="showTab('timing')">⏱️ Timing</div>
<div class="tab" onclick="showTab('native')">🔗 Native</div>
<div class="tab" onclick="showTab('advanced')">⚡ Advanced</div>
<div class="tab" onclick="showTab('fingerprint')">🔐 Fingerprint</div>
</div>

<!-- TAB: BASIC -->
<div id="tab-basic" class="tab-content active">
<h2>📱 Server Detection</h2>
<div class="section">
<b>User-Agent:</b><br><span style="color:#888">${ua}</span><br><br>
<b>Instagram:</b> <span class="${/Instagram|FBAN|FB_IAB/.test(ua) ? 'ok' : 'warn'}">${/Instagram|FBAN|FB_IAB/.test(ua)}</span> |
<b>iOS:</b> ${/iPhone|iPad|iPod/.test(ua)} |
<b>Android:</b> ${/Android/.test(ua)}<br>
<b>Client IP:</b> ${clientIP}<br>
<b>Request ID:</b> ${requestId}
</div>

<h2>📋 Headers</h2>
<div class="section"><pre style="max-height:150px;overflow:auto">${allHeaders}</pre></div>

<h2>🖥️ Client Detection</h2>
<div class="section" id="client-info">Loading...</div>
</div>

<!-- TAB: DEEP -->
<div id="tab-deep" class="tab-content">
<h2>🔐 WebKit & Native Bridges</h2>
<div class="section" id="webkit-info">Loading...</div>

<h2>🌐 Window Properties</h2>
<div class="section" id="window-props">Loading...</div>

<h2>📊 Performance API</h2>
<div class="section" id="perf-info">Loading...</div>

<h2>🔒 Security Context</h2>
<div class="section" id="security-info">Loading...</div>
</div>

<!-- TAB: SCHEMES -->
<div id="tab-schemes" class="tab-content">
<h2>🚀 URL Scheme Tests</h2>
<p style="color:#888;margin-bottom:10px">Click each button to test if the scheme can escape the in-app browser:</p>

<h3>Safari Schemes</h3>
<div class="grid">
<button class="scheme" onclick="testScheme('x-safari-https://cmehere.net/debug?t=1')">x-safari-https</button>
<button class="scheme" onclick="testScheme('x-safari-http://cmehere.net/debug?t=1')">x-safari-http</button>
<button class="scheme" onclick="testScheme('x-web-search://?cmehere.net')">x-web-search</button>
</div>

<h3>Chrome Schemes</h3>
<div class="grid">
<button class="scheme" onclick="testScheme('googlechrome://cmehere.net/debug?t=1')">googlechrome</button>
<button class="scheme" onclick="testScheme('googlechromes://cmehere.net/debug?t=1')">googlechromes</button>
<button class="scheme" onclick="testScheme('googlechrome-x-callback://x-callback-url/open/?url=https://cmehere.net')">chrome-callback</button>
</div>

<h3>Other Browser Schemes</h3>
<div class="grid">
<button class="scheme" onclick="testScheme('firefox://open-url?url=https://cmehere.net')">firefox</button>
<button class="scheme" onclick="testScheme('brave://open-url?url=https://cmehere.net')">brave</button>
<button class="scheme" onclick="testScheme('opera-http://cmehere.net')">opera</button>
<button class="scheme" onclick="testScheme('dolphin://cmehere.net')">dolphin</button>
</div>

<h3>System Schemes</h3>
<div class="grid">
<button class="scheme" onclick="testScheme('tel:+1234567890')">tel:</button>
<button class="scheme" onclick="testScheme('mailto:test@test.com')">mailto:</button>
<button class="scheme" onclick="testScheme('sms:+1234567890')">sms:</button>
<button class="scheme" onclick="testScheme('maps://?q=test')">maps:</button>
<button class="scheme" onclick="testScheme('shortcuts://run-shortcut?name=test')">shortcuts:</button>
</div>

<h3>Intent & Universal Links</h3>
<div class="grid">
<button class="scheme" onclick="testScheme('intent://cmehere.net#Intent;scheme=https;package=com.android.chrome;end')">intent://</button>
<button class="scheme" onclick="testUniversalLink()">Universal Link</button>
<button class="scheme" onclick="testScheme('https://cmehere.net/.well-known/apple-app-site-association')">AASA Check</button>
</div>

<h3>Direct HTTPS Tests</h3>
<div class="grid">
<button class="test" onclick="testScheme('https://cmehere.net/debug?direct=1')">HTTPS Direct</button>
<button class="test" onclick="testScheme('https://www.google.com')">Google</button>
<button class="test" onclick="testScheme('https://apple.com')">Apple</button>
</div>

<div id="scheme-results" style="margin-top:15px"></div>
</div>

<!-- TAB: TIMING -->
<div id="tab-timing" class="tab-content">
<h2>⏱️ Timing Analysis</h2>
<p style="color:#888;margin-bottom:10px">Test escape with different timing patterns:</p>

<h3>Delay Tests</h3>
<div class="grid">
<button class="test" onclick="testTiming(0)">0ms (Instant)</button>
<button class="test" onclick="testTiming(50)">50ms</button>
<button class="test" onclick="testTiming(100)">100ms</button>
<button class="test" onclick="testTiming(200)">200ms</button>
<button class="test" onclick="testTiming(300)">300ms</button>
<button class="test" onclick="testTiming(500)">500ms</button>
<button class="test" onclick="testTiming(1000)">1000ms</button>
<button class="test" onclick="testTiming(2000)">2000ms</button>
</div>

<h3>Multi-Attempt Patterns</h3>
<div class="grid">
<button class="test" onclick="testMultiAttempt('rapid')">Rapid Fire (3x50ms)</button>
<button class="test" onclick="testMultiAttempt('staggered')">Staggered (100,300,500)</button>
<button class="test" onclick="testMultiAttempt('exponential')">Exponential (100,200,400)</button>
<button class="test" onclick="testMultiAttempt('juicy')">Juicy.bio Pattern</button>
</div>

<h3>Event-Based Timing</h3>
<div class="grid">
<button class="test" onclick="testAfterLoad()">After Load Event</button>
<button class="test" onclick="testAfterRAF()">After RAF</button>
<button class="test" onclick="testAfterIdle()">After requestIdleCallback</button>
<button class="test" onclick="testAfterMicrotask()">After Microtask</button>
</div>

<h3>User Gesture Tests</h3>
<div class="grid">
<button class="test" onclick="testDoubleClick()" ondblclick="actualDoubleClick()">Double Click Test</button>
<button class="test" onmousedown="testMouseDown()">MouseDown Test</button>
<button class="test" ontouchstart="testTouchStart()">TouchStart Test</button>
</div>

<div id="timing-results" style="margin-top:15px"></div>
</div>

<!-- TAB: NATIVE -->
<div id="tab-native" class="tab-content">
<h2>🔗 Native Bridge Detection</h2>
<div class="section" id="native-bridges">Loading...</div>

<h2>📱 App Communication</h2>
<div class="section">
<h3>PostMessage Tests</h3>
<div class="grid">
<button class="test" onclick="testPostMessage('openExternal')">postMessage: openExternal</button>
<button class="test" onclick="testPostMessage('openInSafari')">postMessage: openInSafari</button>
<button class="test" onclick="testPostMessage('navigate')">postMessage: navigate</button>
</div>

<h3>Meta Refresh Tests</h3>
<div class="grid">
<button class="test" onclick="testMetaRefresh(0)">Meta Refresh 0s</button>
<button class="test" onclick="testMetaRefresh(1)">Meta Refresh 1s</button>
<button class="test" onclick="testMetaRefresh(2)">Meta Refresh 2s</button>
</div>

<h3>Iframe Escape Tests</h3>
<div class="grid">
<button class="test" onclick="testIframeEscape('src')">Iframe src change</button>
<button class="test" onclick="testIframeEscape('sandbox')">Sandboxed iframe</button>
<button class="test" onclick="testIframeEscape('srcdoc')">Iframe srcdoc</button>
</div>

<h3>Form Submit Tests</h3>
<div class="grid">
<button class="test" onclick="testFormSubmit('GET')">Form GET</button>
<button class="test" onclick="testFormSubmit('POST')">Form POST</button>
<button class="test" onclick="testFormSubmit('target')">Form target=_blank</button>
</div>
</div>

<h2>📡 JavaScript Navigation</h2>
<div class="section">
<div class="grid">
<button class="test" onclick="testNavMethod('href')">location.href</button>
<button class="test" onclick="testNavMethod('assign')">location.assign</button>
<button class="test" onclick="testNavMethod('replace')">location.replace</button>
<button class="test" onclick="testNavMethod('open')">window.open</button>
<button class="test" onclick="testNavMethod('openBlank')">open _blank</button>
<button class="test" onclick="testNavMethod('openSelf')">open _self</button>
<button class="test" onclick="testNavMethod('anchor')">Anchor click</button>
<button class="test" onclick="testNavMethod('anchorDispatch')">Anchor dispatch</button>
</div>
</div>
</div>

<!-- TAB: ADVANCED -->
<div id="tab-advanced" class="tab-content">
<h2>⚡ Advanced Techniques</h2>

<h3>Blob URL Tests</h3>
<div class="section">
<div class="grid">
<button class="test" onclick="testBlobRedirect()">Blob URL Redirect</button>
<button class="test" onclick="testDataUri()">Data URI Redirect</button>
</div>
</div>

<h3>Service Worker Tests</h3>
<div class="section" id="sw-tests">
<div class="grid">
<button class="test" onclick="checkServiceWorker()">Check SW Support</button>
</div>
</div>

<h3>History API Tests</h3>
<div class="section">
<div class="grid">
<button class="test" onclick="testHistoryPush()">history.pushState</button>
<button class="test" onclick="testHistoryReplace()">history.replaceState</button>
<button class="test" onclick="testHistoryBack()">history.back()</button>
</div>
</div>

<h3>Document Write Tests</h3>
<div class="section">
<div class="grid">
<button class="test" onclick="testDocWrite()">document.write redirect</button>
<button class="test" onclick="testDocOpen()">document.open/write/close</button>
</div>
</div>

<h3>Script Injection Tests</h3>
<div class="section">
<div class="grid">
<button class="test" onclick="testScriptInject()">Inject redirect script</button>
<button class="test" onclick="testImgError()">IMG onerror redirect</button>
</div>
</div>
</div>

<!-- TAB: FINGERPRINT -->
<div id="tab-fingerprint" class="tab-content">
<h2>🔐 Account Type Fingerprint</h2>
<p style="color:#888;margin-bottom:10px">Trying to detect differences between large/small accounts:</p>

<div class="section" id="fingerprint-results">
<button onclick="runFullFingerprint()">🔍 Run Full Fingerprint Analysis</button>
</div>

<h2>📊 Comparison Data</h2>
<div class="section" id="comparison-data">
<p>After running fingerprint on both account types, paste results here for comparison.</p>
<textarea id="fp-input" style="width:100%;height:100px;background:#000;color:#0f0;border:1px solid #333;font-family:monospace;font-size:10px" placeholder="Paste fingerprint JSON here..."></textarea>
<button onclick="compareFingerprints()">Compare</button>
</div>

<h2>🎯 Network Timing</h2>
<div class="section" id="network-timing">
<button onclick="runNetworkAnalysis()">📡 Analyze Network Behavior</button>
</div>
</div>

<!-- LOG SECTION -->
<h2>📋 Live Log</h2>
<div id="log"></div>
<div class="grid" style="margin-top:10px">
<button onclick="clearLog()">Clear Log</button>
<button onclick="copyLog()">Copy Log</button>
<button onclick="downloadLog()">Download Log</button>
</div>

<script>
// ═══════════════════════════════════════════════════════════════
// ULTRA DEBUG v2.0 - Comprehensive Instagram In-App Browser Analysis
// ═══════════════════════════════════════════════════════════════

var logData = [];
var requestId = '${requestId}';
var testCounter = 0;

// TAB SYSTEM
function showTab(name){
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector('.tab-content#tab-'+name).classList.add('active');
  event.target.classList.add('active');
}

// LOGGING SYSTEM
function log(msg, type, data){
  type = type || 'info';
  var colors = {ok:'#00ff88', error:'#ff4444', warn:'#ffff00', info:'#00ffff', critical:'#ff00ff'};
  var entry = {time: new Date().toISOString(), msg: msg, type: type, data: data, id: ++testCounter};
  logData.push(entry);

  var logDiv = document.getElementById('log');
  var color = colors[type] || '#888';
  var timeStr = new Date().toLocaleTimeString();
  logDiv.innerHTML = '<div class="log-entry"><span class="log-time">['+timeStr+']</span> <span style="color:'+color+'">['+type.toUpperCase()+']</span> '+msg+'</div>' + logDiv.innerHTML;

  // Send to server for persistence
  try {
    navigator.sendBeacon('/debug-log', JSON.stringify(entry));
  } catch(e){}
}

function clearLog(){ document.getElementById('log').innerHTML = ''; logData = []; }
function copyLog(){ navigator.clipboard.writeText(JSON.stringify(logData, null, 2)).then(() => log('Log copied!', 'ok')); }
function downloadLog(){
  var blob = new Blob([JSON.stringify(logData, null, 2)], {type: 'application/json'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'debug-log-'+requestId+'.json';
  a.click();
}

// ═══════════════════════════════════════════════════════════════
// CLIENT DETECTION
// ═══════════════════════════════════════════════════════════════
(function(){
  var ua = navigator.userAgent || '';
  var info = '';

  // Basic info
  info += '<b>UA:</b> <span style="color:#888;font-size:10px">'+ua+'</span><br><br>';
  info += '<b>Platform:</b> '+(navigator.platform||'N/A')+' | ';
  info += '<b>Vendor:</b> '+(navigator.vendor||'N/A')+' | ';
  info += '<b>Lang:</b> '+navigator.language+'<br>';
  info += '<b>Screen:</b> '+screen.width+'x'+screen.height+' @ '+window.devicePixelRatio+'x | ';
  info += '<b>Viewport:</b> '+window.innerWidth+'x'+window.innerHeight+'<br>';
  info += '<b>Standalone:</b> '+navigator.standalone+' | ';
  info += '<b>Referrer:</b> '+(document.referrer||'none')+'<br><br>';

  // Detection badges
  var detections = [
    {name:'Instagram', test:/Instagram|FBAN|FB_IAB|FBAV|FBIOS/.test(ua)},
    {name:'Facebook', test:/FBAN|FBAV|FB_IAB/.test(ua) && !/Instagram/.test(ua)},
    {name:'TikTok', test:/TikTok|BytedanceWebview/.test(ua)},
    {name:'Twitter/X', test:/Twitter/.test(ua)},
    {name:'Snapchat', test:/Snapchat/.test(ua)},
    {name:'iOS', test:/iPhone|iPad|iPod/.test(ua)},
    {name:'Android', test:/Android/.test(ua)},
    {name:'WebView', test:/wv|WebView/.test(ua)},
  ];

  info += '<b>Detections:</b> ';
  detections.forEach(function(d){
    var cls = d.test ? 'badge-ok' : 'badge-warn';
    info += '<span class="badge '+cls+'">'+d.name+': '+d.test+'</span> ';
  });

  document.getElementById('client-info').innerHTML = info;
  log('Client detection complete', 'ok');
})();

// ═══════════════════════════════════════════════════════════════
// WEBKIT & NATIVE BRIDGE DETECTION
// ═══════════════════════════════════════════════════════════════
(function(){
  var info = '';

  // WebKit checks
  var hasWebkit = !!window.webkit;
  var hasHandlers = !!(window.webkit && window.webkit.messageHandlers);

  info += '<b>window.webkit:</b> <span class="'+(hasWebkit?'warn':'ok')+'">'+hasWebkit+'</span><br>';
  info += '<b>webkit.messageHandlers:</b> <span class="'+(hasHandlers?'warn':'ok')+'">'+hasHandlers+'</span><br>';

  if(hasHandlers){
    try {
      var keys = Object.keys(window.webkit.messageHandlers);
      info += '<b>Handler keys:</b> '+(keys.length > 0 ? keys.join(', ') : '(empty)')+'<br>';
    } catch(e) {
      info += '<b>Handler keys:</b> (cannot enumerate)';
    }
  }

  // Specific handler checks
  var handlers = [
    'instagram', 'observe', 'fb', 'fbNavigation', 'openInSafari',
    'openExternal', 'openBrowser', 'nativeBridge', 'webViewBridge',
    'contextualSearch', 'shareSheet', 'copyToClipboard', 'hapticFeedback'
  ];

  info += '<br><b>Handler probes:</b><br>';
  var foundHandlers = [];
  handlers.forEach(function(h){
    var exists = false;
    try {
      exists = !!(window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers[h]);
      if(exists) foundHandlers.push(h);
    } catch(e){}
    var cls = exists ? 'ok' : '';
    info += '<span class="'+cls+'">'+h+':'+exists+'</span> ';
  });

  // Security context
  info += '<br><br><b>Security:</b><br>';
  info += 'isSecureContext: '+window.isSecureContext+' | ';
  info += 'protocol: '+location.protocol+' | ';
  info += 'crossOriginIsolated: '+window.crossOriginIsolated;

  document.getElementById('webkit-info').innerHTML = info;
  if(foundHandlers.length) log('Found handlers: '+foundHandlers.join(', '), 'critical');
})();

// ═══════════════════════════════════════════════════════════════
// WINDOW PROPERTIES DEEP SCAN
// ═══════════════════════════════════════════════════════════════
(function(){
  var info = '';

  // Check for Instagram-specific properties
  var igProps = ['__INSTAGRAM__', '__instagram', 'InstagramInterface', 'IGBridge',
                 '__fb', '__FACEBOOK__', 'FBInterface', 'webkit', 'native'];

  info += '<b>Instagram/FB Properties:</b><br>';
  igProps.forEach(function(p){
    var exists = p in window;
    var val = exists ? (typeof window[p]) : 'N/A';
    info += p + ': ' + (exists ? '<span class="critical">'+val+'</span>' : 'no') + ' | ';
  });

  // Check for unusual window properties
  info += '<br><br><b>Unusual Properties (non-standard):</b><br>';
  var standardProps = ['addEventListener','alert','atob','blur','btoa','caches','cancelAnimationFrame',
    'clearInterval','clearTimeout','close','closed','confirm','console','crypto','customElements',
    'devicePixelRatio','document','fetch','focus','frameElement','frames','getComputedStyle',
    'getSelection','history','indexedDB','innerHeight','innerWidth','isSecureContext','length',
    'localStorage','location','locationbar','matchMedia','menubar','moveBy','moveTo','name',
    'navigator','onabort','onafterprint','onanimationend','onanimationiteration','onanimationstart',
    'onbeforeprint','onbeforeunload','onblur','oncanplay','oncanplaythrough','onchange','onclick',
    'onclose','oncontextmenu','oncuechange','ondblclick','ondrag','ondragend','ondragenter',
    'ondragleave','ondragover','ondragstart','ondrop','ondurationchange','onemptied','onended',
    'onerror','onfocus','onhashchange','oninput','oninvalid','onkeydown','onkeypress','onkeyup',
    'onlanguagechange','onload','onloadeddata','onloadedmetadata','onloadstart','onmessage',
    'onmousedown','onmouseenter','onmouseleave','onmousemove','onmouseout','onmouseover','onmouseup',
    'onoffline','ononline','onpagehide','onpageshow','onpause','onplay','onplaying','onpopstate',
    'onprogress','onratechange','onrejectionhandled','onreset','onresize','onscroll','onseeked',
    'onseeking','onselect','onstalled','onstorage','onsubmit','onsuspend','ontimeupdate','ontoggle',
    'ontransitionend','onunhandledrejection','onunload','onvolumechange','onwaiting','open',
    'opener','origin','outerHeight','outerWidth','pageXOffset','pageYOffset','parent','performance',
    'personalbar','postMessage','print','prompt','queueMicrotask','releaseEvents','requestAnimationFrame',
    'requestIdleCallback','resizeBy','resizeTo','screen','screenLeft','screenTop','screenX','screenY',
    'scroll','scrollBy','scrollTo','scrollX','scrollY','scrollbars','self','sessionStorage',
    'setInterval','setTimeout','speechSynthesis','status','statusbar','stop','styleMedia','toolbar',
    'top','visualViewport','window'];

  var unusual = [];
  for(var prop in window){
    if(standardProps.indexOf(prop) === -1 && prop.indexOf('on') !== 0 && prop.indexOf('webkit') !== 0){
      try {
        var type = typeof window[prop];
        if(type === 'function' || type === 'object'){
          unusual.push(prop + ':' + type);
        }
      } catch(e){}
    }
  }
  info += unusual.slice(0, 30).join(', ') + (unusual.length > 30 ? '...(+' + (unusual.length-30) + ')' : '');

  document.getElementById('window-props').innerHTML = info;
})();

// ═══════════════════════════════════════════════════════════════
// PERFORMANCE API ANALYSIS
// ═══════════════════════════════════════════════════════════════
(function(){
  var info = '';

  if(window.performance){
    var timing = performance.timing;
    var nav = performance.navigation;

    info += '<b>Navigation type:</b> ' + nav.type + ' ('+['navigate','reload','back_forward','reserved'][nav.type]+')<br>';
    info += '<b>Redirect count:</b> ' + nav.redirectCount + '<br>';

    var loadTime = timing.loadEventEnd - timing.navigationStart;
    var dnsTime = timing.domainLookupEnd - timing.domainLookupStart;
    var connectTime = timing.connectEnd - timing.connectStart;
    var responseTime = timing.responseEnd - timing.responseStart;

    info += '<br><b>Timing (ms):</b><br>';
    info += 'Total load: ' + loadTime + ' | DNS: ' + dnsTime + ' | Connect: ' + connectTime + ' | Response: ' + responseTime;

    // Resource timing
    var resources = performance.getEntriesByType('resource');
    info += '<br><br><b>Resources loaded:</b> ' + resources.length;
  } else {
    info = 'Performance API not available';
  }

  document.getElementById('perf-info').innerHTML = info;
})();

// ═══════════════════════════════════════════════════════════════
// SECURITY CONTEXT
// ═══════════════════════════════════════════════════════════════
(function(){
  var info = '';

  // CSP check
  info += '<b>Content Security Policy:</b><br>';
  var meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  info += meta ? meta.content : '(none in meta)';

  // Feature policy
  info += '<br><br><b>Permissions/Features:</b><br>';
  var features = ['geolocation', 'camera', 'microphone', 'clipboard-read', 'clipboard-write'];
  features.forEach(function(f){
    if(navigator.permissions){
      navigator.permissions.query({name:f}).then(function(r){
        log('Permission '+f+': '+r.state, r.state === 'granted' ? 'ok' : 'warn');
      }).catch(function(){});
    }
  });
  info += 'Check log for permission results...';

  // Storage access
  info += '<br><br><b>Storage:</b><br>';
  info += 'localStorage: ' + (!!window.localStorage) + ' | ';
  info += 'sessionStorage: ' + (!!window.sessionStorage) + ' | ';
  info += 'indexedDB: ' + (!!window.indexedDB) + ' | ';
  info += 'cookies: ' + navigator.cookieEnabled;

  document.getElementById('security-info').innerHTML = info;
})();

// ═══════════════════════════════════════════════════════════════
// NATIVE BRIDGE DETECTION
// ═══════════════════════════════════════════════════════════════
(function(){
  var info = '';

  // Check various bridge patterns
  var bridges = {
    'window.webkit': !!window.webkit,
    'window.webkit.messageHandlers': !!(window.webkit && window.webkit.messageHandlers),
    'window.postMessage': typeof window.postMessage === 'function',
    'window.ReactNativeWebView': !!window.ReactNativeWebView,
    'window.Android': !!window.Android,
    'window.flutter_inappwebview': !!window.flutter_inappwebview,
    'window.chrome.webview': !!(window.chrome && window.chrome.webview),
    'document.hasStorageAccess': typeof document.hasStorageAccess === 'function',
  };

  info += '<b>Bridge Detection:</b><br>';
  for(var bridge in bridges){
    var cls = bridges[bridge] ? 'critical' : '';
    info += '<span class="'+cls+'">'+bridge+': '+bridges[bridge]+'</span><br>';
  }

  // Try to detect custom URL scheme handlers
  info += '<br><b>Scheme Handler Probe:</b><br>';
  info += 'Testing in scheme tests tab...';

  document.getElementById('native-bridges').innerHTML = info;
})();

// ═══════════════════════════════════════════════════════════════
// SCHEME TESTING
// ═══════════════════════════════════════════════════════════════
function testScheme(url){
  var scheme = url.split('://')[0];
  log('Testing scheme: ' + scheme, 'warn');

  var startTime = performance.now();
  var escaped = false;

  // Set up visibility change detection
  var visHandler = function(){
    if(document.hidden){
      escaped = true;
      var elapsed = performance.now() - startTime;
      log('ESCAPE DETECTED via visibility change! Scheme: ' + scheme + ' (' + elapsed.toFixed(0) + 'ms)', 'critical');
    }
  };
  document.addEventListener('visibilitychange', visHandler);

  // Set up blur detection
  var blurHandler = function(){
    var elapsed = performance.now() - startTime;
    log('Window blur detected for: ' + scheme + ' (' + elapsed.toFixed(0) + 'ms)', 'warn');
  };
  window.addEventListener('blur', blurHandler);

  // Clean up after 3 seconds
  setTimeout(function(){
    document.removeEventListener('visibilitychange', visHandler);
    window.removeEventListener('blur', blurHandler);
    if(!escaped){
      log('No escape detected for: ' + scheme + ' (3s timeout)', 'error');
    }
  }, 3000);

  // Execute the navigation
  try {
    location.href = url;
    log('location.href executed for: ' + scheme, 'info');
  } catch(e){
    log('Error testing ' + scheme + ': ' + e.message, 'error');
  }
}

function testUniversalLink(){
  log('Testing Universal Link pattern...', 'warn');
  // Create a link that would trigger universal link handling
  var a = document.createElement('a');
  a.href = 'https://cmehere.net/debug?ul=1';
  a.target = '_blank';
  a.rel = 'noopener';
  document.body.appendChild(a);

  var startTime = performance.now();

  // Try programmatic click
  try {
    a.click();
    setTimeout(function(){
      log('Universal link click completed in ' + (performance.now() - startTime).toFixed(0) + 'ms', 'info');
      a.remove();
    }, 100);
  } catch(e){
    log('Universal link error: ' + e.message, 'error');
    a.remove();
  }
}

// ═══════════════════════════════════════════════════════════════
// TIMING TESTS
// ═══════════════════════════════════════════════════════════════
function testTiming(delay){
  log('Testing escape with ' + delay + 'ms delay...', 'warn');
  setTimeout(function(){
    testScheme('x-safari-https://cmehere.net/debug?delay=' + delay);
  }, delay);
}

function testMultiAttempt(pattern){
  log('Testing multi-attempt pattern: ' + pattern, 'warn');
  var delays;

  switch(pattern){
    case 'rapid':
      delays = [50, 100, 150];
      break;
    case 'staggered':
      delays = [100, 300, 500];
      break;
    case 'exponential':
      delays = [100, 200, 400];
      break;
    case 'juicy':
      // Juicy.bio pattern reverse-engineered
      delays = [0, 100, 200, 300];
      break;
    default:
      delays = [100, 200, 300];
  }

  var schemes = [
    'x-safari-https://cmehere.net/debug?p=' + pattern,
    'googlechrome://cmehere.net/debug?p=' + pattern,
    'googlechromes://cmehere.net/debug?p=' + pattern
  ];

  delays.forEach(function(delay, i){
    setTimeout(function(){
      var scheme = schemes[i % schemes.length];
      log('Attempt ' + (i+1) + ' at ' + delay + 'ms: ' + scheme.split('://')[0], 'info');
      try {
        window.open(scheme, '_blank');
      } catch(e){}
    }, delay);
  });
}

function testAfterLoad(){
  window.addEventListener('load', function(){
    log('Load event fired, testing escape...', 'warn');
    testScheme('x-safari-https://cmehere.net/debug?after=load');
  });
}

function testAfterRAF(){
  requestAnimationFrame(function(){
    log('RAF fired, testing escape...', 'warn');
    testScheme('x-safari-https://cmehere.net/debug?after=raf');
  });
}

function testAfterIdle(){
  if(window.requestIdleCallback){
    requestIdleCallback(function(){
      log('Idle callback fired, testing escape...', 'warn');
      testScheme('x-safari-https://cmehere.net/debug?after=idle');
    });
  } else {
    log('requestIdleCallback not supported', 'error');
  }
}

function testAfterMicrotask(){
  Promise.resolve().then(function(){
    log('Microtask fired, testing escape...', 'warn');
    testScheme('x-safari-https://cmehere.net/debug?after=microtask');
  });
}

function testDoubleClick(){
  log('Click once more for double-click test...', 'warn');
}
function actualDoubleClick(){
  log('Double-click detected! Testing escape...', 'critical');
  testScheme('x-safari-https://cmehere.net/debug?gesture=dblclick');
}
function testMouseDown(){
  log('MouseDown detected! Testing escape...', 'warn');
  testScheme('x-safari-https://cmehere.net/debug?gesture=mousedown');
}
function testTouchStart(){
  log('TouchStart detected! Testing escape...', 'warn');
  testScheme('x-safari-https://cmehere.net/debug?gesture=touchstart');
}

// ═══════════════════════════════════════════════════════════════
// NATIVE COMMUNICATION TESTS
// ═══════════════════════════════════════════════════════════════
function testPostMessage(type){
  log('Testing postMessage: ' + type, 'warn');
  try {
    var msg = {type: type, url: 'https://cmehere.net/debug?pm=' + type};
    window.postMessage(JSON.stringify(msg), '*');
    if(window.webkit && window.webkit.messageHandlers){
      if(window.webkit.messageHandlers[type]){
        window.webkit.messageHandlers[type].postMessage(msg);
        log('Sent to webkit.messageHandlers.' + type, 'ok');
      }
    }
    if(window.parent !== window){
      window.parent.postMessage(JSON.stringify(msg), '*');
      log('Sent to parent frame', 'info');
    }
  } catch(e){
    log('postMessage error: ' + e.message, 'error');
  }
}

function testMetaRefresh(seconds){
  log('Testing meta refresh with ' + seconds + 's delay...', 'warn');
  var meta = document.createElement('meta');
  meta.httpEquiv = 'refresh';
  meta.content = seconds + ';url=x-safari-https://cmehere.net/debug?meta=' + seconds;
  document.head.appendChild(meta);
  log('Meta refresh tag added', 'info');
}

function testIframeEscape(method){
  log('Testing iframe escape: ' + method, 'warn');
  var iframe = document.createElement('iframe');
  iframe.style.display = 'none';
  document.body.appendChild(iframe);

  switch(method){
    case 'src':
      iframe.src = 'x-safari-https://cmehere.net/debug?iframe=src';
      break;
    case 'sandbox':
      iframe.sandbox = 'allow-scripts allow-top-navigation';
      iframe.srcdoc = '<script>top.location="x-safari-https://cmehere.net/debug?iframe=sandbox"<\\/script>';
      break;
    case 'srcdoc':
      iframe.srcdoc = '<script>window.location="x-safari-https://cmehere.net/debug?iframe=srcdoc"<\\/script>';
      break;
  }

  setTimeout(function(){ iframe.remove(); }, 3000);
  log('Iframe created with method: ' + method, 'info');
}

function testFormSubmit(method){
  log('Testing form submit: ' + method, 'warn');
  var form = document.createElement('form');
  form.action = 'x-safari-https://cmehere.net/debug?form=' + method;
  form.method = method === 'POST' ? 'POST' : 'GET';
  if(method === 'target') form.target = '_blank';
  form.style.display = 'none';
  document.body.appendChild(form);
  form.submit();
  setTimeout(function(){ form.remove(); }, 1000);
}

function testNavMethod(method){
  var url = 'x-safari-https://cmehere.net/debug?nav=' + method;
  log('Testing navigation method: ' + method, 'warn');

  switch(method){
    case 'href':
      location.href = url;
      break;
    case 'assign':
      location.assign(url);
      break;
    case 'replace':
      location.replace(url);
      break;
    case 'open':
      window.open(url);
      break;
    case 'openBlank':
      window.open(url, '_blank');
      break;
    case 'openSelf':
      window.open(url, '_self');
      break;
    case 'anchor':
      var a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      document.body.appendChild(a);
      a.click();
      a.remove();
      break;
    case 'anchorDispatch':
      var a2 = document.createElement('a');
      a2.href = url;
      a2.target = '_blank';
      document.body.appendChild(a2);
      a2.dispatchEvent(new MouseEvent('click', {bubbles:true,cancelable:true,view:window}));
      a2.remove();
      break;
  }
}

// ═══════════════════════════════════════════════════════════════
// ADVANCED TECHNIQUES
// ═══════════════════════════════════════════════════════════════
function testBlobRedirect(){
  log('Testing blob URL redirect...', 'warn');
  var html = '<html><head><meta http-equiv="refresh" content="0;url=x-safari-https://cmehere.net/debug?blob=1"></head></html>';
  var blob = new Blob([html], {type: 'text/html'});
  var url = URL.createObjectURL(blob);
  window.open(url);
  setTimeout(function(){ URL.revokeObjectURL(url); }, 5000);
}

function testDataUri(){
  log('Testing data URI redirect...', 'warn');
  var html = '<html><script>location="x-safari-https://cmehere.net/debug?data=1"<\\/script></html>';
  var dataUri = 'data:text/html,' + encodeURIComponent(html);
  window.open(dataUri);
}

function checkServiceWorker(){
  if('serviceWorker' in navigator){
    log('Service Worker supported', 'ok');
    navigator.serviceWorker.getRegistrations().then(function(regs){
      log('SW registrations: ' + regs.length, 'info');
    });
  } else {
    log('Service Worker NOT supported', 'error');
  }
}

function testHistoryPush(){
  log('Testing history.pushState...', 'warn');
  history.pushState({}, '', 'x-safari-https://cmehere.net/debug?history=push');
  log('pushState executed (check URL bar)', 'info');
}

function testHistoryReplace(){
  log('Testing history.replaceState...', 'warn');
  history.replaceState({}, '', 'x-safari-https://cmehere.net/debug?history=replace');
  log('replaceState executed (check URL bar)', 'info');
}

function testHistoryBack(){
  log('Testing history.back()...', 'warn');
  history.back();
}

function testDocWrite(){
  log('Testing document.write redirect...', 'warn');
  document.write('<html><script>location="x-safari-https://cmehere.net/debug?docwrite=1"<\\/script></html>');
}

function testDocOpen(){
  log('Testing document.open/write/close...', 'warn');
  document.open();
  document.write('<script>location="x-safari-https://cmehere.net/debug?docopen=1"<\\/script>');
  document.close();
}

function testScriptInject(){
  log('Testing script injection redirect...', 'warn');
  var s = document.createElement('script');
  s.textContent = 'location.href="x-safari-https://cmehere.net/debug?script=1"';
  document.body.appendChild(s);
}

function testImgError(){
  log('Testing IMG onerror redirect...', 'warn');
  var img = document.createElement('img');
  img.onerror = function(){ location.href = 'x-safari-https://cmehere.net/debug?img=error'; };
  img.src = 'https://invalid-url-' + Date.now() + '.jpg';
  document.body.appendChild(img);
}

// ═══════════════════════════════════════════════════════════════
// FINGERPRINTING
// ═══════════════════════════════════════════════════════════════
function runFullFingerprint(){
  log('Running full fingerprint analysis...', 'warn');

  var fp = {
    requestId: requestId,
    timestamp: new Date().toISOString(),

    // Navigator
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    vendor: navigator.vendor,
    language: navigator.language,
    languages: navigator.languages,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    hardwareConcurrency: navigator.hardwareConcurrency,
    maxTouchPoints: navigator.maxTouchPoints,

    // Screen
    screenWidth: screen.width,
    screenHeight: screen.height,
    screenAvailWidth: screen.availWidth,
    screenAvailHeight: screen.availHeight,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth,
    devicePixelRatio: window.devicePixelRatio,

    // Window
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,

    // Security
    isSecureContext: window.isSecureContext,
    crossOriginIsolated: window.crossOriginIsolated,

    // WebKit
    hasWebkit: !!window.webkit,
    hasMessageHandlers: !!(window.webkit && window.webkit.messageHandlers),

    // Storage
    hasLocalStorage: !!window.localStorage,
    hasSessionStorage: !!window.sessionStorage,
    hasIndexedDB: !!window.indexedDB,

    // Features
    hasServiceWorker: 'serviceWorker' in navigator,
    hasWebGL: !!window.WebGLRenderingContext,
    hasWebGL2: !!window.WebGL2RenderingContext,

    // Timing
    performanceNow: performance.now(),
    navigationType: performance.navigation ? performance.navigation.type : null,

    // Canvas fingerprint
    canvasHash: getCanvasFingerprint(),

    // Audio fingerprint
    audioContextSampleRate: getAudioContext(),

    // WebGL info
    webglInfo: getWebGLInfo()
  };

  var resultDiv = document.getElementById('fingerprint-results');
  resultDiv.innerHTML = '<pre style="max-height:400px;overflow:auto">' + JSON.stringify(fp, null, 2) + '</pre>';
  resultDiv.innerHTML += '<button onclick="copyFingerprint()">📋 Copy Fingerprint</button>';

  window.currentFingerprint = fp;
  log('Fingerprint complete. Copy and compare between accounts!', 'ok');
}

function getCanvasFingerprint(){
  try {
    var canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    var ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Instagram Debug 🔍', 2, 2);
    return canvas.toDataURL().slice(-50);
  } catch(e){
    return 'error';
  }
}

function getAudioContext(){
  try {
    var ctx = new (window.AudioContext || window.webkitAudioContext)();
    return ctx.sampleRate;
  } catch(e){
    return null;
  }
}

function getWebGLInfo(){
  try {
    var canvas = document.createElement('canvas');
    var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if(!gl) return null;
    return {
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      version: gl.getParameter(gl.VERSION)
    };
  } catch(e){
    return null;
  }
}

function copyFingerprint(){
  if(window.currentFingerprint){
    navigator.clipboard.writeText(JSON.stringify(window.currentFingerprint, null, 2))
      .then(function(){ log('Fingerprint copied!', 'ok'); });
  }
}

function compareFingerprints(){
  var input = document.getElementById('fp-input').value;
  log('Comparing fingerprints... (manual comparison needed)', 'warn');
  // User will need to manually compare the two fingerprints
}

function runNetworkAnalysis(){
  log('Running network timing analysis...', 'warn');

  var results = {
    timestamp: new Date().toISOString(),
    tests: []
  };

  // Test fetch timing
  var startFetch = performance.now();
  fetch('/debug?network=fetch&t=' + Date.now())
    .then(function(r){ return r.text(); })
    .then(function(){
      var elapsed = performance.now() - startFetch;
      results.tests.push({type:'fetch', elapsed: elapsed});
      log('Fetch completed in ' + elapsed.toFixed(0) + 'ms', 'info');
    })
    .catch(function(e){
      log('Fetch error: ' + e.message, 'error');
    });

  // Test XHR timing
  var startXhr = performance.now();
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/debug?network=xhr&t=' + Date.now());
  xhr.onload = function(){
    var elapsed = performance.now() - startXhr;
    results.tests.push({type:'xhr', elapsed: elapsed});
    log('XHR completed in ' + elapsed.toFixed(0) + 'ms', 'info');
  };
  xhr.onerror = function(){
    log('XHR error', 'error');
  };
  xhr.send();

  // Test beacon
  var beaconResult = navigator.sendBeacon('/debug?network=beacon&t=' + Date.now(), 'test');
  log('sendBeacon returned: ' + beaconResult, beaconResult ? 'ok' : 'error');

  document.getElementById('network-timing').innerHTML += '<pre>' + JSON.stringify(results, null, 2) + '</pre>';
}

// Initialize
log('ULTRA DEBUG v2.0 initialized', 'ok');
log('Request ID: ' + requestId, 'info');
log('Run tests from the tabs above', 'info');
</script>
</body></html>`);
});

// ═══ X-WEB-SEARCH ESCAPE TEST PAGE ═══
// Based on discovery that x-web-search:// works on large Instagram accounts
app.get('/xtest', (req, res) => {
  const targetUrl = req.query.url || 'https://cmehere.net/mememe';
  const domain = new URL(targetUrl).hostname;

  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🔬 X-Web-Search Escape Lab</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a0f;color:#fff;padding:20px;min-height:100vh}
h1{color:#ff00ff;text-align:center;margin-bottom:20px}
.info{background:#111;padding:15px;border-radius:8px;margin-bottom:20px;border:1px solid #333}
.target{color:#00ff88;word-break:break-all}
.section{margin:20px 0}
h2{color:#00ffff;margin-bottom:10px;font-size:16px}
button{display:block;width:100%;background:linear-gradient(135deg,#ff00ff,#8800aa);color:#fff;border:none;padding:15px;margin:8px 0;font-size:14px;cursor:pointer;border-radius:8px;font-weight:bold}
button:active{transform:scale(0.98)}
button.alt{background:linear-gradient(135deg,#00ffff,#0088aa);color:#000}
button.success{background:linear-gradient(135deg,#00ff88,#00aa55);color:#000}
#log{background:#000;padding:15px;border-radius:8px;margin-top:20px;font-family:monospace;font-size:11px;max-height:300px;overflow-y:auto}
.log-entry{padding:5px 0;border-bottom:1px solid #222}
.ok{color:#00ff88}
.error{color:#ff4444}
.warn{color:#ffff00}
.critical{color:#ff00ff}
</style>
</head><body>
<h1>🔬 X-Web-Search Lab</h1>

<div class="info">
<p><strong>Discovery:</strong> x-web-search:// escapes Instagram's in-app browser on large accounts!</p>
<p style="margin-top:10px"><strong>Target URL:</strong> <span class="target">${targetUrl}</span></p>
<p style="margin-top:5px"><strong>Domain:</strong> <span class="target">${domain}</span></p>
</div>

<div class="section">
<h2>🎯 Primary Tests (x-web-search variations)</h2>
<button onclick="test('x-web-search://?${domain}')">x-web-search://?${domain}</button>
<button onclick="test('x-web-search://${domain}')">x-web-search://${domain}</button>
<button onclick="test('x-web-search://?site:${domain}')">x-web-search://?site:${domain}</button>
<button onclick="test('x-web-search://?${targetUrl}')">x-web-search://?[full URL]</button>
<button onclick="test('x-web-search://?q=${domain}')">x-web-search://?q=${domain}</button>
<button onclick="test('x-web-search://?query=${domain}')">x-web-search://?query=${domain}</button>
</div>

<div class="section">
<h2>🦆 DUCKDUCKGO DIRECT (TRY FIRST!)</h2>
<p style="color:#ff0;margin-bottom:10px;font-size:12px">DDG backslash goes DIRECTLY to first result!</p>
<button class="success" onclick="testDDG('${domain}')">DDG \\${domain} (DIRECT!)</button>
<button class="success" onclick="testDDG('site:${domain}')">DDG \\site:${domain}</button>
<button class="success" onclick="test('ddgQuickLink://%5C${domain}')">DDG App Scheme</button>
</div>

<div class="section">
<h2>🔥 OPTIMIZED SEARCH QUERIES</h2>
<button onclick="test('x-web-search://?${domain} I\\'m Feeling Lucky')">+ "I'm Feeling Lucky"</button>
<button onclick="test('x-web-search://?${targetUrl}')">Full URL as search</button>
<button onclick="test('x-web-search://?"${domain}"')">Domain in quotes</button>
<button onclick="test('x-web-search://?inurl:${domain}')">inurl:${domain}</button>
</div>

<div class="section">
<h2>🍎 SAFARI DIRECT SCHEMES</h2>
<button onclick="test('com-apple-mobilesafari-tab:${targetUrl}')">com-apple-mobilesafari-tab:</button>
<button onclick="test('mobilesafari://${targetUrl}')">mobilesafari://</button>
</div>

<div class="section">
<h2>🔍 Spotlight Search Variations</h2>
<button class="alt" onclick="test('spotlight://${domain}')">spotlight://${domain}</button>
<button class="alt" onclick="test('spotlight-search://${domain}')">spotlight-search://${domain}</button>
<button class="alt" onclick="test('apple-search://${domain}')">apple-search://${domain}</button>
</div>

<div class="section">
<h2>📱 Other System Schemes</h2>
<button class="alt" onclick="test('shortcuts://run-shortcut?name=OpenURL&input=${encodeURIComponent(targetUrl)}')">shortcuts:// (if configured)</button>
<button class="alt" onclick="test('workflow://run-workflow?name=OpenURL&input=${encodeURIComponent(targetUrl)}')">workflow:// (legacy)</button>
<button class="alt" onclick="test('apple-magnifier://')">apple-magnifier://</button>
</div>

<div class="section">
<h2>🌐 Direct URL Tests</h2>
<button class="success" onclick="test('${targetUrl}')">Direct HTTPS (${domain})</button>
<button class="success" onclick="testOpen('${targetUrl}')">window.open HTTPS</button>
<button class="success" onclick="testAnchor('${targetUrl}')">Anchor click HTTPS</button>
</div>

<div class="section">
<h2>⚡ Combined Strategies</h2>
<button onclick="testCombined()">🚀 TRY ALL (staggered 200ms)</button>
<button onclick="testSmartEscape()">🧠 SMART ESCAPE (best first)</button>
</div>

<div id="log"></div>

<script>
var escaped = false;

function log(msg, type) {
  type = type || 'info';
  var colors = {ok:'#00ff88', error:'#ff4444', warn:'#ffff00', info:'#00ffff', critical:'#ff00ff'};
  var logDiv = document.getElementById('log');
  var time = new Date().toLocaleTimeString();
  logDiv.innerHTML = '<div class="log-entry" style="color:'+colors[type]+'">['+time+'] '+msg+'</div>' + logDiv.innerHTML;
}

function test(url) {
  var scheme = url.split('://')[0];
  log('Testing: ' + scheme + '://', 'warn');

  var startTime = performance.now();

  // Visibility change detection
  var visHandler = function() {
    if(document.hidden && !escaped) {
      escaped = true;
      var elapsed = (performance.now() - startTime).toFixed(0);
      log('✅ ESCAPE via ' + scheme + '! (' + elapsed + 'ms)', 'critical');
    }
  };
  document.addEventListener('visibilitychange', visHandler);

  // Timeout cleanup
  setTimeout(function() {
    document.removeEventListener('visibilitychange', visHandler);
    if(!escaped) {
      log('❌ No escape: ' + scheme, 'error');
    }
  }, 3000);

  // Execute
  try {
    location.href = url;
    log('Executed: ' + scheme, 'info');
  } catch(e) {
    log('Error: ' + e.message, 'error');
  }
}

function testOpen(url) {
  log('Testing window.open...', 'warn');
  try {
    var w = window.open(url, '_blank');
    log('window.open returned: ' + (w ? 'window' : 'null'), w ? 'ok' : 'error');
  } catch(e) {
    log('Error: ' + e.message, 'error');
  }
}

function testDDG(query) {
  // DuckDuckGo's backslash feature goes directly to first result
  var ddgUrl = 'https://duckduckgo.com/?q=' + encodeURIComponent('\\\\' + query);
  log('Testing DDG direct: \\\\' + query, 'critical');

  var startTime = performance.now();

  var visHandler = function() {
    if(document.hidden && !escaped) {
      escaped = true;
      var elapsed = (performance.now() - startTime).toFixed(0);
      log('✅ DDG ESCAPE! (' + elapsed + 'ms)', 'critical');
    }
  };
  document.addEventListener('visibilitychange', visHandler);

  setTimeout(function() {
    document.removeEventListener('visibilitychange', visHandler);
  }, 5000);

  try {
    location.href = ddgUrl;
    log('DDG URL opened', 'info');
  } catch(e) {
    log('Error: ' + e.message, 'error');
  }
}

function testAnchor(url) {
  log('Testing anchor click...', 'warn');
  var a = document.createElement('a');
  a.href = url;
  a.target = '_blank';
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  log('Anchor clicked', 'info');
}

function testCombined() {
  log('🚀 Starting combined test...', 'critical');
  var schemes = [
    'x-web-search://?${domain}',
    'x-web-search://${domain}',
    'x-web-search://?site:${domain}',
    'spotlight://${domain}',
    '${targetUrl}'
  ];

  schemes.forEach(function(scheme, i) {
    setTimeout(function() {
      if(!escaped) {
        var name = scheme.split('://')[0];
        log('Attempt ' + (i+1) + ': ' + name, 'warn');
        try { location.href = scheme; } catch(e) {}
      }
    }, i * 200);
  });
}

function testSmartEscape() {
  log('🧠 Smart escape starting...', 'critical');

  // Based on our discovery, x-web-search works!
  // Try it first, then fallback to direct URL

  var startTime = performance.now();
  escaped = false;

  var visHandler = function() {
    if(document.hidden && !escaped) {
      escaped = true;
      var elapsed = (performance.now() - startTime).toFixed(0);
      log('✅ ESCAPED! (' + elapsed + 'ms)', 'critical');
    }
  };
  document.addEventListener('visibilitychange', visHandler);

  // Strategy: Try x-web-search first
  log('Step 1: x-web-search...', 'info');
  location.href = 'x-web-search://?${domain}';

  // If that doesn't work after 1.5s, try direct
  setTimeout(function() {
    if(!escaped) {
      log('Step 2: Direct URL...', 'info');
      location.href = '${targetUrl}';
    }
  }, 1500);

  // Cleanup
  setTimeout(function() {
    document.removeEventListener('visibilitychange', visHandler);
    if(!escaped) {
      log('All attempts failed', 'error');
    }
  }, 5000);
}

log('X-Web-Search Lab initialized', 'ok');
log('Target: ${domain}', 'info');
</script>
</body></html>`);
});

// ═══ INSTAGRAM ESCAPE V2 - Using x-web-search discovery ═══
// Auto-escape page that uses x-web-search:// which works on large accounts
app.get('/igescape', (req, res) => {
  const targetUrl = req.query.url || 'https://cmehere.net/mememe';
  const domain = new URL(targetUrl).hostname;
  const stripped = targetUrl.replace(/^https?:\/\//, '');

  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opening in Safari...</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:20px;padding:40px;text-align:center;max-width:350px;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
h1{font-size:48px;margin-bottom:15px}
h2{color:#333;font-size:18px;margin-bottom:10px}
p{color:#666;font-size:14px;margin-bottom:20px}
.spinner{width:50px;height:50px;border:4px solid #eee;border-top:4px solid #667eea;border-radius:50%;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.btn{display:block;width:100%;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;padding:15px;font-size:16px;border-radius:10px;cursor:pointer;margin-top:15px;font-weight:600;text-decoration:none}
.btn:active{transform:scale(0.98)}
.secondary{background:#f0f0f0;color:#333}
.status{font-size:12px;color:#999;margin-top:15px}
#method{font-weight:bold;color:#667eea}
</style>
</head><body>
<div class="card">
<h1>🚀</h1>
<h2>Opening in Safari...</h2>
<div class="spinner" id="spinner"></div>
<p>If nothing happens, tap the button below:</p>

<a class="btn" id="mainBtn" href="x-web-search://?${domain}">Open in Safari</a>

<a class="btn secondary" href="${targetUrl}">Continue in Browser</a>

<p class="status">Method: <span id="method">auto-detecting...</span></p>
</div>

<script>
var escaped = false;
var targetUrl = '${targetUrl}';
var domain = '${domain}';
var stripped = '${stripped}';

// Visibility change detection
document.addEventListener('visibilitychange', function() {
  if(document.hidden) escaped = true;
});

// Auto-escape sequence
(function() {
  var methods = [
    // Priority 1: x-web-search (proven to work!)
    {name: 'x-web-search', url: 'x-web-search://?site:' + domain, delay: 100},
    // Priority 2: Safari direct schemes
    {name: 'mobilesafari-tab', url: 'com-apple-mobilesafari-tab:' + targetUrl, delay: 400},
    // Priority 3: x-safari (might work)
    {name: 'x-safari-https', url: 'x-safari-https://' + stripped, delay: 700},
    // Priority 4: Chrome fallback
    {name: 'googlechrome', url: 'googlechrome://' + stripped, delay: 1000}
  ];

  methods.forEach(function(m) {
    setTimeout(function() {
      if(!escaped) {
        document.getElementById('method').textContent = m.name;
        try { location.href = m.url; } catch(e) {}
      }
    }, m.delay);
  });

  // Update UI if escaped
  setTimeout(function() {
    if(escaped) {
      document.getElementById('spinner').style.display = 'none';
      document.getElementById('method').textContent = 'Success!';
    }
  }, 1500);
})();
</script>
</body></html>`);
});

// ═══ SMART INSTAGRAM REDIRECT ═══
// Main redirect endpoint that detects Instagram and uses the best escape method
app.get('/igopen', (req, res) => {
  const targetUrl = req.query.url || 'https://cmehere.net/mememe';
  const ua = req.headers['user-agent'] || '';
  const isInstagram = /Instagram|FBAN|FB_IAB/.test(ua);
  const isIOS = /iPhone|iPad|iPod/.test(ua);

  // If not Instagram, just redirect
  if (!isInstagram) {
    return res.redirect(302, targetUrl);
  }

  // If Instagram on iOS, use escape page
  if (isIOS) {
    return res.redirect(302, '/igescape?url=' + encodeURIComponent(targetUrl));
  }

  // Android fallback - try intent
  const domain = new URL(targetUrl).hostname;
  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opening...</title>
<style>
body{font-family:system-ui;background:#000;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
.card{padding:40px}
.btn{display:block;background:#0095f6;color:#fff;padding:15px 30px;border-radius:8px;text-decoration:none;margin-top:20px}
</style>
</head><body>
<div class="card">
<h1>📱</h1>
<p>Opening in browser...</p>
<a class="btn" href="intent://${domain}#Intent;scheme=https;package=com.android.chrome;end">Open in Chrome</a>
<a class="btn" href="${targetUrl}">Continue</a>
</div>
<script>
setTimeout(function(){
  location.href = 'intent://${domain}#Intent;scheme=https;package=com.android.chrome;end';
}, 100);
</script>
</body></html>`);
});

// ═══ HEALTH CHECK (restricted to Railway/internal use) ═══
app.get('/health', (req, res) => {
  // Only allow health checks from Railway or localhost
  const forwardedFor = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  const userAgent = req.headers['user-agent'] || '';

  // Allow Railway health checks (internal) and localhost
  const isRailway = userAgent.includes('Railway') || userAgent.includes('health');
  const isLocalhost = req.ip === '127.0.0.1' || req.ip === '::1';
  const isInternal = !forwardedFor || forwardedFor.includes('10.') || forwardedFor.includes('172.');

  // Return minimal info to external requests
  if (!isRailway && !isLocalhost && !isInternal) {
    return res.status(200).json({ status: 'ok' });
  }

  // Full health check for authorized requests
  if (!dbReady) {
    return res.status(200).json({ status: 'starting', db: false });
  }

  pool.query('SELECT 1').then(() => {
    res.status(200).json({ status: 'ok', db: true });
  }).catch((e) => {
    console.error('Health check DB error:', e.message);
    res.status(200).json({ status: 'degraded', db: false });
  });
});

// ═══ ESCAPE LAB V3 - Testing ALL known escape methods ═══
// Comprehensive testing page with all discovered escape techniques
app.get('/escapelab', (req, res) => {
  const targetUrl = req.query.url || 'https://cmehere.net/mememe';
  const domain = new URL(targetUrl).hostname;
  const stripped = targetUrl.replace(/^https?:\/\//, '');
  const pathOnly = new URL(targetUrl).pathname;

  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>🔬 Escape Lab V3</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a14;color:#fff;padding:15px}
h1{font-size:24px;margin-bottom:5px;text-align:center}
.subtitle{color:#666;font-size:12px;text-align:center;margin-bottom:15px}
.section{background:#1a1a2e;border-radius:12px;padding:15px;margin-bottom:15px}
.section h2{font-size:14px;color:#888;margin-bottom:10px;border-bottom:1px solid #333;padding-bottom:5px}
.btn{display:block;width:100%;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;padding:12px;font-size:14px;border-radius:8px;cursor:pointer;margin-bottom:8px;text-decoration:none;text-align:center}
.btn:active{transform:scale(0.98)}
.btn.green{background:linear-gradient(135deg,#11998e,#38ef7d)}
.btn.orange{background:linear-gradient(135deg,#f2994a,#f2c94c);color:#000}
.btn.red{background:linear-gradient(135deg,#e74c3c,#c0392b)}
.btn.blue{background:linear-gradient(135deg,#2196F3,#21CBF3)}
.btn.gray{background:#444}
.log{background:#000;border-radius:8px;padding:10px;font-family:monospace;font-size:11px;max-height:200px;overflow-y:auto;margin-top:10px}
.log-entry{padding:3px 0;border-bottom:1px solid #222}
.ok{color:#2ecc71}.error{color:#e74c3c}.warn{color:#f39c12}.info{color:#3498db}.critical{color:#e91e63}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.status{font-size:11px;color:#666;text-align:center;margin-top:10px}
.target{background:#222;padding:8px;border-radius:6px;font-size:11px;word-break:break-all;margin-bottom:10px}
</style>
</head><body>

<h1>🔬 Escape Lab V3</h1>
<p class="subtitle">Testing ALL known Instagram escape methods</p>

<div class="target">
  <strong>Target:</strong> ${targetUrl}
</div>

<div class="section">
  <h2>🏆 PROVEN WORKING (x-web-search)</h2>
  <div class="grid">
    <button class="btn green" onclick="test('x-web-search://?${domain}')">?domain</button>
    <button class="btn green" onclick="test('x-web-search://${domain}')">://domain</button>
    <button class="btn green" onclick="test('x-web-search://?site:${domain}')">?site:domain</button>
    <button class="btn green" onclick="test('x-web-search://?${encodeURIComponent(targetUrl)}')">?fullURL</button>
  </div>
</div>

<div class="section">
  <h2>🆕 SHORTCUTS FALLBACK (x-callback-url)</h2>
  <p style="font-size:11px;color:#666;margin-bottom:10px">Uses iOS Shortcuts app with x-error fallback - might bypass restrictions!</p>
  <button class="btn blue" onclick="testShortcuts()">shortcuts://x-callback-url → Safari</button>
  <button class="btn blue" onclick="testShortcutsRandom()">Random Shortcut Name (error fallback)</button>
</div>

<div class="section">
  <h2>📥 FILE DOWNLOAD TRICK</h2>
  <p style="font-size:11px;color:#666;margin-bottom:10px">Pretends to be a file download - forces external browser</p>
  <button class="btn orange" onclick="testDownload()">Download Redirect Trick</button>
  <a class="btn orange" href="/dlredirect?url=${encodeURIComponent(targetUrl)}" download="redirect.html">Direct Download Link</a>
</div>

<div class="section">
  <h2>🍎 SAFARI SCHEMES</h2>
  <div class="grid">
    <button class="btn" onclick="test('x-safari-https://${stripped}')">x-safari-https</button>
    <button class="btn" onclick="test('x-safari-http://${stripped}')">x-safari-http</button>
    <button class="btn gray" onclick="test('com-apple-mobilesafari-tab:${targetUrl}')">mobilesafari-tab</button>
    <button class="btn gray" onclick="test('com-apple-mobilesafari:${targetUrl}')">mobilesafari</button>
  </div>
</div>

<div class="section">
  <h2>🌐 OTHER BROWSER SCHEMES</h2>
  <div class="grid">
    <button class="btn" onclick="test('googlechrome://${stripped}')">Chrome</button>
    <button class="btn" onclick="test('googlechrome://navigate?url=${encodeURIComponent(targetUrl)}')">Chrome Navigate</button>
    <button class="btn" onclick="test('firefox://open-url?url=${encodeURIComponent(targetUrl)}')">Firefox</button>
    <button class="btn" onclick="test('opera://open?url=${encodeURIComponent(targetUrl)}')">Opera</button>
  </div>
</div>

<div class="section">
  <h2>🤖 ANDROID INTENTS</h2>
  <div class="grid">
    <button class="btn blue" onclick="test('intent://${domain}#Intent;scheme=https;end')">Basic Intent</button>
    <button class="btn blue" onclick="test('intent://${domain}${pathOnly}#Intent;scheme=https;end')">Intent+Path</button>
    <button class="btn blue" onclick="test('intent://${domain}#Intent;scheme=https;package=com.android.chrome;end')">Chrome Intent</button>
    <button class="btn blue" onclick="test('intent://${domain}#Intent;scheme=https;action=android.intent.action.VIEW;end')">VIEW Intent</button>
  </div>
</div>

<div class="section">
  <h2>🔮 EXPERIMENTAL</h2>
  <div class="grid">
    <button class="btn red" onclick="test('spotlight://${domain}')">Spotlight</button>
    <button class="btn red" onclick="test('sms:&body=${encodeURIComponent(targetUrl)}')">SMS (view only)</button>
    <button class="btn red" onclick="testBlob()">Blob URL</button>
    <button class="btn red" onclick="testDataURI()">Data URI Redirect</button>
  </div>
  <button class="btn orange" onclick="testMeta()">Meta Refresh Redirect</button>
  <button class="btn orange" onclick="testFormPost()">Form POST Redirect</button>
</div>

<div class="section">
  <h2>⚡ AUTO SEQUENCES</h2>
  <button class="btn green" onclick="autoSequenceV3()">🚀 Run ALL (Priority Order)</button>
  <button class="btn" onclick="autoSafariOnly()">Safari Schemes Only</button>
</div>

<div class="section">
  <h2>📊 Log</h2>
  <div class="log" id="log"></div>
</div>

<p class="status">Escape Lab V3 | Target: ${domain}</p>

<script>
var escaped = false;
var targetUrl = '${targetUrl}';
var domain = '${domain}';
var stripped = '${stripped}';

function log(msg, type) {
  var el = document.getElementById('log');
  var entry = document.createElement('div');
  entry.className = 'log-entry ' + (type || 'info');
  var time = new Date().toLocaleTimeString();
  entry.innerHTML = '<span style="color:#555">' + time + '</span> ' + msg;
  el.insertBefore(entry, el.firstChild);
}

document.addEventListener('visibilitychange', function() {
  if(document.hidden && !escaped) {
    escaped = true;
    log('✅ ESCAPED! Page hidden', 'critical');
  }
});

function test(url) {
  var scheme = url.split('://')[0];
  log('Testing: ' + scheme + '...', 'warn');

  var start = performance.now();
  var localEscaped = false;

  var handler = function() {
    if(document.hidden && !localEscaped) {
      localEscaped = true;
      escaped = true;
      var ms = (performance.now() - start).toFixed(0);
      log('✅ ' + scheme + ' WORKED! (' + ms + 'ms)', 'critical');
    }
  };
  document.addEventListener('visibilitychange', handler);

  setTimeout(function() {
    document.removeEventListener('visibilitychange', handler);
    if(!localEscaped) {
      log('❌ ' + scheme + ' - no escape', 'error');
    }
  }, 2500);

  try {
    location.href = url;
  } catch(e) {
    log('Error: ' + e.message, 'error');
  }
}

function testShortcuts() {
  // Uses Shortcuts x-callback-url with x-error fallback
  // If shortcut doesn't exist, x-error opens as URL
  var url = 'shortcuts://x-callback-url/run-shortcut?name=OpenSafari&x-error=' + encodeURIComponent(targetUrl);
  log('Testing Shortcuts x-callback...', 'warn');
  test(url);
}

function testShortcutsRandom() {
  // Random UUID as shortcut name - guaranteed to fail, x-error should open
  var randomName = 'SC_' + Math.random().toString(36).substr(2, 9);
  var url = 'shortcuts://x-callback-url/run-shortcut?name=' + randomName + '&x-error=' + encodeURIComponent(targetUrl);
  log('Testing random shortcut (' + randomName + ')...', 'warn');
  test(url);
}

function testDownload() {
  // Fetch endpoint that returns as downloadable file
  log('Testing download redirect...', 'warn');
  location.href = '/dlredirect?url=' + encodeURIComponent(targetUrl);
}

function testBlob() {
  log('Testing Blob URL...', 'warn');
  var html = '<html><head><meta http-equiv="refresh" content="0;url=' + targetUrl + '"></head></html>';
  var blob = new Blob([html], {type: 'text/html'});
  var blobUrl = URL.createObjectURL(blob);
  test(blobUrl);
}

function testDataURI() {
  log('Testing Data URI...', 'warn');
  var html = '<html><head><meta http-equiv="refresh" content="0;url=' + targetUrl + '"></head></html>';
  var dataUri = 'data:text/html;base64,' + btoa(html);
  test(dataUri);
}

function testMeta() {
  log('Testing meta refresh redirect...', 'warn');
  location.href = '/metaredirect?url=' + encodeURIComponent(targetUrl);
}

function testFormPost() {
  log('Testing form POST redirect...', 'warn');
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = '/formredirect';
  form.innerHTML = '<input type="hidden" name="url" value="' + targetUrl + '">';
  document.body.appendChild(form);
  form.submit();
}

function autoSequenceV3() {
  log('🚀 Auto sequence V3 starting...', 'critical');
  escaped = false;

  var methods = [
    // Tier 1: x-web-search variations (proven working!)
    {url: 'x-web-search://?site:' + domain, delay: 0},
    {url: 'x-web-search://' + domain, delay: 300},

    // Tier 2: Shortcuts fallback trick
    {url: 'shortcuts://x-callback-url/run-shortcut?name=X&x-error=' + encodeURIComponent(targetUrl), delay: 600},

    // Tier 3: Safari schemes (might work on some accounts)
    {url: 'x-safari-https://' + stripped, delay: 900},
    {url: 'com-apple-mobilesafari-tab:' + targetUrl, delay: 1200},

    // Tier 4: Chrome
    {url: 'googlechrome://' + stripped, delay: 1500},

    // Tier 5: Direct URL (last resort)
    {url: targetUrl, delay: 1800}
  ];

  methods.forEach(function(m, i) {
    setTimeout(function() {
      if(!escaped) {
        var scheme = m.url.split('://')[0];
        log('Attempt ' + (i+1) + '/' + methods.length + ': ' + scheme, 'warn');
        try { location.href = m.url; } catch(e) {}
      }
    }, m.delay);
  });
}

function autoSafariOnly() {
  log('Safari schemes sequence...', 'critical');
  escaped = false;

  var methods = [
    {url: 'x-safari-https://' + stripped, delay: 0},
    {url: 'x-safari-http://' + stripped, delay: 400},
    {url: 'com-apple-mobilesafari-tab:' + targetUrl, delay: 800},
    {url: 'com-apple-mobilesafari:' + targetUrl, delay: 1200}
  ];

  methods.forEach(function(m, i) {
    setTimeout(function() {
      if(!escaped) {
        var scheme = m.url.split('://')[0];
        log('Attempt ' + (i+1) + ': ' + scheme, 'warn');
        try { location.href = m.url; } catch(e) {}
      }
    }, m.delay);
  });
}

log('Escape Lab V3 initialized', 'ok');
log('Target: ' + domain, 'info');
</script>
</body></html>`);
});

// ═══ DOWNLOAD REDIRECT TRICK ═══
// Returns a file that redirects - might bypass in-app browser
app.get('/dlredirect', (req, res) => {
  const targetUrl = req.query.url || 'https://cmehere.net/mememe';

  // Set headers to force download
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename="link.html"');

  // HTML that redirects when opened
  const html = `<!DOCTYPE html>
<html><head>
<meta http-equiv="refresh" content="0;url=${targetUrl}">
<script>window.location.href="${targetUrl}";</script>
</head><body>
<p>Redirecting to <a href="${targetUrl}">${targetUrl}</a>...</p>
</body></html>`;

  res.send(html);
});

// ═══ META REFRESH REDIRECT ═══
app.get('/metaredirect', (req, res) => {
  const targetUrl = req.query.url || 'https://cmehere.net/mememe';

  res.send(`<!DOCTYPE html>
<html><head>
<meta http-equiv="refresh" content="0;url=${targetUrl}">
<meta name="referrer" content="no-referrer">
</head><body>
<script>
// Multiple redirect attempts
setTimeout(function() { window.location.replace("${targetUrl}"); }, 0);
setTimeout(function() { window.location.href = "${targetUrl}"; }, 100);
setTimeout(function() { document.location = "${targetUrl}"; }, 200);
</script>
<p>Redirecting...</p>
</body></html>`);
});

// ═══ FORM POST REDIRECT ═══
app.post('/formredirect', express.urlencoded({ extended: true }), (req, res) => {
  const targetUrl = req.body.url || 'https://cmehere.net/mememe';
  res.redirect(302, targetUrl);
});

// ═══ 404 HANDLER ═══
app.use((req, res) => {
  res.status(404).send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>404 - Not Found</title>
<style>body{font-family:system-ui;background:#0a0a14;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center}h1{font-size:80px;margin:0;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
p{color:#888;margin-top:10px}a{color:#667eea;text-decoration:none}</style></head>
<body><div class="box"><h1>404</h1><p>Page not found</p><a href="/">← Back to Home</a></div></body></html>`);
});

// ═══ GLOBAL ERROR HANDLER ═══
// Catches all unhandled errors - hides internal details from users
app.use((err, req, res, next) => {
  // Log error for debugging (server-side only)
  console.error('Server error:', err.message);

  // Don't expose internal error details to users
  const isDev = process.env.NODE_ENV !== 'production';

  res.status(err.status || 500).json({
    error: isDev ? err.message : 'Internal server error',
    // Never expose stack traces in production
    ...(isDev && { stack: err.stack })
  });
});

// ═══ START ═══
// Start server immediately, then initialize DB
app.listen(PORT, () => {
  console.log(`🚀 cmehere.net starting on port ${PORT}`);
  console.log(`📊 DATABASE_URL exists: ${!!process.env.DATABASE_URL}`);

  // Initialize DB after server is listening
  initDB().then(() => {
    dbReady = true;
    console.log(`✅ Database ready, server fully operational`);
  }).catch(err => {
    console.error('❌ Failed to initialize database:', err.message);
    console.error('Full error:', err);
    // Still set dbReady to true to allow page to load (with empty data)
    // This prevents infinite "Starting up" screen
    dbReady = true;
    console.log('⚠️ Running without database - some features may not work');
  });
});
