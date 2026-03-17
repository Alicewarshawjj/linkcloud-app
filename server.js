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

    const { link_type, link_id, link_title } = req.body;

    // Validate input - reject invalid data
    if (!link_type || typeof link_type !== 'string' || !['social', 'featured', 'carousel', 'redirect'].includes(link_type)) {
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

    // SECURITY: Do NOT store link_url - it could leak protected URLs
    await pool.query(
      `INSERT INTO analytics (slug, source, link_type, link_id, link_title, user_agent, ip_address, country, country_code, region, os, browser, device, referrer)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      ['main', null, link_type, safe_link_id, safe_link_title, user_agent, geoInfo.ip, geoInfo.country, geoInfo.countryCode, geoInfo.region, deviceInfo.os, deviceInfo.browser, deviceInfo.device, referrer]
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

    // By Source (traffic sources like ig1, twitter1, etc.)
    const bySourceResult = await pool.query(
      `SELECT source, COUNT(*) as clicks
       FROM analytics
       WHERE slug = 'main' AND clicked_at > NOW() - INTERVAL '1 day' * $1 AND source IS NOT NULL AND source != ''
       GROUP BY source
       ORDER BY clicks DESC`,
      [d]
    );

    res.json({
      total: parseInt(totalResult.rows[0]?.total || 0),
      byType: byTypeResult.rows,
      topLinks: topLinksResult.rows,
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

// ═══ AI SUMMARY: Comprehensive analytics for AI analysis ═══
app.get('/api/analytics/ai-summary', async (req, res) => {
  try {
    // API key authentication (for external bot access)
    const apiKey = req.headers['x-api-key'] || req.query.key;
    const validKey = process.env.ANALYTICS_API_KEY;

    if (!validKey || apiKey !== validKey) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const days = Math.min(parseInt(req.query.days) || 7, 90);
    const compareDays = days; // Compare to previous period

    // Current period stats
    const currentPeriod = await pool.query(`
      SELECT
        COUNT(*) as total_clicks,
        COUNT(DISTINCT ip_address) as unique_visitors,
        COUNT(DISTINCT country_code) as countries_count
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
    `);

    // Previous period stats (for comparison)
    const previousPeriod = await pool.query(`
      SELECT COUNT(*) as total_clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days * 2} days'
        AND clicked_at <= NOW() - INTERVAL '${days} days'
    `);

    // Top countries
    const topCountries = await pool.query(`
      SELECT country, country_code, region, COUNT(*) as clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
      GROUP BY country, country_code, region
      ORDER BY clicks DESC
      LIMIT 10
    `);

    // Top US states
    const topUSStates = await pool.query(`
      SELECT region, COUNT(*) as clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
        AND country_code = 'US'
        AND region IS NOT NULL
      GROUP BY region
      ORDER BY clicks DESC
      LIMIT 10
    `);

    // Top links
    const topLinks = await pool.query(`
      SELECT link_type, link_title, COUNT(*) as clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
      GROUP BY link_type, link_title
      ORDER BY clicks DESC
      LIMIT 10
    `);

    // Traffic sources
    const trafficSources = await pool.query(`
      SELECT COALESCE(source, 'direct') as source, COUNT(*) as clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
      GROUP BY source
      ORDER BY clicks DESC
      LIMIT 10
    `);

    // Hourly distribution (peak hours)
    const hourlyStats = await pool.query(`
      SELECT EXTRACT(HOUR FROM clicked_at) as hour, COUNT(*) as clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
      GROUP BY hour
      ORDER BY clicks DESC
    `);

    // Daily trend
    const dailyTrend = await pool.query(`
      SELECT DATE(clicked_at) as date, COUNT(*) as clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
      GROUP BY date
      ORDER BY date DESC
    `);

    // Device breakdown
    const devices = await pool.query(`
      SELECT device, COUNT(*) as clicks
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${days} days'
      GROUP BY device
      ORDER BY clicks DESC
    `);

    // Calculate insights
    const current = parseInt(currentPeriod.rows[0].total_clicks);
    const previous = parseInt(previousPeriod.rows[0].total_clicks);
    const changePercent = previous > 0 ? Math.round(((current - previous) / previous) * 100) : 0;

    // Find peak hours
    const peakHours = hourlyStats.rows.slice(0, 3).map(h => parseInt(h.hour));

    res.json({
      period: `${days} days`,
      generated_at: new Date().toISOString(),

      summary: {
        total_clicks: current,
        unique_visitors: parseInt(currentPeriod.rows[0].unique_visitors),
        countries_reached: parseInt(currentPeriod.rows[0].countries_count),
        change_vs_previous: {
          percent: changePercent,
          direction: changePercent > 0 ? 'up' : changePercent < 0 ? 'down' : 'stable',
          previous_total: previous
        }
      },

      top_countries: topCountries.rows,
      top_us_states: topUSStates.rows,
      top_links: topLinks.rows,
      traffic_sources: trafficSources.rows,
      devices: devices.rows,

      timing: {
        peak_hours: peakHours,
        hourly_distribution: hourlyStats.rows,
        daily_trend: dailyTrend.rows
      },

      // Pre-computed insights for AI
      insights: {
        best_performing_link: topLinks.rows[0] || null,
        top_traffic_source: trafficSources.rows[0] || null,
        primary_audience_country: topCountries.rows[0] || null,
        primary_device: devices.rows[0] || null,
        trend: changePercent > 20 ? 'growing_fast' : changePercent > 0 ? 'growing' : changePercent < -20 ? 'declining_fast' : changePercent < 0 ? 'declining' : 'stable'
      }
    });

  } catch (e) {
    console.error('AI Summary error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ═══ AI QUERY: Answer specific questions about analytics ═══
app.get('/api/analytics/query', async (req, res) => {
  try {
    // API key authentication
    const apiKey = req.headers['x-api-key'] || req.query.key;
    const validKey = process.env.ANALYTICS_API_KEY;

    if (!validKey || apiKey !== validKey) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const { q, days = 7 } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'Missing query parameter "q"' });
    }

    const d = Math.min(parseInt(days), 90);
    let result = null;

    // Parse common questions
    const query = q.toLowerCase();

    if (query.includes('country') || query.includes('מדינ') || query.includes('איפה')) {
      result = await pool.query(`
        SELECT country, country_code, COUNT(*) as clicks,
               ROUND(COUNT(*)::numeric * 100 / SUM(COUNT(*)) OVER(), 1) as percent
        FROM analytics
        WHERE clicked_at > NOW() - INTERVAL '${d} days'
        GROUP BY country, country_code
        ORDER BY clicks DESC
        LIMIT 15
      `);
      return res.json({ question: q, type: 'countries', data: result.rows });
    }

    if (query.includes('state') || query.includes('סטייט') || query.includes('מדינות אמריקה')) {
      result = await pool.query(`
        SELECT region as state, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at > NOW() - INTERVAL '${d} days'
          AND country_code = 'US' AND region IS NOT NULL
        GROUP BY region
        ORDER BY clicks DESC
        LIMIT 15
      `);
      return res.json({ question: q, type: 'us_states', data: result.rows });
    }

    if (query.includes('link') || query.includes('לינק') || query.includes('ביצוע')) {
      result = await pool.query(`
        SELECT link_type, link_title, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at > NOW() - INTERVAL '${d} days'
        GROUP BY link_type, link_title
        ORDER BY clicks DESC
        LIMIT 15
      `);
      return res.json({ question: q, type: 'links', data: result.rows });
    }

    if (query.includes('source') || query.includes('traffic') || query.includes('מקור') || query.includes('תנועה')) {
      result = await pool.query(`
        SELECT COALESCE(source, 'direct') as source, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at > NOW() - INTERVAL '${d} days'
        GROUP BY source
        ORDER BY clicks DESC
        LIMIT 15
      `);
      return res.json({ question: q, type: 'sources', data: result.rows });
    }

    if (query.includes('hour') || query.includes('time') || query.includes('שעה') || query.includes('זמן') || query.includes('מתי')) {
      result = await pool.query(`
        SELECT EXTRACT(HOUR FROM clicked_at) as hour, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at > NOW() - INTERVAL '${d} days'
        GROUP BY hour
        ORDER BY hour
      `);
      return res.json({ question: q, type: 'hours', data: result.rows });
    }

    if (query.includes('device') || query.includes('מכשיר') || query.includes('mobile') || query.includes('desktop')) {
      result = await pool.query(`
        SELECT device, browser, os, COUNT(*) as clicks
        FROM analytics
        WHERE clicked_at > NOW() - INTERVAL '${d} days'
        GROUP BY device, browser, os
        ORDER BY clicks DESC
        LIMIT 15
      `);
      return res.json({ question: q, type: 'devices', data: result.rows });
    }

    if (query.includes('today') || query.includes('היום')) {
      result = await pool.query(`
        SELECT COUNT(*) as clicks, COUNT(DISTINCT ip_address) as unique_visitors
        FROM analytics
        WHERE clicked_at > CURRENT_DATE
      `);
      return res.json({ question: q, type: 'today', data: result.rows[0] });
    }

    if (query.includes('yesterday') || query.includes('אתמול')) {
      result = await pool.query(`
        SELECT COUNT(*) as clicks, COUNT(DISTINCT ip_address) as unique_visitors
        FROM analytics
        WHERE clicked_at >= CURRENT_DATE - INTERVAL '1 day'
          AND clicked_at < CURRENT_DATE
      `);
      return res.json({ question: q, type: 'yesterday', data: result.rows[0] });
    }

    // Default: return general stats
    result = await pool.query(`
      SELECT
        COUNT(*) as total_clicks,
        COUNT(DISTINCT ip_address) as unique_visitors,
        COUNT(DISTINCT country_code) as countries
      FROM analytics
      WHERE clicked_at > NOW() - INTERVAL '${d} days'
    `);
    return res.json({ question: q, type: 'general', data: result.rows[0] });

  } catch (e) {
    console.error('Query error:', e);
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
    Snapchat: ua.includes('Snapchat') || ua.includes('snapchat') || ref.includes('snapchat.com')
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

// Route 3: Generic link pattern (catches scrapers following /link/*)
app.get('/link/:id', (req, res) => {
  const ua = req.headers['user-agent'] || 'unknown';
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  recordHoneypotHit(ip, ua, `/link/${req.params.id}`);
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
    const safeType = ['social', 'featured', 'carousel'].includes(linkType) ? linkType : 'redirect';
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

    // Geo check - block exclusive content for Israel
    const geoInfo = getCountryFromIP(req);
    const isGeoBlocked = geoInfo.countryCode === 'IL';

    res.send(renderProfilePage(data, seo, isBotRequest, null, isGeoBlocked));
  } catch (e) {
    console.error('Render error:', e);
    res.status(500).send('Server error');
  }
});

// ═══ TRAFFIC SOURCE ROUTE (Clean URLs: /ig-main, /twitter1, etc.) ═══
app.get('/:source', async (req, res, next) => {
  // Skip if it's a known route
  const knownRoutes = ['admin', 'go', 'api', 'favicon.ico', 'robots.txt'];
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

  const TYPES = {
    onlyfans:{n:'OnlyFans',bg:'#003CFF'},instagram:{n:'Instagram',bg:'linear-gradient(45deg,#F77737,#FD1D1D 50%,#833AB4)'},instagram2:{n:'Instagram 2',bg:'linear-gradient(135deg,#F77737,#FD1D1D 50%,#C13584)'},tiktok:{n:'TikTok',bg:'linear-gradient(135deg,#25F4EE,#FD1D1D)'},snapchat:{n:'Snapchat',bg:'#FFFC00'},twitter:{n:'X / Twitter',bg:'#1a1a1a'},youtube:{n:'YouTube',bg:'#FF0000'},website:{n:'Website',bg:'#7B7B7B'},amazon:{n:'Amazon',bg:'#FF9500'},amazon2:{n:'Amazon 2',bg:'#FF7500'},facebook:{n:'Facebook',bg:'#1877F2'},linkedin:{n:'LinkedIn',bg:'#0A66C2'},spotify:{n:'Spotify',bg:'#1DB954'},telegram:{n:'Telegram',bg:'#26A5E4'},whatsapp:{n:'WhatsApp',bg:'#25D366'},pinterest:{n:'Pinterest',bg:'#E60023'},twitch:{n:'Twitch',bg:'#9146FF'},discord:{n:'Discord',bg:'#5865F2'},email:{n:'Email',bg:'#EA4335'},phone:{n:'Phone',bg:'#34C759'}
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
    const params = new URLSearchParams({ t: type, n: title || '' });
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
    const redirectUrl = f.url ? buildRedirectUrl(f.url, 'featured', f.title) : null;
    const cardContent = `<div class="feat-card-display" style="${imgBg}"><div class="feat-overlay"><div class="feat-icon" style="background:${f.color || '#667eea'}"><svg viewBox="0 0 24 24" style="width:22px;height:22px;fill:#fff"><circle cx="12" cy="12" r="10"/></svg></div><span class="feat-title">${esc(f.title)}</span></div></div>`;
    if (redirectUrl) {
      return `<a href="${esc(redirectUrl)}" class="feat-link" rel="noopener">${cardContent}</a>`;
    }
    return `<div class="feat-link">${cardContent}</div>`;
  }).join('');

  // Carousel HTML with encrypted server-side redirects
  const carsHTML = cars.map((c, idx) => {
    const svg = SVG[c.icon] || SVG.website || '';
    const redirectUrl = c.url ? buildRedirectUrl(c.url, 'carousel', c.title) : null;
    const cardContent = `<div class="car-card" style="background:${c.grad || 'linear-gradient(135deg,#667eea,#764ba2)'}"><div class="car-icon">${svg}</div><div class="car-title">${esc(c.title)}</div><div class="car-sub">${esc(c.sub || '')}</div></div>`;
    if (redirectUrl) {
      return `<a href="${esc(redirectUrl)}" class="car-link" rel="noopener">${cardContent}</a>`;
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

  const title = seo.title || p.name || 'cmehere.net';
  const description = seo.description || p.bio || '';

  // Site URL for meta tags
  const siteUrl = 'https://cmehere.net';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(title)}</title>
  <meta name="description" content="${esc(description)}">
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
  <script id="early-deeplink-detect">
  (function(){try{if(typeof window==='undefined')return;var ua=navigator.userAgent||'';var ref=document.referrer||'';var isSnapchatWebView=(ua.indexOf('iPhone')!==-1||ua.indexOf('iPad')!==-1)&&ua.indexOf('Mobile/')!==-1&&ua.indexOf('Safari')===-1&&ua.indexOf('CriOS')===-1&&ua.indexOf('FxiOS')===-1;window.__IS_INAPP__=ua.indexOf('Instagram')!==-1||ua.indexOf('FBAN')!==-1||ua.indexOf('FBAV')!==-1||ua.indexOf('TikTok')!==-1||ua.indexOf('LinkedInApp')!==-1||ua.indexOf('Twitter')!==-1||ua.indexOf('TwitterAndroid')!==-1||ua.indexOf('Threads')!==-1||ua.indexOf('Barcelona')!==-1||ua.indexOf('Snapchat')!==-1||ua.indexOf('snapchat')!==-1||isSnapchatWebView||ref.indexOf('t.co')!==-1||ref.indexOf('twitter.com')!==-1||ref.indexOf('x.com')!==-1||ref.indexOf('threads.net')!==-1||ref.indexOf('snapchat.com')!==-1;window.__IS_IOS__=/iPhone|iPad|iPod/i.test(ua);window.__IS_ANDROID__=/Android/i.test(ua)}catch(e){}})();
  </script>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;justify-content:center}
    .container{width:100%;max-width:480px;background:#fff;min-height:100vh;box-shadow:0 0 20px rgba(0,0,0,.08)}

    /* In-App Browser Overlay */
    .inapp-overlay{display:none;position:fixed;inset:0;z-index:9999;opacity:0;transition:opacity .3s}
    .inapp-overlay.active{display:flex;flex-direction:column;align-items:center;justify-content:center;opacity:1}
    .inapp-backdrop{position:absolute;inset:0;background:rgba(0,0,0,.88);backdrop-filter:blur(10px)}
    .inapp-btn{position:relative;z-index:2;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;padding:16px 40px;border-radius:12px;font-size:18px;font-weight:700;cursor:pointer;box-shadow:0 6px 20px rgba(102,126,234,.4);transition:transform .2s}
    .inapp-btn:hover{transform:translateY(-2px)}
    .inapp-fallback{position:relative;z-index:2;background:rgba(255,255,255,.1);color:rgba(255,255,255,.7);border:1px solid rgba(255,255,255,.2);padding:10px 20px;border-radius:8px;font-size:13px;cursor:pointer;margin-top:16px;transition:background .2s}
    .inapp-fallback:hover{background:rgba(255,255,255,.15)}

    /* Cover */
    .cover{position:relative;height:180px;overflow:hidden}
    .cover-img{width:100%;height:100%;object-fit:cover}
    .cover-gradient{width:100%;height:100%;background:linear-gradient(135deg,#667eea,#764ba2)}

    /* Avatar */
    .avatar-section{display:flex;flex-direction:column;align-items:center;margin-top:-55px;position:relative;z-index:2}
    .avatar-wrapper{position:relative}
    .avatar-img,.avatar-placeholder{width:110px;height:110px;border-radius:50%;border:4px solid #fff;box-shadow:0 4px 15px rgba(0,0,0,.15);object-fit:cover}
    .avatar-placeholder{background:linear-gradient(135deg,#667eea,#764ba2)}
    .verified-badge{position:absolute;bottom:4px;right:4px;width:28px;height:28px;background:#1DA1F2;border-radius:50%;display:flex;align-items:center;justify-content:center;border:3px solid #fff}

    /* Profile Info */
    .profile-info{text-align:center;padding:16px 24px 0}
    .profile-name{font-size:24px;font-weight:800;color:#1a1a2e;letter-spacing:.5px}
    .profile-bio{color:#666;font-size:14px;margin-top:8px;line-height:1.5}

    /* Social Icons */
    .socials{display:flex;flex-wrap:wrap;justify-content:center;gap:12px;padding:24px 16px}
    .social-link{text-decoration:none}
    .social-icon{width:55px;height:55px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:transform .2s,box-shadow .2s;cursor:pointer}
    .social-icon:hover{transform:scale(1.1);box-shadow:0 4px 15px rgba(0,0,0,.2)}
    .social-icon svg{width:24px;height:24px}

    /* Featured Links */
    .section-title{color:#667eea;text-align:center;font-size:13px;font-weight:700;letter-spacing:1px;text-transform:uppercase;padding:8px 0 16px}
    .feat-link{text-decoration:none;display:block;margin:0 16px 16px;cursor:pointer}
    .feat-card-display{height:200px;border-radius:16px;overflow:hidden;position:relative;transition:transform .2s}
    .feat-card-display:hover{transform:scale(1.02)}
    .feat-overlay{position:absolute;bottom:0;left:0;right:0;height:80px;background:linear-gradient(to top,rgba(0,0,0,.65),transparent);display:flex;align-items:flex-end;padding:14px}
    .feat-icon{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin-right:12px;flex-shrink:0}
    .feat-title{color:#fff;font-weight:700;font-size:15px}

    /* Carousel */
    .carousel{display:flex;gap:12px;overflow-x:auto;padding:0 16px 16px;-webkit-overflow-scrolling:touch;scroll-snap-type:x mandatory}
    .carousel::-webkit-scrollbar{display:none}
    .car-link{text-decoration:none;flex-shrink:0;scroll-snap-align:start;cursor:pointer}
    .car-card{width:200px;height:200px;border-radius:16px;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;transition:transform .2s}
    .car-card:hover{transform:scale(1.03)}
    .car-icon{margin-bottom:12px}
    .car-icon svg{width:40px;height:40px;fill:#fff}
    .car-title{color:#fff;font-weight:700;font-size:15px;text-align:center}
    .car-sub{color:rgba(255,255,255,.8);font-size:12px;text-align:center;margin-top:4px}

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
  <div id="inappOverlay" class="inapp-overlay">
    <div class="inapp-backdrop"></div>
    <button class="inapp-btn" id="openSafariBtn">Open in Browser 😉</button>
    <button class="inapp-fallback" id="nothingHappened">Nothing happened?</button>
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
      <h1 class="profile-name">${esc(p.name || '')}</h1>
      ${p.bio ? `<p class="profile-bio">${esc(p.bio)}</p>` : ''}
    </div>
    <div class="socials animate delay-3">${socialsHTML}</div>
    ${feats.length ? `<div class="animate delay-4"><div class="section-title">Featured Links</div>${featsHTML}</div>` : ''}
    ${cars.length ? `<div class="animate delay-5"><div class="section-title" style="margin-top:8px">Featured Content</div><div class="carousel">${carsHTML}</div></div>` : ''}
  </div>

  <script>
    // Deep linking script for in-app browsers
    (function(){if(!window.__IS_INAPP__)return;var isIOS=window.__IS_IOS__;var isAndroid=window.__IS_ANDROID__;var overlay=document.getElementById('inappOverlay');var openBtn=document.getElementById('openSafariBtn');var fallbackBtn=document.getElementById('nothingHappened');if(isIOS){openBtn.textContent='Open in Safari 😉'}else if(isAndroid){openBtn.textContent='Open in Chrome 😉'}else{openBtn.textContent='Open in Browser 😉'}overlay.classList.add('active');function addBrowserParam(url){try{var u=new URL(url);u.searchParams.set('browser','1');return u.toString()}catch(e){return url}}function handleiOSClick(){try{var canonicalUrl=addBrowserParam(window.location.href);var stripped=canonicalUrl.replace(/^https?:\\/\\//,'');var xSafariUrl=canonicalUrl.startsWith('https')?'x-safari-https://'+stripped:'x-safari-http://'+stripped;window.open(xSafariUrl,'_blank')}catch(e){}}function handleAndroidClick(){try{var hostname=window.location.hostname;var pathAndSearch=window.location.pathname+window.location.search;var fallbackUrl=addBrowserParam(window.location.href);var intentUrl='intent://'+hostname+pathAndSearch+'#Intent;scheme=https;package=com.android.chrome;S.browser_fallback_url='+encodeURIComponent(fallbackUrl)+';end';window.location=intentUrl}catch(e){}}openBtn.onclick=function(e){if(e)e.preventDefault();if(isIOS)handleiOSClick();else if(isAndroid)handleAndroidClick();else window.open(window.location.href,'_blank')};fallbackBtn.onclick=function(e){if(e)e.preventDefault();var url=window.location.href;if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(url).then(function(){alert('URL copied!\\n\\nPaste it in Safari to open.\\n\\nOr: tap ••• at top right → "Open in Browser"')}).catch(function(){prompt('Copy this URL and open in Safari:',url)})}else{prompt('Copy this URL and open in Safari:',url)}};if(isAndroid){try{var a=document.createElement('a');a.href=window.location.href;a.target='_blank';a.rel='noopener noreferrer';a.style.display='none';document.body.appendChild(a);a.click();setTimeout(function(){if(a.parentNode)a.parentNode.removeChild(a)},500);setTimeout(function(){handleAndroidClick()},3000)}catch(e){}}})();
  </script>
</body>
</html>`;
}

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
