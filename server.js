'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Optional .env reader, implemented without third-party packages.
function loadEnvFile() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || Object.prototype.hasOwnProperty.call(process.env, match[1])) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[match[1]] = value;
  }
}
loadEnvFile();

const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const VERSION = '1.0.0';
const API_KEYS = new Set((process.env.API_KEYS || '').split(',').map((v) => v.trim()).filter(Boolean));
const SIGNING_SECRET = process.env.SIGNING_SECRET || '';
const REQUIRE_SIGNATURE = process.env.REQUIRE_SIGNATURE === 'true';
const PAYLOAD_FILE = path.resolve(__dirname, process.env.PAYLOAD_FILE || './protected/payload.txt');
const BINDINGS_FILE = path.join(__dirname, 'data', 'bindings.json');
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map((v) => v.trim()).filter(Boolean);
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('PORT is not valid.');
if (REQUIRE_SIGNATURE && !SIGNING_SECRET) throw new Error('SIGNING_SECRET is required when REQUIRE_SIGNATURE is true.');
if (API_KEYS.size === 0) console.warn('[Moonslot] API_KEYS is not set: the private resource will stay closed.');

const requestCounts = new Map();
const failedAttempts = new Map();
const MAX_REQUESTS_PER_WINDOW = 100;
const RATE_WINDOW_MS = 60_000;
const MAX_FAILURES = 10;
const BLOCK_DURATION_MS = 30 * 60_000;
let bindings = {};

try {
  const parsed = JSON.parse(fs.readFileSync(BINDINGS_FILE, 'utf8'));
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) bindings = parsed;
} catch (error) {
  if (error.code !== 'ENOENT') console.error('[Moonslot] Could not load access bindings.');
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}
function json(res, code, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
}
function digest(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function saveBindings() {
  try {
    fs.mkdirSync(path.dirname(BINDINGS_FILE), { recursive: true });
    const temp = `${BINDINGS_FILE}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(bindings, null, 2), { mode: 0o600 });
    fs.renameSync(temp, BINDINGS_FILE);
  } catch (error) {
    console.error('[Moonslot] Could not save access bindings.');
  }
}
function isBlocked(ip) {
  const record = failedAttempts.get(ip);
  if (!record) return false;
  if (record.blockedUntil <= Date.now()) { failedAttempts.delete(ip); return false; }
  return true;
}
function rejectPrivate(ip, res) {
  const record = failedAttempts.get(ip) || { count: 0, blockedUntil: 0 };
  record.count += 1;
  if (record.count >= MAX_FAILURES) { record.count = 0; record.blockedUntil = Date.now() + BLOCK_DURATION_MS; }
  failedAttempts.set(ip, record);
  json(res, 404, { error: 'Resource not found.' });
}
function privateAccess(req, res, pathname, ip) {
  if (isBlocked(ip)) { json(res, 404, { error: 'Resource not found.' }); return false; }
  const apiKey = req.headers['x-api-key'] || '';
  const deviceId = req.headers['x-hwid'] || '';
  if (!API_KEYS.has(apiKey) || !/^[A-Za-z0-9_-]{8,128}$/.test(deviceId)) {
    rejectPrivate(ip, res); return false;
  }
  if (REQUIRE_SIGNATURE) {
    const timestamp = Number.parseInt(req.headers['x-ts'] || '', 10);
    const signature = req.headers['x-sig'] || '';
    if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > 30_000) {
      rejectPrivate(ip, res); return false;
    }
    const expected = crypto.createHmac('sha256', SIGNING_SECRET)
      .update(`${apiKey}.${timestamp}.${deviceId}.${pathname}`).digest('hex');
    if (!safeEqual(signature, expected)) { rejectPrivate(ip, res); return false; }
  }
  const keyId = digest(apiKey);
  const deviceDigest = digest(deviceId);
  if (!bindings[keyId]) { bindings[keyId] = deviceDigest; saveBindings(); }
  else if (!safeEqual(bindings[keyId], deviceDigest)) { rejectPrivate(ip, res); return false; }
  failedAttempts.delete(ip);
  return true;
}
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8'
};
function serveStatic(req, res, pathname) {
  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.resolve(PUBLIC_DIR, relative);
  if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) return false;
  const type = MIME[path.extname(file).toLowerCase()];
  if (!type) return false;
  fs.readFile(file, (error, content) => {
    if (error) return json(res, 404, { error: 'Resource not found.' });
    res.writeHead(200, {
      'Content-Type': type,
      'Content-Length': content.length,
      'Cache-Control': file.endsWith('.html') ? 'no-store' : 'no-cache'
    });
    res.end(req.method === 'HEAD' ? undefined : content);
  });
  return true;
}
function handle(req, res) {
  const ip = clientIp(req);
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.length && !ALLOWED_ORIGINS.includes(origin)) {
    json(res, 403, { error: 'Origin not allowed.' }); return;
  }
  if (origin && ALLOWED_ORIGINS.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  const rate = requestCounts.get(ip) || { count: 0, expires: Date.now() + RATE_WINDOW_MS };
  if (rate.expires <= Date.now()) { rate.count = 0; rate.expires = Date.now() + RATE_WINDOW_MS; }
  rate.count += 1;
  requestCounts.set(ip, rate);
  if (rate.count > MAX_REQUESTS_PER_WINDOW) { json(res, 429, { error: 'Too many requests. Try again later.' }); return; }

  if (req.method !== 'GET' && req.method !== 'HEAD') { json(res, 405, { error: 'Method not allowed.' }); return; }
  const url = new URL(req.url, 'http://localhost');
  const pathname = decodeURIComponent(url.pathname);

  if (pathname === '/health') { json(res, 200, { status: 'healthy' }); return; }
  if (pathname === '/status') { json(res, 200, { service: 'Moonslot', status: 'online', version: VERSION, timestamp: new Date().toISOString() }); return; }
  if (pathname === '/api') { json(res, 200, { name: 'Moonslot', version: VERSION, status: 'online' }); return; }
  if (pathname === '/info') { json(res, 200, { service: 'Moonslot', message: 'Service available.' }); return; }
  if (pathname === '/v1/load') {
    if (!privateAccess(req, res, pathname, ip)) return;
    fs.readFile(PAYLOAD_FILE, 'utf8', (error, contents) => {
      if (error) { json(res, 503, { error: 'Resource temporarily unavailable.' }); return; }
      const body = Buffer.from(contents, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store, max-age=0' });
      res.end(req.method === 'HEAD' ? undefined : body);
    });
    return;
  }
  if (serveStatic(req, res, pathname)) return;
  json(res, 404, { error: 'Resource not found.' });
}

const server = http.createServer((req, res) => {
  try { handle(req, res); }
  catch (error) {
    console.error('[Moonslot] Internal error:', error.message);
    if (!res.headersSent) json(res, 500, { error: 'Internal server error.' });
    else res.destroy();
  }
});
server.listen(PORT, () => console.log(`[Moonslot] Service started on port ${PORT}.`));
const cleanup = setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of requestCounts) if (record.expires <= now) requestCounts.delete(ip);
  for (const [ip, record] of failedAttempts) if (record.blockedUntil && record.blockedUntil <= now && record.count === 0) failedAttempts.delete(ip);
}, RATE_WINDOW_MS);
cleanup.unref();
function shutdown(signal) {
  console.log(`[Moonslot] ${signal} received; shutting down.`);
  clearInterval(cleanup);
  server.close(() => process.exit(0));
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
