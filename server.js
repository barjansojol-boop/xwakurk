require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'school.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student','teacher')),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS announcements (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 author_id INTEGER NOT NULL,
 title TEXT NOT NULL,
 body TEXT NOT NULL DEFAULT '',
 audio_file TEXT,
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 FOREIGN KEY(author_id) REFERENCES users(id)
);
`);

app.disable('x-powered-by');
app.use(helmet({
 contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], mediaSrc: ["'self'"], connectSrc: ["'self'"],
  objectSrc: ["'none'"], upgradeInsecureRequests: null
 }}
}));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(session({
 store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
 secret: process.env.SESSION_SECRET || 'development-only-change-me',
 resave: false, saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 12 }
}));
app.use(express.static(path.join(ROOT, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR, { fallthrough: false }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const audioStorage = multer.diskStorage({
 destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
 filename: (_req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname).toLowerCase()}`)
});
const audioUpload = multer({
 storage: audioStorage, limits: { fileSize: 5 * 1024 * 1024, files: 1 },
 fileFilter: (_req, file, cb) => {
  const allowed = ['audio/webm','audio/ogg','audio/mp4','audio/mpeg','audio/wav','audio/x-wav','audio/aac'];
  if (allowed.includes(file.mimetype)) cb(null, true);
  else cb(new Error('Please upload a supported audio recording (WebM, OGG, MP4, MP3, WAV, or AAC).'));
 }
});

function safeUser(user) {
 return user ? { id: user.id, name: user.name, email: user.email, role: user.role } : null;
}
function currentUser(req) {
 if (!req.session.userId) return null;
 return db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(req.session.userId) || null;
}
function requireLogin(req, res, next) {
 const user = currentUser(req);
 if (!user) return res.status(401).json({ error: 'Please log in first.' });
 req.user = user; next();
}
function requireTeacher(req, res, next) {
 const user = currentUser(req);
 if (!user || user.role !== 'teacher') return res.status(403).json({ error: 'Teacher access only.' });
 req.user = user; next();
}
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }

app.get('/api/me', (req, res) => res.json({ user: safeUser(currentUser(req)) }));

app.post('/api/register', authLimiter, async (req, res) => {
 const name = String(req.body.name || '').trim();
 const email = String(req.body.email || '').trim().toLowerCase();
 const password = String(req.body.password || '');
 if (name.length < 2 || name.length > 80) return res.status(400).json({ error: 'Name must be 2–80 characters.' });
 if (!validEmail(email) || email.length > 180) return res.status(400).json({ error: 'Enter a valid email address.' });
 if (password.length < 8 || password.length > 200) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
 try {
  const hash = await bcrypt.hash(password, 12);
  const info = db.prepare("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'student')").run(name, email, hash);
  req.session.userId = Number(info.lastInsertRowid);
  res.status(201).json({ user: safeUser(currentUser(req)), message: 'Registration successful.' });
 } catch (e) {
  if (String(e.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'An account with this email already exists.' });
  console.error(e); res.status(500).json({ error: 'Could not register right now.' });
 }
});

app.post('/api/login', authLimiter, async (req, res) => {
 const email = String(req.body.email || '').trim().toLowerCase();
 const password = String(req.body.password || '');
 const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
 req.session.regenerate(err => {
  if (err) return res.status(500).json({ error: 'Could not start session.' });
  req.session.userId = user.id;
  res.json({ user: safeUser(user), message: 'Welcome back.' });
 });
});

app.post('/api/logout', (req, res) => {
 req.session.destroy(() => res.clearCookie('connect.sid').json({ message: 'Logged out.' }));
});

app.get('/api/teacher-setup-status', (_req, res) => {
 const teacher = db.prepare("SELECT id FROM users WHERE role='teacher' LIMIT 1").get();
 res.json({ setupAvailable: !teacher });
});

app.post('/api/teacher-setup', authLimiter, async (req, res) => {
 const existing = db.prepare("SELECT id FROM users WHERE role='teacher' LIMIT 1").get();
 if (existing) return res.status(403).json({ error: 'Teacher setup is already closed. Ask the school administrator.' });
 const setupCode = process.env.TEACHER_SETUP_CODE;
 if (!setupCode || setupCode.startsWith('change-this')) return res.status(503).json({ error: 'Administrator must configure TEACHER_SETUP_CODE in the environment first.' });
 const name = String(req.body.name || '').trim();
 const email = String(req.body.email || '').trim().toLowerCase();
 const password = String(req.body.password || '');
 if (String(req.body.setupCode || '') !== setupCode) return res.status(403).json({ error: 'Setup code is incorrect.' });
 if (name.length < 2 || name.length > 80 || !validEmail(email) || password.length < 8 || password.length > 200)
  return res.status(400).json({ error: 'Enter a name, valid email, and password of at least 8 characters.' });
 try {
  const hash = await bcrypt.hash(password, 12);
  const info = db.prepare("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'teacher')").run(name,email,hash);
  req.session.userId = Number(info.lastInsertRowid);
  res.status(201).json({ user: safeUser(currentUser(req)), message: 'Teacher account created. Keep your login details private.' });
 } catch (e) {
  if (String(e.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'That email is already registered.' });
  console.error(e); res.status(500).json({ error: 'Could not create teacher account.' });
 }
});

app.get('/api/announcements', (_req, res) => {
 const rows = db.prepare(`SELECT a.id,a.title,a.body,a.audio_file,a.created_at,u.name AS author
 FROM announcements a JOIN users u ON u.id=a.author_id ORDER BY a.id DESC LIMIT 100`).all();
 res.json({ announcements: rows });
});

app.post('/api/announcements', requireTeacher, (req, res, next) => {
 audioUpload.single('audio')(req, res, err => {
  if (err) return res.status(400).json({ error: err.message || 'Audio upload failed.' });
  next();
 });
}, (req, res) => {
 const title = String(req.body.title || '').trim();
 const body = String(req.body.body || '').trim();
 const audioFile = req.file ? `/uploads/${path.basename(req.file.filename)}` : null;
 if (title.length < 2 || title.length > 140) {
  if (req.file) fs.unlink(req.file.path, () => {});
  return res.status(400).json({ error: 'Announcement title must be 2–140 characters.' });
 }
 if (body.length > 5000) {
  if (req.file) fs.unlink(req.file.path, () => {});
  return res.status(400).json({ error: 'Message must be 5,000 characters or fewer.' });
 }
 if (!body && !audioFile) return res.status(400).json({ error: 'Add message text or record/upload a voice message.' });
 const info = db.prepare('INSERT INTO announcements (author_id,title,body,audio_file) VALUES (?,?,?,?)').run(req.user.id,title,body,audioFile);
 const row = db.prepare(`SELECT a.id,a.title,a.body,a.audio_file,a.created_at,u.name AS author FROM announcements a JOIN users u ON u.id=a.author_id WHERE a.id=?`).get(info.lastInsertRowid);
 res.status(201).json({ announcement: row, message: 'Announcement published.' });
});

app.use((err, _req, res, _next) => {
 console.error(err);
 if (res.headersSent) return;
 res.status(500).json({ error: 'Unexpected server error.' });
});

app.listen(PORT, () => console.log(`Xwakurk School website running at http://localhost:${PORT}`));
