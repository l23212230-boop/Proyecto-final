const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DATA_FILE = path.join(__dirname, 'data.json');
const USERS_FILE = path.join(__dirname, 'users.json');

// Registration codes (for prototyping). In production keep these secret or generate per-invite.
// Available roles: admin, investigador, observador, empresa
const REG_CODES = {
	admin: process.env.REG_CODE_ADMIN || 'ADMIN123',
	investigador: process.env.REG_CODE_INVESTIGADOR || 'INVEST123',
	observador: process.env.REG_CODE_OBSERVADOR || 'OBSERV123',
	empresa: process.env.REG_CODE_EMPRESA || 'EMPRESA123'
};

if (!fs.existsSync(UPLOAD_DIR)) {
	fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Initialize simple JSON store for metadata and users
function readJSON(file, defaultValue) {
	try {
		if (!fs.existsSync(file)) return defaultValue;
		const raw = fs.readFileSync(file, 'utf8');
		return JSON.parse(raw || 'null') || defaultValue;
	} catch (e) {
		return defaultValue;
	}
}
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

let data = readJSON(DATA_FILE, { files: [] });
let users = readJSON(USERS_FILE, null);

// Seed default users if not present
if (!users) {
	// Seed with representative roles for testing
	users = [
		{ username: 'admin', password: bcrypt.hashSync('admin', 10), role: 'admin' },
		{ username: 'moderator', password: bcrypt.hashSync('moderator', 10), role: 'investigador' },
		{ username: 'client', password: bcrypt.hashSync('client', 10), role: 'observador' }
	];
	writeJSON(USERS_FILE, users);
}

// Multer storage: keep original name but prefix with timestamp to avoid collisions
const storage = multer.diskStorage({
	destination: (req, file, cb) => cb(null, UPLOAD_DIR),
	filename: (req, file, cb) => {
		const safeName = file.originalname.replace(/\s+/g, '_');
		cb(null, Date.now() + '-' + safeName);
	}
});

const upload = multer({ storage });

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
	secret: process.env.SESSION_SECRET || 'keyboard cat',
	resave: false,
	saveUninitialized: false,
	cookie: { maxAge: 1000 * 60 * 60 * 4 }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Auth helpers
function findUser(username) { return users.find(u => u.username === username); }
function ensureAuth(req, res, next) {
	if (req.session && req.session.user) return next();
	return res.status(401).json({ error: 'Unauthorized' });
}
function ensureRole(role) {
	return (req, res, next) => {
		if (!req.session || !req.session.user) return res.status(401).json({ error: 'Unauthorized' });
		if (req.session.user.role === role || req.session.user.role === 'admin') return next();
		return res.status(403).json({ error: 'Forbidden' });
	};
}

// Login
app.post('/login', (req, res) => {
	const { username, password } = req.body;
	if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
	const user = findUser(username);
	if (!user) return res.status(401).json({ error: 'Invalid credentials' });
	if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
 req.session.user = { username: user.username, role: user.role, email: user.email || null, companyName: user.companyName || null };
 res.json({ ok: true, user: req.session.user });
});

// Register new user using a registration code. Body: { username, password, code, email, companyName? }
app.post('/register', (req, res) => {
 const { username, password, code, email, companyName } = req.body;
 if (!username || !password || !code || !email) return res.status(400).json({ error: 'Missing fields (username, password, email, code required)' });
 // username uniqueness
 if (findUser(username)) return res.status(409).json({ error: 'Username already exists' });
 // determine role from code
 let role = null;
 if (code === REG_CODES.admin) role = 'admin';
 else if (code === REG_CODES.investigador) role = 'investigador';
 else if (code === REG_CODES.observador) role = 'observador';
 else if (code === REG_CODES.empresa) role = 'empresa';
 else return res.status(400).json({ error: 'Invalid registration code' });

 if (role === 'empresa' && !companyName) return res.status(400).json({ error: 'companyName is required for empresa accounts' });

 const hashed = bcrypt.hashSync(password, 10);
 const newUser = { username, password: hashed, role, email, companyName: companyName || null };
 users.push(newUser);
 writeJSON(USERS_FILE, users);
 // auto-login after registration
 req.session.user = { username: newUser.username, role: newUser.role, email: newUser.email, companyName: newUser.companyName };
 res.json({ ok: true, user: req.session.user });
});

app.post('/logout', (req, res) => {
	req.session.destroy(() => res.json({ ok: true }));
});

app.get('/me', (req, res) => {
	res.json({ user: req.session.user || null });
});

// Allow admin to retrieve current registration codes (so admin can distribuirlos).
app.get('/codes', ensureAuth, (req, res) => {
	if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
	// Return codes (in real app don't expose admin code casually)
	res.json({ codes: REG_CODES });
});

// Public codes endpoint: returns non-admin codes suitable for showing on a public register page.
app.get('/public-codes', (req, res) => {
	// Expose all codes (including admin) as requested. WARNING: sensitive in real apps.
	res.json({ codes: {
		admin: REG_CODES.admin,
		investigador: REG_CODES.investigador,
		observador: REG_CODES.observador,
		empresa: REG_CODES.empresa
	}});
});

// Upload endpoint: admins and investigadores can upload
app.post('/upload', ensureAuth, (req, res, next) => {
	const role = req.session.user && req.session.user.role;
	if (role !== 'admin' && role !== 'investigador') return res.status(403).json({ error: 'Only admins or investigadores can upload' });
	next();
}, upload.single('file'), (req, res) => {
	if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
	const uploaderUser = findUser(req.session.user.username) || {};
	// accept optional category from the upload form
	const category = (req.body && req.body.category) ? String(req.body.category).trim() : null;
	const entry = {
		filename: req.file.filename,
		originalName: req.file.originalname,
		uploader: req.session.user.username,
		uploaderRole: req.session.user.role,
		uploaderEmail: uploaderUser.email || null,
		category: category,
		uploadedAt: new Date().toISOString()
	};
	data.files.unshift(entry);
	writeJSON(DATA_FILE, data);
	res.json({ ok: true, file: entry });
});

// List files metadata
app.get('/files', (req, res) => {
	const user = req.session && req.session.user;
	// Helpers to create sanitized views
	const baseView = (f) => ({ originalName: f.originalName, uploader: f.uploader, uploaderRole: f.uploaderRole, filename: f.filename, uploadedAt: f.uploadedAt });
	if (!user) {
		// anonymous: do not expose uploaderEmail
		return res.json(data.files.map(baseView));
	}
	if (user.role === 'empresa') {
		// For company users, include investigator email for investigator-uploaded files
		const list = data.files.map(f => {
			const uploaderUser = findUser(f.uploader) || {};
			const item = baseView(f);
			item.uploaderEmail = (f.uploaderRole === 'investigador') ? (uploaderUser.email || f.uploaderEmail || null) : null;
			return item;
		});
		return res.json(list);
	}
	if (user.role === 'observador') {
		// Observers can see files but not personal emails
		return res.json(data.files.map(baseView));
	}
	// Admins and investigadores see full metadata (including uploaderEmail if present)
	return res.json(data.files.map(f => ({ ...f })));
});

// Serve uploaded files
app.get('/files/:name', (req, res) => {
	const name = req.params.name;
	// Prevent path traversal by resolving and ensuring it's inside UPLOAD_DIR
	const filePath = path.join(UPLOAD_DIR, name);
	const resolved = path.resolve(filePath);
	const uploadDirResolved = path.resolve(UPLOAD_DIR);
	if (!resolved.startsWith(uploadDirResolved + path.sep) && resolved !== uploadDirResolved) {
		return res.status(400).send('Invalid file path');
	}
	if (!fs.existsSync(resolved)) return res.status(404).send('File not found');
	// Prefer inline disposition so browsers try to render PDFs/images instead of forcing download
	try {
		const ext = (path.extname(resolved) || '').toLowerCase();
		// set inline disposition for common viewable types (pdf, png, jpg, jpeg, gif, svg, txt)
		const inlineExts = ['.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.txt', '.html'];
		if (inlineExts.includes(ext)) {
			res.setHeader('Content-Disposition', `inline; filename="${path.basename(resolved)}"`);
		} else {
			// for other types, keep default (browser may download)
			res.setHeader('Content-Disposition', `attachment; filename="${path.basename(resolved)}"`);
		}
	} catch (e) {
		// ignore header errors
	}
	res.sendFile(resolved);
});

// Delete file: only admins can delete files
app.delete('/files/:name', ensureAuth, (req, res) => {
	const name = req.params.name;
	const user = req.session.user;
	if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Only admins can delete files' });
	const idx = data.files.findIndex(f => f.filename === name);
	if (idx === -1) return res.status(404).json({ error: 'Not found' });
	// delete file from disk
	const filePath = path.join(UPLOAD_DIR, name);
	try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) {}
	data.files.splice(idx, 1);
	writeJSON(DATA_FILE, data);
	res.json({ ok: true });
});

// Admin: list users (safe fields)
app.get('/users', ensureAuth, (req, res) => {
	if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
	const list = users.map(u => ({ username: u.username, role: u.role, email: u.email || null, companyName: u.companyName || null }));
	res.json(list);
});

// Admin: delete a user and optionally their files
app.delete('/users/:username', ensureAuth, (req, res) => {
	if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
	const uname = req.params.username;
	const uidx = users.findIndex(u => u.username === uname);
	if (uidx === -1) return res.status(404).json({ error: 'User not found' });
	// remove user's files
	const toRemove = data.files.filter(f => f.uploader === uname).map(f => f.filename);
	toRemove.forEach(fn => {
		const p = path.join(UPLOAD_DIR, fn);
		try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch (e) {}
	});
	data.files = data.files.filter(f => f.uploader !== uname);
	users.splice(uidx, 1);
	writeJSON(DATA_FILE, data);
	writeJSON(USERS_FILE, users);
	res.json({ ok: true });
});

// Simple viewer page for embedding PDFs (and linking other types)
app.get('/view', (req, res) => {
	const file = req.query.file;
	if (!file) return res.status(400).send('Missing file parameter');
	res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

app.listen(PORT, () => {
	console.log(`Server listening on http://localhost:${PORT}`);
});
