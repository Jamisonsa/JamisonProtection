// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const User = require('./user');

const app = express();
const PORT = process.env.PORT || 4000;
const isProduction = process.env.NODE_ENV === 'production';

// ────── TRUST PROXY (needed for Render HTTPS + cookies) ──────
app.set('trust proxy', 1);

// ────── CORS (frontend origins allowed) ──────
app.use(
    cors({
        origin: [
            'http://localhost:4000',         // local express serve
            'http://127.0.0.1:5500',         // VSCode live server
            'http://localhost:5500',
            'https://jamisonprotection.onrender.com', // Render deployment
        ],
        credentials: true,
    })
);

// ────── SESSION SETUP ──────
// In production → Secure cookies + cross-site allowed
// In dev → regular localhost cookies
const FileStore = require('session-file-store')(session);
app.use(
    session({
        store: new FileStore({ path: './sessions', retries: 1 }),
        secret: 'jamison-secret-key',
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 1000 * 60 * 60 * 2
        }
    })
);


// ────── LOGGING MIDDLEWARE (for debugging) ──────
app.use((req, _res, next) => {
    console.log(
        '📩', req.method, req.url,
        '| cookie:', req.headers.cookie,
        '| sessionID:', req.sessionID,
        '| user:', req.session.user
    );
    next();
});

// ────── STATIC FILES ──────
app.use(express.static(path.join(__dirname)));

// ────── BODY PARSING ──────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ────── DATABASE CONNECTION ──────
mongoose
    .connect(process.env.MONGO_URI || 'mongodb://localhost/jamison-protection', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log('✅ MongoDB connected'))
    .catch((err) => console.error('MongoDB connection error:', err));

// ────── SCHEMAS ──────
const Shift = mongoose.model(
    'Shift',
    new mongoose.Schema({
        date: String,
        time: String,
        location: String,
        notes: String,
        claimedBy: String,
    })
);

const Log = mongoose.model(
    'Log',
    new mongoose.Schema({
        username: String,
        date: String,
        hours: Number,
        description: String,
    })
);

// ────── SEED DEFAULT USERS (only if none exist) ──────
async function seedUsers() {
    const existing = await User.find();
    if (existing.length === 0) {
        const defaults = [
            { username: 'owner', password: 'ownerpass', role: 'owner' },
            { username: 'worker1', password: 'pass1', role: 'worker' },
            { username: 'worker2', password: 'pass2', role: 'worker' },
        ];
        await User.insertMany(defaults);
        console.log('✅ Seeded default users');
    }
}
seedUsers();

// ────── MIDDLEWARE HELPERS ──────
function requireLogin(req, res, next) {
    if (req.session && req.session.user) return next();
    return res.status(401).json({ message: 'Not logged in' });
}

function isOwner(req, res, next) {
    if (req.session && req.session.role === 'owner') return next();
    return res.status(403).json({ message: 'Owner access only' });
}

function isWorker(req, res, next) {
    if (req.session && req.session.role === 'worker') return next();
    return res.status(403).json({ message: 'Worker access only' });
}

// ────── AUTH ROUTES ──────
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    req.session.user = user.username;
    req.session.role = user.role;

    req.session.save(err => {
        if (err) {
            console.error('❌ Session save error:', err);
            return res.status(500).json({ message: 'Session save error' });
        }
        console.log('✅ LOGIN SUCCESS', username, '| sessionID:', req.sessionID);
        res.status(200).json({ message: 'Login successful', role: user.role });
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ message: 'Logged out' });
    });
});

// ────── DEBUG SESSION ──────
app.get('/api/session-debug', (req, res) => {
    res.json({
        user: req.session.user || null,
        role: req.session.role || null,
    });
});

// ────── SHIFTS ──────
app.post('/api/shifts', requireLogin, isOwner, async (req, res) => {
    const { date, time, location, notes } = req.body;
    const shift = new Shift({ date, time, location, notes });
    await shift.save();
    res.json({ message: 'Shift posted' });
});

app.get('/api/shifts', requireLogin, isWorker, async (_req, res) => {
    const shifts = await Shift.find({ claimedBy: null });
    res.json(shifts);
});

app.get('/api/view-all-shifts', requireLogin, isOwner, async (_req, res) => {
    const shifts = await Shift.find();
    res.json(shifts);
});

app.post('/api/claim', requireLogin, isWorker, async (req, res) => {
    const { shiftId } = req.body;
    const shift = await Shift.findById(shiftId);
    if (!shift || shift.claimedBy)
        return res.status(400).json({ message: 'Already claimed' });

    shift.claimedBy = req.session.user;
    await shift.save();
    res.json({ message: 'Claimed' });
});

// ────── LOG HOURS ──────
app.post('/api/log-hours', requireLogin, isWorker, async (req, res) => {
    const { date, hours, description } = req.body;
    await Log.create({ username: req.session.user, date, hours, description });
    res.json({ message: 'Hours logged' });
});

app.get('/api/view-logs', requireLogin, isOwner, async (_req, res) => {
    const logs = await Log.find();
    res.json(logs);
});

app.get('/api/logs-by-date', requireLogin, isOwner, async (req, res) => {
    const { date } = req.query;
    if (!date) return res.status(400).json({ message: 'Date is required' });
    const logs = await Log.find({ date });
    res.json(logs);
});

// ────── ADMIN PANEL ──────
app.get('/api/users', requireLogin, isOwner, async (_req, res) => {
    const users = await User.find({}, { password: 0 });
    res.json(users);
});

app.post('/api/users', requireLogin, isOwner, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role)
        return res.status(400).json({ message: 'Missing fields' });

    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ message: 'User already exists' });

    const newUser = new User({ username, password, role });
    await newUser.save();
    res.json({ message: 'User created' });
});

app.delete('/api/users/:id', requireLogin, isOwner, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted' });
});

app.put('/api/users/:id', requireLogin, isOwner, async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ message: 'Password required' });

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.password = password;
    await user.save();
    res.json({ message: 'Password updated successfully (hashed)' });
});

// ────── FRONTEND ROUTES ──────
app.get('/admin-panel.html', requireLogin, isOwner, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

// ────── START SERVER ──────
app.listen(PORT, () =>
    console.log(`🚀 Server running on port ${PORT} [${isProduction ? 'Production' : 'Development'}]`)
);
