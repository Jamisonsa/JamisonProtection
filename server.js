// server.js
process.env.NODE_ENV = 'production';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 4000;

// ────── MongoDB Connection ──────
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/jamison-protection', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'));

// ────── Schemas ──────
const Shift = mongoose.model('Shift', new mongoose.Schema({
  date: String,
  time: String,
  location: String,
  notes: String,
  claimedBy: String
}));

const Log = mongoose.model('Log', new mongoose.Schema({
  username: String,
  date: String,
  hours: Number
}));

const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  password: String,
  role: String // 'owner' or 'worker'
}));

// ────── Seed Users ──────
async function seedUsers() {
  const existing = await User.find();
  if (existing.length === 0) {
    await User.create([
      { username: 'owner', password: 'ownerpass', role: 'owner' },
      { username: 'worker1', password: 'pass1', role: 'worker' },
      { username: 'worker2', password: 'pass2', role: 'worker' }
    ]);
    console.log('✅ Seeded default users');
  }
}
seedUsers();

// ────── CORS ──────
app.use(cors({
  origin: 'https://jamisonprotection.onrender.com',
  credentials: true
}));

// ────── Sessions ──────
app.set('trust proxy', 1); // ✅ Required for secure cookies on Render (behind proxy)

app.use(session({
  name: 'connect.sid',
  secret: 'jamison-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,             // ✅ Required for HTTPS-only cookies on Render
    sameSite: 'none',         // ✅ Required for cross-site cookie with frontend/backend split
    httpOnly: true
  }
}));




// ────── Middleware ──────
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ────── Static Files ──────
app.use(express.static(path.join(__dirname, 'public')));

// ────── Session Debug ──────
app.get('/api/session-debug', (req, res) => {
  res.json({
    user: req.session.user || null,
    role: req.session.role || null
  });
});

// ────── Role Switch Routes ──────
app.post('/api/switch-to-worker', (req, res) => {
  if (req.session.user === 'owner') {
    req.session.role = 'worker';
    return res.status(200).json({ message: 'Switched to worker' });
  }
  return res.status(403).json({ message: 'Only owner can switch to worker' });
});

app.post('/api/switch-to-owner', (req, res) => {
  if (req.session.user === 'owner') {
    req.session.role = 'owner';
    return res.status(200).json({ message: 'Switched to owner' });
  }
  return res.status(403).json({ message: 'Only owner can switch to owner' });
});
// ─── User Management (Admin Panel) ───
app.get('/api/users', requireLogin, isOwner, async (_req, res) => {
  const users = await User.find({}, '-password'); // omit passwords
  res.json(users);
});

app.post('/api/users', requireLogin, isOwner, async (req, res) => {
  const { username, password, role } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ message: 'User already exists' });
  await User.create({ username, password, role });
  res.json({ message: 'User created' });
});

app.delete('/api/users/:id', requireLogin, isOwner, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: 'User deleted' });
});

app.put('/api/users/:id', requireLogin, isOwner, async (req, res) => {
  const { password } = req.body;
  await User.findByIdAndUpdate(req.params.id, { password });
  res.json({ message: 'Password updated' });
});

// ────── Auth Middleware ──────
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

// ────── Auth Routes ──────
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, password });
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  req.session.user = user.username;
  req.session.role = user.role;
  res.status(200).json({ message: 'Login successful', role: user.role });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out' });
});

// ────── Shift Routes ──────
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
  if (!shift || shift.claimedBy) return res.status(400).json({ message: 'Already claimed' });

  shift.claimedBy = req.session.user;
  await shift.save();
  res.json({ message: 'Claimed' });
});

// ────── Log Hours ──────
app.post('/api/log-hours', requireLogin, isWorker, async (req, res) => {
  const { date, hours } = req.body;
  await Log.create({ username: req.session.user, date, hours });
  res.json({ message: 'Hours logged' });
});

app.get('/api/view-logs', requireLogin, isOwner, async (_req, res) => {
  const logs = await Log.find();
  res.json(logs);
});

// ────── Admin Panel ──────
app.get('/admin-panel.html', requireLogin, isOwner, (req, res) => {
  const filePath = path.join(__dirname, 'public', 'admin-panel.html');
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) return res.status(500).send('Error loading admin panel');
    res.send(html);
  });
});

app.get('/api/verify-owner', requireLogin, isOwner, (req, res) => {
  return res.sendStatus(200);
});
// ─── Debug Session Route ───
app.get('/api/debug-session', (req, res) => {
  res.json({
    user: req.session.user || null,
    role: req.session.role || null,
    fullSession: req.session
  });
});


// ────── Start Server ──────
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


