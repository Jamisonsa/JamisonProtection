// server.js
process.env.NODE_ENV = 'production';
require('dotenv').config();
// ───── Twilio ─────
let twilioClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
    twilioClient = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
}

const E164 = /^\+?[1-9]\d{1,14}$/;
async function notifyUsersOfNewShift(shift) {
    try {
        if (!twilioClient) return; // no-op if Twilio not configured

        // Get all owners + workers who opted in and have a valid phone
        const recipients = await User.find({
            role: { $in: ['owner', 'worker'] },
            notifySms: true,
            phone: { $ne: null }
        }, { phone: 1, username: 1 });

        if (!recipients.length) return;

        const body =
            `New shift posted:\n` +
            `📅 ${shift.date} at ${shift.time}\n` +
            `📍 ${shift.location}\n` +
            (shift.notes ? `📝 ${shift.notes}\n` : '') +
            `— Jamison Protection`;

        const fromConfig = process.env.TWILIO_MESSAGING_SERVICE_SID
            ? { messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID }
            : { from: process.env.TWILIO_FROM };

        const sends = recipients
            .filter(u => E164.test(u.phone))
            .map(u => twilioClient.messages.create({
                ...fromConfig,
                to: u.phone,
                body
            }));

        await Promise.allSettled(sends);
    } catch (err) {
        console.error('SMS notify error:', err?.message || err);
    }
}

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;
const User = require('./user');

// ────── MongoDB Connection ──────
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/jamison-protection', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'));

// ────── Schemas ──────
// ────── Schemas ──────
const Shift = mongoose.model('Shift', new mongoose.Schema({
    date: String,          // e.g. "2025-11-03"
    time: String,          // e.g. "09:00"
    location: String,
    notes: String,
    claimedBy: String,     // username who currently holds it, or null
    status: { type: String, enum: ['available','claimed','dropped'], default: 'available' },
    droppedBy: String,     // username who dropped it (last)
    dropTime: Date,        // when it was dropped
    alertSent: { type: Boolean, default: false } // to prevent repeat 24h texts
}));



const Log = mongoose.model('Log', new mongoose.Schema({
  username: String,
  date: String,
  hours: Number,
  description: String   
}));

// ────── Seed Users ──────
async function seedUsers() {
  const existing = await User.find();
  if (existing.length === 0) {
    const users = [
      new User({ username: 'owner', password: 'ownerpass', role: 'owner' }),
      new User({ username: 'worker1', password: 'pass1', role: 'worker' }),
      new User({ username: 'worker2', password: 'pass2', role: 'worker' })
    ];
    for (const user of users) {
      await user.save(); // triggers hashing
    }
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
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self' data: https:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https:; connect-src 'self' https:;"
    );
    next();
});




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

// ───── Role Switch Routes ─────

// Owner temporarily views as worker
app.post('/api/switch-to-worker', requireLogin, (req, res) => {
    if (req.session.role !== 'owner') {
        return res.status(403).json({ message: 'Only owner can switch to worker view' });
    }
    req.session.viewMode = 'worker';
    res.status(200).json({ message: 'Now viewing as worker', viewMode: 'worker' });
});

// Owner restores full owner/admin access
app.post('/api/switch-to-owner', requireLogin, (req, res) => {
    if (req.session.role !== 'owner') {
        return res.status(403).json({ message: 'Only owner can switch to owner view' });
    }

    // ✅ Fully restore owner access
    req.session.viewMode = null;
    req.session.role = 'owner';

    req.session.save(err => {
        if (err) return res.status(500).json({ message: 'Failed to restore session' });
        res.status(200).json({ message: 'Now viewing as owner', viewMode: 'owner' });
    });
});
app.get('/api/whoami', (req, res) => {
    res.json({
        user: req.session.user,
        role: req.session.role,
        viewMode: req.session.viewMode
    });
});

// ─── User Management (Admin Panel) ───
// ─── Admin: Create, Delete, Update Users ───
app.get('/api/users', requireLogin, isOwner, async (_req, res) => {
  const users = await User.find({}, { password: 0 }); // hide password
  res.json(users);
});
// Delete a shift (Owner only)
app.delete('/api/delete-shift/:id', requireLogin, isOwner, async (req, res) => {
    try {
        const shiftId = req.params.id;
        const deleted = await Shift.findByIdAndDelete(shiftId);
        if (!deleted) return res.status(404).json({ message: 'Shift not found' });
        res.json({ message: 'Shift deleted successfully' });
    } catch (err) {
        console.error('Delete shift error:', err);
        res.status(500).json({ message: 'Failed to delete shift' });
    }
});

app.post('/api/users', requireLogin, isOwner, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ message: 'Missing fields' });
  }

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

  await User.findByIdAndUpdate(req.params.id, { password });
  res.json({ message: 'Password updated' });
});


// ────── Auth Middleware ──────
function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ message: 'Not logged in' });
}
function isOwner(req, res, next) {
    if (req.session && req.session.role === 'owner' && req.session.viewMode !== 'worker') {
        return next();
    }
    return res.status(403).json({ message: 'Owner access only' });
}
function isWorker(req, res, next) {
    // Allow both real workers and owners viewing as workers
    if (
        req.session &&
        (req.session.role === 'worker' ||
            (req.session.role === 'owner' && req.session.viewMode === 'worker'))
    ) {
        return next();
    }
    return res.status(403).json({ message: 'Worker access only' });
}


// ────── Auth Routes ──────
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
if (!user) return res.status(401).json({ message: 'Invalid credentials' });

const isMatch = await user.comparePassword(password);
if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  req.session.user = user.username;
  req.session.role = user.role;
  req.session.viewMode = user.role; // ✅ start with same as role
    res.status(200).json({ message: 'Login successful', role: user.role });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out' });
});

// ────── Shift Routes ──────
app.post('/api/shifts', requireLogin, isOwner, async (req, res) => {
    const { date, time, location, notes } = req.body;
    const shift = new Shift({
        date, time, location, notes,
        status: 'available',
        claimedBy: null,
        droppedBy: null,
        dropTime: null,
        alertSent: false
    });
    await shift.save();

    notifyUsersOfNewShift(shift).catch(() => {});
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
    if (!shift) return res.status(404).json({ message: 'Shift not found' });
    if (shift.claimedBy) return res.status(400).json({ message: 'Shift already claimed' });

    shift.claimedBy = req.session.user;
    shift.status = 'claimed';
    shift.droppedBy = null;
    shift.dropTime = null;
    shift.alertSent = false; // reset any previous alert state
    await shift.save();

    res.json({ message: 'Shift claimed successfully' });
});


// ────── Drop Shift ──────
app.post('/api/drop', requireLogin, isWorker, async (req, res) => {
    const { shiftId } = req.body;
    const shift = await Shift.findById(shiftId);
    if (!shift) return res.status(404).json({ message: 'Shift not found' });
    if (shift.claimedBy !== req.session.user)
        return res.status(403).json({ message: 'You can only drop your own shifts' });

    shift.status = 'dropped';
    shift.droppedBy = req.session.user;
    shift.claimedBy = null;
    shift.dropTime = new Date();
    // keep alertSent as-is; 24h checker will set it when it fires
    await shift.save();

    res.json({ message: 'Shift dropped successfully' });
});

app.post('/api/repost-shift', requireLogin, isOwner, async (req, res) => {
    const { shiftId } = req.body;
    const shift = await Shift.findById(shiftId);
    if (!shift) return res.status(404).json({ message: 'Shift not found' });

    shift.status = 'available';
    shift.claimedBy = null;
    shift.droppedBy = null;
    shift.dropTime = null;
    shift.alertSent = false;
    await shift.save();

    res.json({ message: 'Shift reposted as available' });
});

// ────── Log Hours ──────
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
// Available (or dropped but unclaimed) shifts for workers to claim
app.get('/api/shifts', requireLogin, isWorker, async (_req, res) => {
    const shifts = await Shift.find({
        claimedBy: null,
        status: { $in: ['available', 'dropped'] }
    }).sort({ date: 1, time: 1 });
    res.json(shifts);
});

// Current user's claimed shifts (to show Drop buttons)
app.get('/api/my-shifts', requireLogin, isWorker, async (req, res) => {
    const shifts = await Shift.find({
        claimedBy: req.session.user,
        status: 'claimed'
    }).sort({ date: 1, time: 1 });
    res.json(shifts);
});

// ────── Shift Drop Monitor ──────
function toDateTime(dateStr, timeStr) {
    // dateStr "2025-11-03", timeStr "09:00" -> Date in local server time
    return new Date(`${dateStr}T${timeStr}:00`);
}

async function checkDroppedShifts() {
    try {
        const now = new Date();

        // all dropped & unclaimed shifts that haven't been alerted yet
        const dropped = await Shift.find({
            status: 'dropped',
            claimedBy: null,
            alertSent: false
        });

        for (const shift of dropped) {
            const startAt = toDateTime(shift.date, shift.time);
            const hoursUntil = (startAt - now) / 36e5;

            // alert when within 24 hours but still in the future
            if (hoursUntil <= 24 && hoursUntil > 0) {
                console.log(`🚨 24h alert for shift ${shift._id} at ${shift.location} (${shift.date} ${shift.time})`);

                if (twilioClient) {
                    const owners = await User.find({
                        role: { $in: ['owner', 'admin'] },
                        notifySms: true,
                        phone: { $ne: null }
                    }, { phone: 1, username: 1 });

                    const body =
                        `⚠️ Urgent Shift: ${shift.location}\n` +
                        `${shift.date} ${shift.time}\n` +
                        `Dropped by ${shift.droppedBy}. Needs coverage within 24h.`;

                    const fromConfig = process.env.TWILIO_MESSAGING_SERVICE_SID
                        ? { messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID }
                        : { from: process.env.TWILIO_FROM };

                    await Promise.allSettled(
                        owners.map(o => twilioClient.messages.create({ ...fromConfig, to: o.phone, body }))
                    );
                }

                // prevent repeated alerts
                shift.alertSent = true;
                await shift.save();
            }
        }
    } catch (err) {
        console.error('Error checking dropped shifts:', err?.message || err);
    }
}

// run every 30 minutes
setInterval(checkDroppedShifts, 30 * 60 * 1000);


// Run every 30 minutes
setInterval(checkDroppedShifts, 30 * 60 * 1000);

// ────── Start Server ──────
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


