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
            role: { $in: ['owner', 'worker', 'admin'] },
            notifySms: true,
            phone: { $ne: null }
        }, { phone: 1, username: 1 });

        if (!recipients.length) return;

        const body =
            `New shift posted:\n` +
            `📅 ${shift.date} at ${shift.startTime}\n` +
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
const nodemailer = require('nodemailer');

// ────── NodeMailer Config ──────
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.CONTACT_EMAIL_USER,
        pass: process.env.CONTACT_EMAIL_PASS
    }
});

transporter.verify((err, success) => {
    if (err) {
        console.error('Nodemailer config error:', err);
    } else {
        console.log('✅ Nodemailer is ready');
    }
});
const cloudinary = require('cloudinary').v2;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

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
const bcrypt = require('bcrypt');
const multer = require('multer');
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 20 * 1024 * 1024 } // 20 MB cap; adjust if you need bigger
});

// ────── MongoDB Connection ──────
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/jamison-protection', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'));

// ────── Schemas ──────
const Shift = mongoose.model('Shift', new mongoose.Schema({
    date: String,
    startTime: String,
    expectedEnd: String,
    location: String,
    position: String,
    notes: String,
    status: { type: String, enum: ['available','claimed','dropped'], default: 'available' },
    claimedBy: String,
    droppedBy: String,
    dropTime: String,
    alertSent: { type: Boolean, default: false } // to prevent repeat 24h texts
}));



const Log = mongoose.model('Log', new mongoose.Schema({
    user: String,
    date: String,
    startTime: String,
    endTime: String,
    location: String,
    position: String,
    hours: Number
}));
// ─── Security Log Model ───
const SecurityLog = mongoose.model('SecurityLog', new mongoose.Schema({
    date: String,
    time: String,
    location: String,
    description: String,
    initials: String,
    submittedBy: String,
    createdAt: { type: Date, default: Date.now }
}));
const Interview = mongoose.model('Interview', new mongoose.Schema({
    name: String,
    email: String,
    position: String,

    resumePath: String,
    resumeDownloadPath: String,
    resumeOriginalName: String,
    resumeMimeType: String,

    coverPath: String,
    coverDownloadPath: String,
    coverOriginalName: String,
    coverMimeType: String,

    submittedAt: { type: Date, default: Date.now },

    interviewTime: String,
    zoomLink: String,

    status: {
        type: String,
        enum: ['New', 'Reviewed', 'Interview Scheduled', 'Rejected', 'Hired'],
        default: 'New'
    },

    notes: { type: String, default: '' },
    reviewedAt: Date,
    hiredAt: Date,
    hiredWorkerUsername: String
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
    const user = req.session.user || null;
    res.json({
        user,
        role: user ? user.role : null
    });
});

// ────── Role Switch Routes ──────

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
app.delete('/api/delete-multiple-shifts', requireLogin, isOwner, async (req, res) => {
    try {
        const { ids } = req.body;
        if (!ids || !Array.isArray(ids)) {
            return res.status(400).json({ message: 'Invalid shift ID list' });
        }

        const result = await Shift.deleteMany({ _id: { $in: ids } });
        res.json({ message: `Deleted ${result.deletedCount} shifts successfully.` });
    } catch (err) {
        console.error('Bulk delete error:', err);
        res.status(500).json({ message: 'Failed to delete shifts' });
    }
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

app.post('/api/admin/create-user', requireLogin, isOwner, async (req, res) => {
    try {
        const { username, password, role, hourlyRate } = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        const user = new User({
            username,
            password,
            role,
            hourlyRate: hourlyRate || 25
        });
        await user.save(); // the model will hash it automatically

        console.log(`👤 Created ${role}: ${username} ($${hourlyRate}/hr)`);
        res.json({ message: `User ${username} created successfully with $${hourlyRate}/hr rate.` });
    } catch (err) {
        console.error('Error creating user:', err);
        res.status(500).json({ message: 'Error creating user.' });
    }
});
// ─── Toggle SMS Alerts ───
app.post('/api/admin/toggle-sms', requireLogin, isOwner, async (req, res) => {
    try {
        const { username, enable } = req.body;
        if (!username) return res.status(400).json({ message: 'Username is required' });

        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: 'User not found' });

        user.notifySms = enable;
        await user.save();

        console.log(`📱 SMS Alerts ${enable ? 'enabled' : 'disabled'} for ${username}`);
        res.json({ message: `SMS alerts ${enable ? 'enabled' : 'disabled'} for ${username}` });
    } catch (err) {
        console.error('Error toggling SMS:', err);
        res.status(500).json({ message: 'Error updating SMS setting' });
    }
});

// ─── Test SMS Route ───
app.post('/api/admin/test-sms', requireLogin, isOwner, async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ message: 'Phone number is required.' });

        if (!twilioClient) {
            return res.status(500).json({ message: 'Twilio is not configured on the server.' });
        }

        const fromConfig = process.env.TWILIO_MESSAGING_SERVICE_SID
            ? { messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID }
            : { from: process.env.TWILIO_FROM };

        await twilioClient.messages.create({
            ...fromConfig,
            to: phone,
            body: `✅ Test SMS from Jamison Protection — Twilio is configured correctly!`
        });

        console.log(`📤 Test SMS sent to ${phone}`);
        res.json({ message: `Test SMS successfully sent to ${phone}` });
    } catch (err) {
        console.error('Error sending test SMS:', err);
        if (err.code) console.error(`Twilio Error Code: ${err.code}`);
        res.status(500).json({ message: 'Failed to send test SMS.', error: err.message });
    }

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
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        req.session.user = { username: user.username, role: user.role };
        req.session.role = user.role;  // ✅ store role separately for middleware

        console.log(`✅ ${user.username} logged in as ${user.role}`);

        req.session.save(err => {
            if (err) console.error('Session save error:', err);
            res.json({ message: 'Login successful', role: user.role });
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out' });
});
// ─── Worker Self Password Reset ───
app.post('/api/change-password', requireLogin, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ message: 'Both old and new passwords are required.' });
        }

        const user = await User.findOne({ username: req.session.user.username });
        if (!user) return res.status(404).json({ message: 'User not found.' });

        const isMatch = await user.comparePassword(oldPassword);
        if (!isMatch) return res.status(401).json({ message: 'Old password is incorrect.' });

        user.password = newPassword; // pre-save hook will hash automatically
        await user.save();

        res.json({ message: 'Password updated successfully.' });
    } catch (err) {
        console.error('Change password error:', err);
        res.status(500).json({ message: 'Server error changing password.' });
    }
});

// ─── Submit new security log ───
app.post('/api/security-logs', requireLogin, async (req, res) => {
    try {
        const { date, time, location, description, initials } = req.body;
        const submittedBy = req.session.user.username;

        const newLog = new SecurityLog({
            date,
            time,
            location,
            description,
            initials,
            submittedBy
        });

        await newLog.save();
        console.log(`🛡️ Security log added by ${submittedBy}: ${description}`);
        res.json({ message: 'Security log submitted successfully' });
    } catch (err) {
        console.error('Error submitting security log:', err);
        res.status(500).json({ message: 'Failed to submit security log' });
    }
});

// ─── Get security logs with filtering + CSV export ───
app.get('/api/security-logs', requireLogin, async (req, res) => {
    try {
        const { date, initials, format } = req.query;
        const filter = {};

        if (date) filter.date = date;
        if (initials) filter.initials = { $regex: new RegExp(initials, 'i') };

        const logs = await SecurityLog.find(filter).sort({ date: -1, time: -1 });

        // ✅ CSV Export Mode
        if (format === 'csv') {
            const { Parser } = require('json2csv');
            const fields = ['date', 'time', 'location', 'description', 'initials', 'submittedBy'];
            const parser = new Parser({ fields });
            const csv = parser.parse(logs);

            res.header('Content-Type', 'text/csv');
            res.attachment('security_logs.csv');
            return res.send(csv);
        }

        res.json(logs);
    } catch (err) {
        console.error('Error fetching security logs:', err);
        res.status(500).json({ message: 'Failed to load security logs' });
    }
});


// ────── Shift Routes ──────
app.post('/api/shifts', requireLogin, isOwner, async (req, res) => {
    const { date, startTime, expectedEnd, location, position, notes } = req.body;

    const shift = new Shift({
        date,
        startTime,
        expectedEnd,
        location,
        position,
        notes,
        status: 'available',
        claimedBy: null,
        droppedBy: null,
        dropTime: null,
        alertSent: false
    });
    await shift.save();

    console.log(`✅ New shift posted by ${req.session.user.username}: ${date} ${startTime} at ${location}`);

    notifyUsersOfNewShift(shift).catch(() => {});
    res.json({ message: 'Shift posted' });
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

    shift.claimedBy = req.session.user.username;
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
    if (shift.claimedBy !== req.session.user.username)
        return res.status(403).json({ message: 'You can only drop your own shifts' });

    shift.status = 'dropped';
    shift.droppedBy = req.session.user.username;
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
app.get('/api/worker-calendar', requireLogin, isWorker, async (req, res) => {
    try {
        const availableShifts = await Shift.find({
            claimedBy: null,
            status: { $in: ['available', 'dropped'] }
        }).sort({ date: 1, startTime: 1 });

        const myShifts = await Shift.find({
            claimedBy: req.session.user.username,
            status: 'claimed'
        }).sort({ date: 1, startTime: 1 });

        const events = [
            ...availableShifts.map(shift => ({
                id: shift._id,
                title: `Available: ${shift.location}`,
                start: `${shift.date}T${shift.startTime}`,
                date: shift.date,
                startTime: shift.startTime,
                expectedEnd: shift.expectedEnd || '',
                location: shift.location || '',
                position: shift.position || '',
                notes: shift.notes || '',
                status: shift.status,
                type: 'available'
            })),
            ...myShifts.map(shift => ({
                id: shift._id,
                title: `My Shift: ${shift.location}`,
                start: `${shift.date}T${shift.startTime}`,
                date: shift.date,
                startTime: shift.startTime,
                expectedEnd: shift.expectedEnd || '',
                location: shift.location || '',
                position: shift.position || '',
                notes: shift.notes || '',
                status: shift.status,
                type: 'claimed'
            }))
        ];

        res.json(events);
    } catch (err) {
        console.error('Error loading worker calendar:', err);
        res.status(500).json({ message: 'Failed to load worker calendar.' });
    }
});
// ────── Log Hours ──────
// ─── Worker Log Hours ───
app.post('/api/log-hours', requireLogin, async (req, res) => {
    try {
        const { date, startTime, endTime, location, position, hours } = req.body;
        const user = req.session.user?.username || req.session.user || 'Unknown';

        const newLog = new Log({
            user,
            date,
            startTime,
            endTime,
            location,
            position,
            hours
        });

        await newLog.save();
        console.log(`🕒 Hours logged by ${user}: ${hours} hrs on ${date}`);
        res.json({ message: 'Hours logged successfully' });
    } catch (err) {
        console.error('Error logging hours:', err);
        res.status(500).json({ message: 'Failed to log hours' });
    }
});


// ─── View Submitted Hours ───
app.get('/api/view-logs', requireLogin, isOwner, async (req, res) => {
    try {
        const logs = await Log.find().sort({ date: -1 });
        if (!logs.length) return res.json([]);

        const grouped = {};
        logs.forEach(log => {
            const user = log.user || 'Unknown';
            if (!grouped[user]) grouped[user] = [];
            grouped[user].push(log);
        });

        res.json(grouped);
    } catch (err) {
        console.error('Error loading logs:', err);
        res.status(500).json({ message: 'Failed to load logs' });
    }
});

app.get('/api/logs-by-date', requireLogin, isOwner, async (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ message: 'Date is required' });

  const logs = await Log.find({ date });
  res.json(logs);
});
// ─── Payroll Summary ───
// ─── Detailed Payroll Summary ───
app.get('/api/payroll', requireLogin, isOwner, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        if (!startDate || !endDate) {
            return res.status(400).json({ message: 'Start and end dates required' });
        }

        // Get all logged hours in the range
        const logs = await Log.find({
            date: { $gte: startDate, $lte: endDate }
        }).sort({ user: 1, date: 1 });

        if (!logs.length) return res.json([]);

        // Get all users and build a rate map
        const users = await User.find();
        const rateMap = {};
        users.forEach(u => { rateMap[u.username] = u.hourlyRate || 20; });

        // Group logs by user
        const grouped = {};
        logs.forEach(log => {
            const user = log.user || 'Unknown';
            if (!grouped[user]) grouped[user] = [];
            grouped[user].push(log);
        });

        // Build detailed payroll data
        const results = Object.keys(grouped).map(user => {
            const rate = rateMap[user] || 20;
            const totalHours = grouped[user].reduce((sum, l) => sum + (parseFloat(l.hours) || 0), 0);
            const totalPay = totalHours * rate;

            return {
                user,
                rate,
                totalHours: totalHours.toFixed(2),
                totalPay: totalPay.toFixed(2),
                entries: grouped[user].map(l => ({
                    date: l.date,
                    start: l.startTime,
                    end: l.endTime,
                    location: l.location,
                    position: l.position,
                    hours: l.hours,
                    pay: (l.hours * rate).toFixed(2)
                }))
            };
        });

        res.json(results);
    } catch (err) {
        console.error('Error building payroll report:', err);
        res.status(500).json({ message: 'Payroll generation failed' });
    }
});


// ────── Admin Panel ──────
app.get('/admin-panel.html', requireLogin, isOwner, (req, res) => {
  const filePath = path.join(__dirname, 'public', 'admin-panel.html');
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) return res.status(500).send('Error loading admin panel');
    res.send(html);
  });
});
app.get('/api/owner-calendar', requireLogin, isOwner, async (_req, res) => {
    try {
        const shifts = await Shift.find().sort({ date: 1, startTime: 1 });

        const events = shifts.map(shift => ({
            id: shift._id,
            title: shift.claimedBy
                ? `${shift.location} — ${shift.claimedBy}`
                : `${shift.location} — Open`,
            start: `${shift.date}T${shift.startTime}`,
            date: shift.date,
            startTime: shift.startTime,
            expectedEnd: shift.expectedEnd || '',
            location: shift.location || '',
            position: shift.position || '',
            notes: shift.notes || '',
            status: shift.status,
            claimedBy: shift.claimedBy || null
        }));

        res.json(events);
    } catch (err) {
        console.error('Error loading owner calendar:', err);
        res.status(500).json({ message: 'Failed to load owner calendar.' });
    }
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
    }).sort({ date: 1, startTime: 1 });

    console.log(`👷 Worker fetched ${shifts.length} available/dropped shifts`);
    res.json(shifts);
});

// Current user's claimed shifts (to show Drop buttons)
app.get('/api/my-shifts', requireLogin, isWorker, async (req, res) => {
    const shifts = await Shift.find({
        claimedBy: req.session.user.username,
        status: 'claimed'
    }).sort({ date: 1, startTime: 1 });
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
            const startAt = toDateTime(shift.date, shift.startTime);
            const hoursUntil = (startAt - now) / 36e5;

            // alert when within 24 hours but still in the future
            if (hoursUntil <= 24 && hoursUntil > 0) {
                console.log(`🚨 24h alert for shift ${shift._id} at ${shift.location} (${shift.date} ${shift.startTime})`);

                if (twilioClient) {
                    const owners = await User.find({
                        role: { $in: ['owner', 'admin'] },
                        notifySms: true,
                        phone: { $ne: null }
                    }, { phone: 1, username: 1 });

                    const body =
                        `⚠️ Urgent Shift: ${shift.location}\n` +
                        `${shift.date} ${shift.startTime}\n` +
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


// Run every 30 minutes
setInterval(checkDroppedShifts, 30 * 60 * 1000);
// ─── Contact Form Route ───
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, message } = req.body;
        if (!name || !email || !message) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        // Email to business
        const mailOptions = {
            from: `"Jamison Protection Website" <${process.env.CONTACT_EMAIL_USER}>`,
            to: 'jamisonprotectionllc@gmail.com',
            subject: `📬 New Contact Form Message from ${name}`,
            text: `You received a new message from ${name} (${email}):\n\n${message}`,
            replyTo: email
        };

        // Send to business
        await transporter.sendMail(mailOptions);
        console.log(`📨 Contact message sent from ${name} (${email})`);

        // ✅ Send confirmation to sender
        await transporter.sendMail({
            from: `"Jamison Protection" <${process.env.CONTACT_EMAIL_USER}>`,
            cc: 'jamisonprotectionllc@gmail.com',
            to: email,
            subject: "We received your message",
            text: `Hi ${name},\n\nThank you for contacting Jamison Protection. We’ve received your message and will respond shortly.\n\n— Jamison Protection Team`
        });

        // Send final response
        res.json({ message: 'Your message has been sent successfully!' });
    } catch (err) {
        console.error('Error sending contact form email:', err);
        res.status(500).json({ message: 'Failed to send message. Please try again later.' });
    }
});
// ─── Job Interview / Resume Upload (Cloudinary Stream Upload) ───
const streamifier = require('streamifier');

// Upload raw binary safely from memory and keep original name
function uploadRawToCloudinaryFromBuffer(file, subfolder) {
    return new Promise((resolve, reject) => {
        const base = path.basename(file.originalname, path.extname(file.originalname))
            .replace(/[^a-z0-9_\-]+/gi, '_');
        const publicId = `${subfolder}/${base}_${Date.now()}`;

        const uploadStream = cloudinary.uploader.upload_stream(
            {
                resource_type: 'raw',
                public_id: publicId,
                overwrite: true,
                use_filename: true,
                unique_filename: false,
                // ✅ Tell Cloudinary the real MIME type (prevents PDF corruption)
                content_type: file.mimetype
            },
            (err, result) => {
                if (err) return reject(err);

                const viewUrl = result.secure_url;
                const downloadUrl = cloudinary.url(result.public_id, {
                    resource_type: 'raw',
                    type: 'upload',
                    version: result.version,
                    flags: 'attachment',
                    attachment: file.originalname,
                    secure: true
                });

                resolve({
                    ...result,
                    secure_url: viewUrl,
                    download_url: downloadUrl
                });
            }
        );

        // ✅ Binary-safe streaming
        const stream = streamifier.createReadStream(file.buffer, { encoding: null });
        stream.pipe(uploadStream);
    });
}


// Nice “download with original filename” URL (optional, but fixes “file” name on download)
function rawDownloadUrl(result, originalName) {
    const ext = path.extname(originalName).slice(1).toLowerCase();
    // Build a URL that forces download with the original filename
    return cloudinary.url(result.public_id, {
        resource_type: 'raw',
        type: 'upload',
        format: ext,
        secure: true,
        // Force attachment with a filename:
        flags: 'attachment',
        attachment: originalName
    });
}

app.post('/api/interview', upload.fields([{ name: 'resume' }, { name: 'cover' }]), async (req, res) => {
    try {
        const { name, email, position } = req.body;
        if (!name || !email || !req.files?.resume) {
            return res.status(400).json({ message: 'Name, email, and résumé are required.' });
        }

        const resumeFile = req.files.resume?.[0];
        const coverFile = req.files.cover?.[0];

        let resumeUrl = null;
        let resumeDownload = null;
        let coverUrl = null;
        let coverDownload = null;

        if (resumeFile) {
            const up = await uploadRawToCloudinaryFromBuffer(resumeFile, 'jamison_protection/resumes');
            resumeUrl = up.secure_url;
            resumeDownload = up.download_url;
        }

        if (coverFile) {
            const up = await uploadRawToCloudinaryFromBuffer(coverFile, 'jamison_protection/covers');
            coverUrl = up.secure_url;
            coverDownload = up.download_url;
        }

        const interview = new Interview({
            name,
            email,
            position,

            resumePath: resumeUrl,
            resumeDownloadPath: resumeDownload,
            resumeOriginalName: resumeFile ? resumeFile.originalname : null,
            resumeMimeType: resumeFile ? resumeFile.mimetype : null,

            coverPath: coverUrl,
            coverDownloadPath: coverDownload,
            coverOriginalName: coverFile ? coverFile.originalname : null,
            coverMimeType: coverFile ? coverFile.mimetype : null
        });

        await interview.save();

        let ownerEmailSent = false;
        let applicantEmailSent = false;
        let emailErrors = [];

        try {
            await transporter.sendMail({
                from: `"Jamison Protection Careers" <${process.env.CONTACT_EMAIL_USER}>`,
                to: 'jamisonprotectionllc@gmail.com',
                subject: `📄 New Interview Request from ${name}`,
                text:
                    `Applicant Details:

Name: ${name}
Email: ${email}
Position: ${position || 'Not specified'}

Résumé (view): ${resumeUrl || '—'}
Résumé (download): ${resumeDownload || '—'}
Cover Letter (view): ${coverUrl || '—'}
Cover Letter (download): ${coverDownload || '—'}`
            });
            ownerEmailSent = true;
        } catch (err) {
            console.error('Owner email failed:', err);
            emailErrors.push(`Owner email failed: ${err.message}`);
        }

        try {
            await transporter.sendMail({
                from: `"Jamison Protection" <${process.env.CONTACT_EMAIL_USER}>`,
                to: email,
                subject: 'We received your application',
                text: `Hi ${name},

Thank you for applying to Jamison Protection. We’ve received your résumé and will review your application soon.

— Jamison Protection Team`
            });
            applicantEmailSent = true;
        } catch (err) {
            console.error('Applicant email failed:', err);
            emailErrors.push(`Applicant email failed: ${err.message}`);
        }

        return res.status(200).json({
            message: ownerEmailSent && applicantEmailSent
                ? 'Your application has been submitted successfully!'
                : 'Your application was saved, but one or more email notifications failed.',
            applicationSaved: true,
            ownerEmailSent,
            applicantEmailSent,
            emailErrors
        });

    } catch (err) {
        console.error('Error handling interview submission:', err);
        res.status(500).json({ message: 'Failed to submit application. Please try again later.' });
    }
});



function generateICS(interview) {
    const { interviewTime, zoomLink, name, email } = interview;

    const start = new Date(interviewTime);
    const end = new Date(start.getTime() + 30 * 60 * 1000); // 30 min duration

    const formatDate = d => d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

    return `
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Jamison Protection//Interview Scheduler//EN
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
UID:${Date.now()}@jamisonprotection.com
SUMMARY:Interview with Jamison Protection
DTSTART:${formatDate(start)}
DTEND:${formatDate(end)}
LOCATION:Google Meet
DESCRIPTION:Interview with Jamison Protection\\nJoin Link: ${zoomLink}
ORGANIZER;CN=Jamison Protection:mailto:${process.env.CONTACT_EMAIL_USER}
ATTENDEE;CN=${name};RSVP=TRUE:mailto:${email}
END:VEVENT
END:VCALENDAR
  `.trim();
}

// ─── Schedule Interview (manual Google Meet link) ───
app.post('/api/interviews/schedule', requireLogin, isOwner, async (req, res) => {
    try {
        const { id, time, meetLink } = req.body;
        const interview = await Interview.findById(id);
        if (!interview) return res.status(404).json({ message: 'Interview not found.' });

        interview.interviewTime = time;
        interview.zoomLink = meetLink;
        interview.status = 'Interview Scheduled';
        await interview.save();

        const icsContent = generateICS(interview);

        await transporter.sendMail({
            from: `"Jamison Protection" <${process.env.CONTACT_EMAIL_USER}>`,
            to: interview.email,
            cc: 'jamisonprotectionllc@gmail.com',
            subject: 'Interview Scheduled with Jamison Protection',
            html: `
    <p>Hi <strong>${interview.name}</strong>,</p>
    <p>Your interview has been scheduled for <strong>${time}</strong>.</p>
    <p>
      <a href="${meetLink}" target="_blank" style="
        background-color:#e63946;
        color:white;
        padding:10px 15px;
        border-radius:6px;
        text-decoration:none;
        font-weight:bold;
      ">
        Join Google Meet Interview
      </a>
    </p>
    <p>We look forward to speaking with you.<br><br>— Jamison Protection Team</p>
  `,
            attachments: [
                {
                    filename: 'JamisonProtection-Interview.ics',
                    content: icsContent,
                    contentType: 'text/calendar'
                }
            ]
        });

        res.json({ message: 'Interview scheduled and Meet link sent successfully.' });
    } catch (err) {
        console.error('Error scheduling interview:', err);
        res.status(500).json({ message: 'Failed to schedule interview.' });
    }
});
// ─── Get all interview submissions (for Owner Panel) ───
app.get('/api/interviews', requireLogin, isOwner, async (_req, res) => {
    try {
        const interviews = await Interview.find().sort({ submittedAt: -1 });
        res.json(interviews);
    } catch (err) {
        console.error('Error fetching interviews:', err);
        res.status(500).json({ message: 'Failed to load interview submissions' });
    }
});

app.get('/api/interviews/file/:id', requireLogin, isOwner, async (req, res) => {
    try {
        const interview = await Interview.findById(req.params.id);
        if (!interview) return res.status(404).send('Interview not found');

        const fileType = req.query.type === 'cover' ? 'cover' : 'resume';
        const mode = req.query.mode === 'preview' ? 'preview' : 'download';

        const fileUrl = fileType === 'cover'
            ? (interview.coverDownloadPath || interview.coverPath)
            : (interview.resumeDownloadPath || interview.resumePath);

        const originalName = fileType === 'cover'
            ? (interview.coverOriginalName || 'cover-letter')
            : (interview.resumeOriginalName || 'resume');

        const mimeType = fileType === 'cover'
            ? (interview.coverMimeType || 'application/octet-stream')
            : (interview.resumeMimeType || 'application/octet-stream');

        if (!fileUrl) return res.status(404).send('File not found');

        const response = await fetch(fileUrl);
        if (!response.ok) {
            return res.status(502).send('Failed to fetch file from storage');
        }

        const buffer = Buffer.from(await response.arrayBuffer());
        const safeName = originalName.replace(/"/g, '');

        res.setHeader('Content-Type', mimeType);

        if (mode === 'preview' && mimeType === 'application/pdf') {
            res.setHeader('Content-Disposition', `inline; filename="${safeName}"`);
        } else {
            res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
        }

        res.send(buffer);
    } catch (err) {
        console.error('Error serving interview file:', err);
        res.status(500).send('Server error');
    }
});
app.put('/api/interviews/:id/status', requireLogin, isOwner, async (req, res) => {
    try {
        const { status } = req.body;

        const allowed = ['New', 'Reviewed', 'Interview Scheduled', 'Rejected', 'Hired'];
        if (!allowed.includes(status)) {
            return res.status(400).json({ message: 'Invalid status.' });
        }

        const interview = await Interview.findById(req.params.id);
        if (!interview) return res.status(404).json({ message: 'Interview not found.' });

        interview.status = status;
        if (status === 'Reviewed' && !interview.reviewedAt) {
            interview.reviewedAt = new Date();
        }

        await interview.save();
        res.json({ message: 'Status updated successfully.' });
    } catch (err) {
        console.error('Error updating interview status:', err);
        res.status(500).json({ message: 'Failed to update status.' });
    }
});

app.put('/api/interviews/:id/notes', requireLogin, isOwner, async (req, res) => {
    try {
        const { notes } = req.body;

        const interview = await Interview.findById(req.params.id);
        if (!interview) return res.status(404).json({ message: 'Interview not found.' });

        interview.notes = notes || '';
        await interview.save();

        res.json({ message: 'Notes saved successfully.' });
    } catch (err) {
        console.error('Error saving interview notes:', err);
        res.status(500).json({ message: 'Failed to save notes.' });
    }
});
function generateTempPassword(length = 10) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$';
    let pwd = '';
    for (let i = 0; i < length; i++) {
        pwd += chars[Math.floor(Math.random() * chars.length)];
    }
    return pwd;
}

function makeUsernameFromEmail(email) {
    return email.split('@')[0].replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
}

app.post('/api/interviews/:id/hire', requireLogin, isOwner, async (req, res) => {
    try {
        const interview = await Interview.findById(req.params.id);
        if (!interview) return res.status(404).json({ message: 'Interview not found.' });

        let username = makeUsernameFromEmail(interview.email);
        let finalUsername = username;
        let counter = 1;

        while (await User.findOne({ username: finalUsername })) {
            finalUsername = `${username}${counter}`;
            counter++;
        }

        const tempPassword = generateTempPassword();

        const newWorker = new User({
            username: finalUsername,
            password: tempPassword,
            role: 'worker',
            hourlyRate: 25
        });

        await newWorker.save();

        interview.status = 'Hired';
        interview.hiredAt = new Date();
        interview.hiredWorkerUsername = finalUsername;
        await interview.save();

        await transporter.sendMail({
            from: `"Jamison Protection" <${process.env.CONTACT_EMAIL_USER}>`,
            to: interview.email,
            cc: 'jamisonprotectionllc@gmail.com',
            subject: 'You Have Been Hired by Jamison Protection',
            text: `Hi ${interview.name},

Congratulations! You have been hired by Jamison Protection.

Your worker account has been created.

Username: ${finalUsername}
Temporary Password: ${tempPassword}

Please log in and change your password as soon as possible.

— Jamison Protection Team`
        });

        res.json({
            message: `Applicant hired successfully. Worker account created for ${finalUsername}.`,
            username: finalUsername
        });
    } catch (err) {
        console.error('Error hiring applicant:', err);
        res.status(500).json({ message: 'Failed to hire applicant.' });
    }
});
// ────── Start Server ──────
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


