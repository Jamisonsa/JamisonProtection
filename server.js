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
const bcrypt = require('bcrypt');

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
        console.log(`✅ ${user.username} logged in as ${user.role}`);

        res.json({ message: 'Login successful', role: user.role });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out' });
});
// ─── Submit new security log ───
app.post('/api/security-logs', requireLogin, async (req, res) => {
    try {
        const { date, time, location, description, initials } = req.body;
        const submittedBy = req.session.user;

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

    console.log(`✅ New shift posted by ${req.session.user}: ${date} ${time} at ${location}`);

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
    console.log(`👷 Worker fetched ${shifts.length} available/dropped shifts`);

    res.json(shifts);
});
app.post('/api/log-hours', requireLogin, async (req, res) => {
    try {
        const { date, startTime, endTime, location, position, hours } = req.body;
        const user = req.session.user;

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
        console.log(`🕒 Hours logged by ${user}: ${hours} hrs on ${date} (${position})`);
        res.json({ message: 'Hours logged successfully' });
    } catch (err) {
        console.error('Error logging hours:', err);
        res.status(500).json({ message: 'Failed to log hours' });
    }
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


