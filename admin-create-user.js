// admin-create-user.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./user'); // ✅ Use your real model (so it keeps the hashing + schema)

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/jamison-protection')
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

const [,, username, password, role] = process.argv;

(async () => {
    if (!username || !password || !role) {
        console.log('Usage: node admin-create-user.js <username> <password> <owner|worker|admin>');
        process.exit();
    }

    let user = await User.findOne({ username });

    if (user) {
        console.log(`⚠️ User "${username}" already exists. Updating password...`);
        user.password = password; // triggers your bcrypt pre-save hook in user.js
        user.role = role;
        await user.save();
        console.log(`✅ Updated password for ${role} user: ${username}`);
    } else {
        const newUser = new User({ username, password, role });
        await newUser.save(); // triggers bcrypt pre-save hook
        console.log(`✅ Created ${role} user: ${username}`);
    }

    process.exit();
})();
