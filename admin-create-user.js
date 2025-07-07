// admin-create-user.js
require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/jamison-protection')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String
});

const User = mongoose.model('User', userSchema);

// Command-line args
const [,, username, password, role] = process.argv;

if (!username || !password || !role) {
  console.log('Usage: node admin-create-user.js <username> <password> <owner|worker>');
  process.exit();
}

User.findOne({ username }).then(existing => {
  if (existing) {
    console.log('❌ That username is already taken.');
    process.exit();
  } else {
    return User.create({ username, password, role });
  }
}).then(() => {
  console.log(`✅ Created ${role} user: ${username}`);
  process.exit();
});
