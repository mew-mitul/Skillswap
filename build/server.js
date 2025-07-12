const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/skillswap', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB successfully!');
});

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePhoto: { type: String },
  location: { type: String, default: 'Mumbai, Maharashtra' },
  availability: [{ type: String }],
  visibility: { type: String, default: 'Public' },
  offeredSkills: [{ type: String }],
  wantedSkills: [{ type: String }],
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Skill Swap Schema
const skillSwapSchema = new mongoose.Schema({
  fromUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  toUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  offeredSkill: { type: String, required: true },
  wantedSkill: { type: String, required: true },
  message: { type: String },
  status: { type: String, enum: ['Pending', 'Accepted', 'Rejected', 'Completed'], default: 'Pending' },
  rating: { type: Number, min: 1, max: 5 },
  createdAt: { type: Date, default: Date.now }
});

const SkillSwap = mongoose.model('SkillSwap', skillSwapSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Register User
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if email is admin reserved
    if (email === 'admin@123') {
      return res.status(400).json({ message: 'This email is reserved for admin use' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login User
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check for admin login
    if (email === 'admin@123' && password === '0000') {
      const adminUser = {
        id: 'admin',
        name: 'Admin',
        email: 'admin@123',
        isAdmin: true
      };

      const token = jwt.sign(adminUser, JWT_SECRET, { expiresIn: '24h' });
      return res.json({
        message: 'Admin login successful',
        user: adminUser,
        token
      });
    }

    // Regular user login
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const userResponse = {
      id: user._id,
      name: user.name,
      email: user.email,
      profilePhoto: user.profilePhoto,
      location: user.location,
      availability: user.availability,
      visibility: user.visibility,
      offeredSkills: user.offeredSkills,
      wantedSkills: user.wantedSkills,
      isAdmin: false
    };

    const token = jwt.sign(userResponse, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      message: 'Login successful',
      user: userResponse,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get User Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    if (req.user.id === 'admin') {
      return res.json({
        id: 'admin',
        name: 'Admin',
        email: 'admin@123',
        isAdmin: true
      });
    }

    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update User Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    if (req.user.id === 'admin') {
      return res.status(400).json({ message: 'Admin profile cannot be updated' });
    }

    const { name, location, availability, visibility, profilePhoto } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        name,
        location,
        availability,
        visibility,
        profilePhoto
      },
      { new: true }
    ).select('-password');

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get All Users (for browsing skills)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ visibility: 'Public' })
      .select('name location profilePhoto offeredSkills availability')
      .limit(20);

    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create Skill Swap Request
app.post('/api/swaps', authenticateToken, async (req, res) => {
  try {
    const { toUserId, offeredSkill, wantedSkill, message } = req.body;

    const swap = new SkillSwap({
      fromUser: req.user.id,
      toUser: toUserId,
      offeredSkill,
      wantedSkill,
      message
    });

    await swap.save();
    res.status(201).json({ message: 'Swap request created successfully', swap });
  } catch (error) {
    console.error('Create swap error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get User's Swaps
app.get('/api/swaps', authenticateToken, async (req, res) => {
  try {
    const swaps = await SkillSwap.find({
      $or: [{ fromUser: req.user.id }, { toUser: req.user.id }]
    })
    .populate('fromUser', 'name profilePhoto')
    .populate('toUser', 'name profilePhoto')
    .sort({ createdAt: -1 });

    res.json(swaps);
  } catch (error) {
    console.error('Get swaps error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Swap Status
app.put('/api/swaps/:swapId', authenticateToken, async (req, res) => {
  try {
    const { status, rating } = req.body;
    const swap = await SkillSwap.findByIdAndUpdate(
      req.params.swapId,
      { status, rating },
      { new: true }
    );

    res.json({ message: 'Swap updated successfully', swap });
  } catch (error) {
    console.error('Update swap error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add/Remove Skills
app.put('/api/skills', authenticateToken, async (req, res) => {
  try {
    const { skill, type, action } = req.body; // action: 'add' or 'remove'

    if (req.user.id === 'admin') {
      return res.status(400).json({ message: 'Admin cannot modify skills' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (type === 'offered') {
      if (action === 'add') {
        if (!user.offeredSkills.includes(skill)) {
          user.offeredSkills.push(skill);
        }
      } else if (action === 'remove') {
        user.offeredSkills = user.offeredSkills.filter(s => s !== skill);
      }
    } else if (type === 'wanted') {
      if (action === 'add') {
        if (!user.wantedSkills.includes(skill)) {
          user.wantedSkills.push(skill);
        }
      } else if (action === 'remove') {
        user.wantedSkills = user.wantedSkills.filter(s => s !== skill);
      }
    }

    await user.save();
    res.json({ message: 'Skills updated successfully', user });
  } catch (error) {
    console.error('Update skills error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin Routes
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    if (req.user.id !== 'admin' && !req.user.isAdmin) {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const totalUsers = await User.countDocuments();
    const totalSwaps = await SkillSwap.countDocuments();
    const pendingSwaps = await SkillSwap.countDocuments({ status: 'Pending' });
    const completedSwaps = await SkillSwap.countDocuments({ status: 'Completed' });

    res.json({
      totalUsers,
      totalSwaps,
      pendingSwaps,
      completedSwaps
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
