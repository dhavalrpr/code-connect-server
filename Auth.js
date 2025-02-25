// auth.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const appleSignin = require('apple-signin-auth');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  authProvider: { type: String, enum: ['local', 'google', 'apple'], default: 'local' },
  authProviderId: String,
  profilePicture: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Google OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Helper Functions
const generateToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
};

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes

// Regular Email/Password Registration
app.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        message: 'User already exists with this email or username' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      authProvider: 'local'
    });

    await user.save();

    // Generate token
    const token = generateToken(user);

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Regular Email/Password Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Verify password
    if (user.authProvider !== 'local') {
      return res.status(400).json({ 
        message: `Please use ${user.authProvider} to login` 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user);

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Google Sign In
app.post('/auth/google', async (req, res) => {
  try {
    const { token } = req.body;

    // Verify Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;

    // Find or create user
    let user = await User.findOne({ 
      $or: [
        { email },
        { authProviderId: googleId, authProvider: 'google' }
      ]
    });

    if (!user) {
      // Create new user
      const username = name.replace(/\s+/g, '') + Math.random().toString(36).slice(-4);
      user = new User({
        username,
        email,
        authProvider: 'google',
        authProviderId: googleId,
        profilePicture: picture
      });
    } else {
      // Update existing user
      user.lastLogin = new Date();
      if (user.authProvider !== 'google') {
        user.authProvider = 'google';
        user.authProviderId = googleId;
      }
    }

    await user.save();

    // Generate token
    const jwtToken = generateToken(user);

    res.json({
      token: jwtToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture
      }
    });

  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ message: 'Server error during Google authentication' });
  }
});

// Apple Sign In
app.post('/auth/apple', async (req, res) => {
  try {
    const { authorizationCode } = req.body;

    // Verify Apple token
    const appleResponse = await appleSignin.verifyAuthorizationToken(
      authorizationCode,
      {
        clientId: process.env.APPLE_CLIENT_ID,
        redirectUri: process.env.APPLE_REDIRECT_URI,
      }
    );

    const { sub: appleId, email } = appleResponse;

    // Find or create user
    let user = await User.findOne({ 
      $or: [
        { email },
        { authProviderId: appleId, authProvider: 'apple' }
      ]
    });

    if (!user) {
      // Create new user
      const username = 'user' + Math.random().toString(36).slice(-8);
      user = new User({
        username,
        email,
        authProvider: 'apple',
        authProviderId: appleId
      });
    } else {
      // Update existing user
      user.lastLogin = new Date();
      if (user.authProvider !== 'apple') {
        user.authProvider = 'apple';
        user.authProviderId = appleId;
      }
    }

    await user.save();

    // Generate token
    const token = generateToken(user);

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture
      }
    });

  } catch (error) {
    console.error('Apple auth error:', error);
    res.status(500).json({ message: 'Server error during Apple authentication' });
  }
});

// Get Current User
app.get('/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout (optional - mainly handled on frontend)
app.post('/auth/logout', verifyToken, async (req, res) => {
  try {
    // Update last login time
    await User.findByIdAndUpdate(req.user.userId, {
      lastLogin: new Date()
    });
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error during logout' });
  }
});

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Auth server running on port ${PORT}`);
});