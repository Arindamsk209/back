const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const User = require('./models/User');
const Post = require('./models/Post');

// Constants
const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET;
const port = process.env.PORT || 4000;

const app = express();

// Middleware
app.use(cors({
  credentials: true,
  origin: ['https://fascinating-truffle-d8d0b4.netlify.app'], // Frontend origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
app.use(express.json());
app.use(cookieParser());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Register User
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, salt);
    const userDoc = await User.create({ username, password: hashedPassword });
    res.json(userDoc);
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(400).json({ error: 'Registration failed', details: err });
  }
});

// Login User
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.findOne({ username });
    if (!userDoc) {
      return res.status(400).json('User not found');
    }

    const isPasswordValid = bcrypt.compareSync(password, userDoc.password);
    if (isPasswordValid) {
      const token = jwt.sign({ username, id: userDoc._id }, secret, { expiresIn: '1h' });

      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        sameSite: 'None', // Enable cross-site cookies
      });

      res.json({ id: userDoc._id, username, token });
    } else {
      res.status(400).json('Wrong credentials');
    }
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ error: 'Login failed', details: err });
  }
});

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  jwt.verify(token, secret, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden: Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Profile Route
app.get('/profile', authenticateToken, (req, res) => {
  res.json(req.user);
});

// Create Post Route (Authenticated)
app.post('/post', authenticateToken, async (req, res) => {
  const { title, summary, content, cover } = req.body;
  try {
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover,
      author: req.user.id,
    });
    res.json(postDoc);
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ error: 'Post creation failed', details: err });
  }
});

// Get All Posts
app.get('/post', authenticateToken, async (req, res) => {
  try {
    const posts = await Post.find().populate('author', 'username');
    res.json(posts);
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ error: 'Failed to fetch posts', details: err });
  }
});

// Start the Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
