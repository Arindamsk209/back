const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

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

// Connect to MongoDB
mongoose.connect('mongodb+srv://arindamsingh209:arindam@cluster1.29d0mug.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Register User
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    console.log(e);
    res.status(400).json(e);
  }
});

// Login User
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });

  if (!userDoc) {
    return res.status(400).json('User not found');
  }

  const passOk = bcrypt.compareSync(password, userDoc.password);

  if (passOk) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) return res.status(500).json({ error: 'Failed to create token' });

      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Set secure only in production
        sameSite: 'None', // Required for cross-site cookies
      });

      res.json({
        id: userDoc._id,
        username,
        token,
      });
    });
  } else {
    res.status(400).json('Wrong credentials');
  }
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, secret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Profile Route
app.get('/profile', authenticateToken, (req, res) => {
  res.json(req.user);
});

// Logout User
app.post('/logout', (req, res) => {
  res.cookie('token', '', { httpOnly: true, sameSite: 'None', secure: true }).json('ok');
});

// Remaining Routes (Create, Edit Post, etc.)
app.post('/post', authenticateToken, async (req, res) => {
  const { title, summary, content, cover } = req.body;
  const postDoc = await Post.create({
    title,
    summary,
    content,
    cover,
    author: req.user.id,
  });
  res.json(postDoc);
});

// Start Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
