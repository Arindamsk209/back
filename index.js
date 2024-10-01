const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const salt = bcrypt.genSaltSync(10);
const secret = 'asdfe45we45w345wegw345werjktjwertkj';
const port = process.env.PORT || 4000;

const app = express();

// Middleware
app.use(cors({
  credentials: true,
  origin: ['https://fascinating-truffle-d8d0b4.netlify.app'], // Ensure only the front-end is allowed
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
mongoose.connect('mongodb+srv://arindamsingh209:arindam@cluster1.29d0mug.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Get the token from the header

    if (!token) return res.sendStatus(401); // No token, unauthorized

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Token invalid, forbidden
        req.user = user; // Save the user info from the token
        next(); // Proceed to the next middleware or route handler
    });
};


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
  if (!userDoc) return res.status(400).json('User not found');

  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    // Create JWT
    const token = jwt.sign({ username, id: userDoc._id }, secret);
    res.cookie('token', token, { httpOnly: true }).json({
      id: userDoc._id,
      username,
    });
  } else {
    res.status(400).json('Wrong credentials');
  }
});

app.get('/profile', authenticateToken, (req, res) => {
    res.json(req.user); // Send user info from the token
});

// Logout User
app.post('/logout', (req, res) => {
  res.cookie('token', '', { httpOnly: true }).json('ok');
});

// Create Post
app.post('/post', async (req, res) => {
  const { title, summary, content, cover } = req.body; // Get cover image URL from request
  const { token } = req.cookies;
  if (!token) return res.status(401).json('No token provided');

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(401).json('Unauthorized');

    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover, // Use the URL directly
      author: info.id,
    });
    res.json(postDoc);
  });
});

// Edit Post
app.put('/post', async (req, res) => {
  const { id, title, summary, content, cover } = req.body; // Get cover image URL from request
  const { token } = req.cookies;
  if (!token) return res.status(401).json('No token provided');

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(401).json('Unauthorized');
    
    const postDoc = await Post.findById(id);
    if (!postDoc) return res.status(404).json('Post not found');

    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) return res.status(403).json('You are not the author');

    await postDoc.updateOne({
      title,
      summary,
      content,
      cover: cover ? cover : postDoc.cover, // Update with new URL if provided
    });

    res.json(postDoc);
  });
});

// Show Posts
app.get('/post', async (req, res) => {
  res.json(
    await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20)
  );
});

// Show Single Post
app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate('author', ['username']);
  if (!postDoc) return res.status(404).json('Post not found');
  res.json(postDoc);
});

// Start Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
