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
// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if the username already exists
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ error: 'Username already taken' });
  }

  // Hash the password
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  // Create a new user instance
  const newUser = new User({ username, password: hashedPassword });

  // Save the new user to the database
  await newUser.save();
  
  // Send a response back to the client
  res.json({ username });
});


// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });

  if (!userDoc) {
    return res.status(400).json('User not found');
  }

  const isPasswordValid = bcrypt.compareSync(password, userDoc.password);
  if (isPasswordValid) {
    // You can store user data in memory if needed, but this is not a recommended practice for production
    req.session = { userId: userDoc._id, username }; // Temporary storage
    res.json({ id: userDoc._id, username }); // Return user info directly
  } else {
    res.status(400).json('Wrong credentials');
  }
});

// Profile endpoint
// Profile endpoint to get user info by username
app.get('/profile/:username', async (req, res) => {
  const { username } = req.params; // Extract username from URL parameters
  const userDoc = await User.findOne({ username });

  if (!userDoc) {
    return res.status(404).json('User not found');
  }

  // If user found, return user info without password
  res.json({ username: userDoc.username });
});


// Logout endpoint
app.post('/logout', (req, res) => {
  // Clear user session or related data here (if applicable)
  req.session = null; // Clearing session (for demonstration)
  res.json({ message: 'Logout successful' });
});

// Create Post endpoint
app.post('/post', async (req, res) => {
  const { title, content, cover, authorId } = req.body; // Include authorId from the user context
  const newPost = new Post({ title, content, cover, author: authorId });
  await newPost.save();
  res.json(newPost);
});


// Fetch Posts endpoint
app.get('/post', async (req, res) => {
  const posts = await Post.find().populate('author', 'username'); // Populate author information
  res.json(posts);
});

// Get Post by ID
app.get('/post/:id', async (req, res) => {
  const post = await Post.findById(req.params.id).populate('author', 'username');
  if (!post) {
    return res.status(404).json('Post not found');
  }
  res.json(post);
});

// Update Post endpoint
app.put('/post', async (req, res) => {
  const { id, title, content, cover } = req.body;
  const updatedPost = await Post.findByIdAndUpdate(id, { title, content, cover }, { new: true });
  if (!updatedPost) {
    return res.status(404).json('Post not found');
  }
  res.json(updatedPost);
});
// Start the Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
