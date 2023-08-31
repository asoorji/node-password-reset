const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const app = express();
require('dotenv').config()

app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_KEY, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err.message));

// Create a user schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
  });
  
  const User = mongoose.model('User', userSchema);
  
  const JWT_SECRET = process.env.JWT_SECRET_KEY; 

// Endpoint for user registration
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
  
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
      // Create a new user in the database
      const newUser = new User({ email, password: hashedPassword });
      await newUser.save();
  
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      console.error('Error registering user:', error);
      res.status(500).json({ message: 'Error registering user' });
    }
  });
  
// Endpoint for user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });

    // If user doesn't exist
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // If the password is valid, generate a JWT token
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Endpoint for password reset
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  
    try {
      const decodedToken = jwt.verify(token, JWT_SECRET);
      const { email } = decodedToken;
  
      // Find the user by email and update the password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await User.updateOne({ email }, { password: hashedPassword });
  
      res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
      res.status(400).json({ message: 'Invalid or expired token' });
    }
  });

app.listen(3000, () => {
  console.log(JWT_SECRET);
  console.log(process.env.MONGO_KEY);
  console.log('Server is running on port 3000');
});
