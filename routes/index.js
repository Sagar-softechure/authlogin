var express = require('express');
var router = express.Router();
var User = require('../models/user');
var bcrypt = require('bcryptjs');
const { generateAccessToken, generateRefreshToken } = require('../utils/jwt');
const jwt = require('jsonwebtoken');
const RefreshToken = require('../models/Refreshtoken');
const authenticate = require('../middleware/authenticate');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Hello World!' });
});

router.get('/register', function(req, res, next) {
  res.render('register');
});

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.post('/login', async function(req, res, next) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    await RefreshToken.create({ 
      user: user._id, 
      token: refreshToken, 
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) 
    });
    res.cookie('refreshToken', refreshToken, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ accessToken });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'An error occurred during login' });
  }
});

router.post('/register', function(req, res, next) {
  const { username, email, password } = req.body;
  const user = new User({ username, email, password });
  user.save()
    .then(() => {
      res.redirect('/');
    })
    .catch((err) => {
      res.json({ error: 'Username or email already exists' });
    });
});

router.post('/logout', async function(req, res) {
  const token = req.cookies.refreshToken;
try {
  if (token) {
    await RefreshToken.deleteOne({ token }); // Remove from DB
    res.clearCookie('refreshToken');         // Remove from browser
  }

  res.redirect('/login'); // Or send a status/message
} catch (error) {
  res.status(500).json({ error: 'Failed to logout' });
}
  
});

router.post('/refresh', async function(req, res) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token missing' });
  }

  // Check if token exists in DB
  const storedToken = await RefreshToken.findOne({ token: refreshToken });
  if (!storedToken) {
    return res.status(403).json({ message: 'Invalid refresh token' });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const newAccessToken = jwt.sign({ id: decoded.id }, ACCESS_TOKEN_SECRET, {
      expiresIn: '15m',
    });

    return res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ message: 'Refresh token expired or invalid' });
  }
});

router.get('/dashboard', authenticate, async function(req, res) {
  res.render('dashboard');
});

module.exports = router;
