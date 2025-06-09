var express = require('express');
var router = express.Router();
var User = require('../models/user');
var bcrypt = require('bcryptjs');

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
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    res.render('login', { error: 'User not found' });
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    res.render('login', { error: 'Invalid password' });
  }
  res.redirect('/');
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
module.exports = router;
