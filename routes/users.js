const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passportJWT = require('../middlewares/passport-jwt');

/* GET users listing. */
// localhost:4000/api/v1/users/profile
router.get('/profile', [ passportJWT.checkAuth], async function(req, res, next) {
  const user = await User.findByPk(req.user.user_id);
  return res.status(200).json({
    user:  {
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      role: user.role
    }
  });
});

// localhost:4000/api/v1/users
router.get('/', function(req, res, next) {
  return res.status(200).json({
    message: 'Hello Users'
  });
});

// localhost:4000/api/v1/users/register
router.post('/register', async function(req, res, next) {
  const {fullname, email, password} = req.body;
  //check email
  const user = await User.findOne({ where: { email : email}});
  if (user != null) {
    return res.status(400).json({ message: 'email has already exist'});
  }

  // encrypt password
  const salt = await bcrypt.genSalt(8);
  const passwordHash = await bcrypt.hash(password, salt);

  // use bcrypt compare on login
  // const isValid = await bcrypt.compare(password, user.password);

  const newUser = await User.create({
    fullname: fullname,
    email: email,
    password: passwordHash
  });



  return res.status(201).json({
    message: 'Register Success',
    user:{
      id: newUser.id,
      fullname: newUser.fullname
    }
  });
});

// localhost:4000/api/v1/users/login
router.post('/login', async function(req, res, next) {
  const { email, password} = req.body;

  // email varification system
  const user = await User.findOne({ where: { email : email}});
  if (user === null) {
    return res.status(400).json({message: 'User Not Found'});
  }

  // compare with table on password hash
  const isValid = await bcrypt.compare(password, user.password);
  if (isValid === false) {
    return res.status(401).json({message: 'Password Incorrect'});
  }

  // create token
  const token = jwt.sign({ user_id : user.id, role: user.role}, 
    process.env.JWT_KEY, { expiresIn: '7d'});
  return res.status(200).json({
    message: 'Login Successful',
    access_token: token
  });
});

module.exports = router;
