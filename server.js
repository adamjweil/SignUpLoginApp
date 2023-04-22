const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');


const jwtSecret = 'your_jwt_secret';

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
const uri = 'mongodb://localhost:27017/signuploginapp';
mongoose.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Mongoose User schema
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  profilePicture: String,
});

const User = mongoose.model('User', UserSchema);


const connection = mongoose.connection;
connection.once('open', () => {
  console.log('MongoDB database connection established successfully');
});

// Authentication middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization').split(' ')[1];

  if (!token) {
    return res.status(401).send('Access denied');
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).send('Invalid token');
  }
};

// Routes
app.get('/', (req, res) => {
  res.send('Hello from the server!');
});

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  console.log("hitting the register API")
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({message: 'User already exists'});
  }

  const salt = 10;
  const hashedPassword = await bcrypt.hash(password, salt);
  const user = new User({ email, password: hashedPassword });
  await user.save();
  console.log(user)

  res.status(201).send('User created successfully');
});

app.post('/api/auth/login', async (req, res) => {
const { email, password } = req.body;

const user = await User.findOne({ email });
if (!user) {
  return res.status(400).send('Invalid email or password');
}

const validPassword = await bcrypt.compare(password, user.password);
if (!validPassword) {
  return res.status(400).send('Invalid email or password');
}

const token = jwt.sign({ _id: user._id, email: user.email }, jwtSecret);
  res.send({ email: user.email, token });
});

// Start server
const port = process.env.PORT || 5001;
app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
