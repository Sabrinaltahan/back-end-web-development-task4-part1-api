const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const authMiddleware = require('./middleware/auth');
const UserDetails = require('./models/UserDetails');
const User = require('./models/User');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(cors()); // Enable CORS for all routes

// This would allow requests only from 'http://localhost:3000'
// app.use(cors({
//     origin: ['http://localhost:3000', 'http://127.0.0.1:3000']
// }));

// Validation middleware for registration
const validateRegistration = [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];

// User registration endpoint
app.post('/register', validateRegistration, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { username, password } = req.body;

        // Check if username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Create new user
        const newUser = new User({ username, password });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

// Validation middleware for login
const validateLogin = [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
];

// User login endpoint
app.post('/login', validateLogin, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { username, password } = req.body;

        // Check if user exists
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Generate JWT token
        const payload = {
            user: {
                id: user.id
            }
        };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
        if (err) throw err;
            res.json({ token });
        });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

// Validation middleware for protected route
const validateUserDetails = [
    body('phone').notEmpty().withMessage('Phone is required'),
    body('address').notEmpty().withMessage('Address is required'),
    body('email').isEmail().withMessage('Invalid email format'),
];

// Protected route with user details handling
app.post('/protected', authMiddleware, validateUserDetails, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { phone, address, email } = req.body;
        const userId = req.user.id;

        // Check if user details already exist
        let userDetails = await UserDetails.findOne({ user: userId });

        if (!userDetails) {
            // Create new user details if not exist
            userDetails = new UserDetails({
                user: userId,
                phone,
                address,
                email
            });
        } else {
            // Update existing user details
            userDetails.phone = phone;
            userDetails.address = address;
            userDetails.email = email;
        }

        await userDetails.save();

        res.json({ message: 'User details saved successfully', userDetails });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
