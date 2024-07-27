require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Security middleware
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from the 'public' directory

// MongoDB Connection
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
    console.error('MongoDB URI is not set in environment variables. Please check your .env file.');
    process.exit(1);
}

mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
        process.exit(1);
    });

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    points: { type: Number, default: 0 }
});
const User = mongoose.model('User', userSchema);

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ success: false, message: 'Token required' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Endpoint for user registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'Please provide all required fields' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.json({ success: true, message: 'User registered successfully', userId: newUser._id });
    } catch (err) {
        if (err.code === 11000) {
            res.status(400).json({ success: false, message: 'Username or email already exists' });
        } else {
            res.status(500).json({ success: false, message: 'Error registering user', error: err.message });
        }
    }
});

// Endpoint for user login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Please provide all required fields' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        // Generate a token
        const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ success: true, message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error logging in', error: err.message });
    }
});

// Endpoint for processing payments
app.post('/api/process-payment', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const username = req.user.username; // Use authenticated user

    if (!amount || isNaN(amount)) {
        return res.status(400).json({ success: false, error: 'Invalid request parameters' });
    }

    const points = amount * 10;

    try {
        const user = await User.findOne({ username });
        if (user) {
            user.points += points;
            await user.save();
            res.json({ success: true, message: 'Payment processed successfully', points: user.points });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error processing payment', error: err.message });
    }
});

// Endpoint to get user points by username
app.get('/api/get-user-points', async (req, res) => {
    const { username } = req.query;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }

    try {
        const user = await User.findOne({ username });
        if (user) {
            res.json({ success: true, points: user.points });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error fetching user points', error: err.message });
    }
});

// Endpoint to get user details (secured)
app.get('/api/get-user-details', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (user) {
            res.json({ success: true, username: user.username, email: user.email, points: user.points });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error fetching user details', error: err.message });
    }
});

// Endpoint to logout (clear token/session)
app.post('/api/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
});

// Serve homepage.html as the default page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
