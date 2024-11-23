const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.static('static'));

// MongoDB connection function
let cachedConnection = null;
const connectToDatabase = async () => {
    if (cachedConnection) {
        return cachedConnection;
    }
    
    const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://appleidmusic960:Dataking8@tapsidecluster.oeofi.mongodb.net/';
    try {
        const connection = await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            bufferCommands: false,
            serverSelectionTimeoutMS: 5000
        });
        cachedConnection = connection;
        return connection;
    } catch (error) {
        console.error('MongoDB connection error:', error);
        throw error;
    }
};

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: String,
    messageCount: { type: Number, default: 0 },
    currentModel: { type: String, default: 'Qwen/Qwen2.5-Coder-32B-Instruct' },
    lastLogin: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware
const auth = async (req, res, next) => {
    try {
        await connectToDatabase();
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findOne({ _id: decoded.userId });
        
        if (!user) {
            throw new Error();
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ success: false, message: 'Please authenticate' });
    }
};

// Serve register.html as the default page
app.get('/', async (req, res) => {
    await connectToDatabase();
    res.sendFile(path.join(__dirname, 'static', 'register.html'));
});

// Serve index.html
app.get('/index.html', async (req, res) => {
    await connectToDatabase();
    res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

// Routes
app.post('/api/auth', async (req, res) => {
    try {
        await connectToDatabase();
        const { email, password, action } = req.body;

        if (action === 'signup') {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ success: false, message: 'Email already registered' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const user = new User({
                email,
                password: hashedPassword,
                lastLogin: new Date()
            });

            await user.save();

            const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
            res.json({ 
                success: true, 
                token,
                user: {
                    email: user.email,
                    messageCount: user.messageCount,
                    currentModel: user.currentModel,
                    lastLogin: user.lastLogin
                }
            });

        } else if (action === 'login') {
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ success: false, message: 'Invalid credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ success: false, message: 'Invalid credentials' });
            }

            user.lastLogin = new Date();
            await user.save();

            const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
            res.json({ 
                success: true, 
                token,
                user: {
                    email: user.email,
                    messageCount: user.messageCount,
                    currentModel: user.currentModel,
                    lastLogin: user.lastLogin
                }
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Message count and model switching endpoint
app.post('/api/message', auth, async (req, res) => {
    try {
        await connectToDatabase();
        const user = req.user;
        
        user.messageCount += 1;
        
        if (user.messageCount > 20) {
            user.currentModel = 'mistralai/Mixtral-8x7B-Instruct-v0.1';
        }
        
        await user.save();
        
        res.json({ 
            success: true, 
            messageCount: user.messageCount,
            currentModel: user.currentModel
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get user info endpoint
app.get('/api/user', auth, async (req, res) => {
    try {
        await connectToDatabase();
        res.json({ 
            success: true, 
            user: {
                email: req.user.email,
                messageCount: req.user.messageCount,
                currentModel: req.user.currentModel,
                lastLogin: req.user.lastLogin
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Check token validity endpoint
app.post('/api/verify-token', async (req, res) => {
    try {
        await connectToDatabase();
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findOne({ _id: decoded.userId });
        
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }

        res.json({ 
            success: true,
            user: {
                email: user.email,
                messageCount: user.messageCount,
                currentModel: user.currentModel,
                lastLogin: user.lastLogin
            }
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
});

// Export the Express API
module.exports = app;