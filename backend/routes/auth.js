const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { validateEmail, validatePassword } = require('../utils/validators');
const { authMiddleware } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
    try {
        const { email, password, fullName } = req.body;

        if (!validateEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email' });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ success: false, message: 'Password too short' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }

        const user = new User({ email, password, fullName });
        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION || '24h' }
        );

        res.status(201).json({
            success: true,
            token,
            user: user.toJSON(),
        });

    } catch (error) {
        logger.error('Register error:', error.message);
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        logger.info(`Login attempt: ${email}`);

        const user = await User.findOne({ email });
        if (!user) {
            logger.warn(`User not found: ${email}`);
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const passwordMatch = await user.comparePassword(password);
        logger.info(`Password match for ${email}: ${passwordMatch}`);
        
        if (!passwordMatch) {
            logger.warn(`Invalid password for: ${email}`);
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION || '24h' }
        );

        res.json({
            success: true,
            token,
            user: user.toJSON(),
        });

    } catch (error) {
        logger.error('Login error:', error.message);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
});

// Get profile
router.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        res.json({ success: true, user: user.toJSON() });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching profile' });
    }
});

// Update profile
router.put('/profile', authMiddleware, async (req, res) => {
    try {
        const { fullName, department } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { fullName, department, updatedAt: new Date() },
            { new: true }
        );
        res.json({ success: true, user: user.toJSON() });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating profile' });
    }
});

// Change password
router.post('/change-password', authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const user = await User.findById(req.user.userId);
        if (!await user.comparePassword(currentPassword)) {
            return res.status(401).json({ success: false, message: 'Current password incorrect' });
        }

        user.password = newPassword;
        await user.save();

        res.json({ success: true, message: 'Password changed' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error changing password' });
    }
});

module.exports = router;