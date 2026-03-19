/**
 * Authentication Controller
 */

const User = require('../models/User');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

class AuthController {
    /**
     * Register user
     */
    async register(req, res, next) {
        try {
            const { email, password, fullName } = req.body;

            // Check if user already exists
            const existingUser = await User.findOne({ email: email.toLowerCase() });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already registered',
                });
            }

            // Create new user
            const user = new User({
                email: email.toLowerCase(),
                password,
                fullName,
                role: 'Staff',
            });

            await user.save();

            // Generate JWT token
            const token = jwt.sign(
                { userId: user._id, email: user.email, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRATION || '24h' }
            );

            logger.info(`User registered: ${email}`);

            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                token,
                user: user.toJSON(),
            });

        } catch (error) {
            logger.error('Registration error:', error.message);
            next(error);
        }
    }

    /**
     * Login user
     */
    async login(req, res, next) {
        try {
            const { email, password } = req.body;

            // Find user
            const user = await User.findOne({ email: email.toLowerCase() });
            if (!user) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials',
                });
            }

            // Check password
            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials',
                });
            }

            // Check if user is active
            if (!user.isActive) {
                return res.status(403).json({
                    success: false,
                    message: 'User account is inactive',
                });
            }

            // Generate JWT token
            const token = jwt.sign(
                { userId: user._id, email: user.email, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRATION || '24h' }
            );

            logger.info(`User logged in: ${email}`);

            res.json({
                success: true,
                message: 'Login successful',
                token,
                user: user.toJSON(),
            });

        } catch (error) {
            logger.error('Login error:', error.message);
            next(error);
        }
    }

    /**
     * Get user profile
     */
    async getProfile(req, res, next) {
        try {
            const user = await User.findById(req.user.userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            res.json({
                success: true,
                user: user.toJSON(),
            });

        } catch (error) {
            logger.error('Get profile error:', error.message);
            next(error);
        }
    }

    /**
     * Update user profile
     */
    async updateProfile(req, res, next) {
        try {
            const { fullName, department } = req.body;

            const user = await User.findByIdAndUpdate(
                req.user.userId,
                {
                    fullName: fullName || undefined,
                    department: department || undefined,
                    updatedAt: new Date(),
                },
                { new: true, runValidators: true }
            );

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            logger.info(`User profile updated: ${user.email}`);

            res.json({
                success: true,
                message: 'Profile updated successfully',
                user: user.toJSON(),
            });

        } catch (error) {
            logger.error('Update profile error:', error.message);
            next(error);
        }
    }

    /**
     * Change password
     */
    async changePassword(req, res, next) {
        try {
            const { currentPassword, newPassword } = req.body;

            const user = await User.findById(req.user.userId);
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            // Verify current password
            const isPasswordValid = await user.comparePassword(currentPassword);
            if (!isPasswordValid) {
                return res.status(401).json({
                    success: false,
                    message: 'Current password is incorrect',
                });
            }

            // Update password
            user.password = newPassword;
            user.updatedAt = new Date();
            await user.save();

            logger.info(`Password changed for user: ${user.email}`);

            res.json({
                success: true,
                message: 'Password changed successfully',
            });

        } catch (error) {
            logger.error('Change password error:', error.message);
            next(error);
        }
    }
}

module.exports = new AuthController();