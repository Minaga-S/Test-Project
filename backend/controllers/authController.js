/**
 * Authentication Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.


const User = require('../models/User');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const auditLogService = require('../services/auditLogService');

class AuthController {
    createAccessToken(user) {
        return jwt.sign(
            { userId: user._id, email: user.email, role: user.role, permissions: user.permissions || [] },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION || '24h' }
        );
    }

    createRefreshToken(user) {
        return jwt.sign(
            { userId: user._id },
            process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d' }
        );
    }

    /**
     * Register user
     */
    async register(req, res, next) {
        try {
            const { email, password, fullName } = req.body;

            const normalizedEmail = email.toLowerCase();

            // Check if user already exists
            const existingUser = await User.findOne({ email: normalizedEmail });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already registered',
                });
            }

            // Create new user
            const user = new User({
                email: normalizedEmail,
                password,
                fullName,
                role: 'Staff',
            });

            await user.save();

            const token = this.createAccessToken(user);
            const refreshToken = this.createRefreshToken(user);

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_REGISTER',
                entityType: 'User',
                entityId: String(user._id),
                after: { email: user.email, role: user.role },
                ipAddress: req.ip || '',
            });

            logger.info(`User registered: ${normalizedEmail}`);

            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                token,
                refreshToken,
                user: user.toJSON(),
            });

        } catch (error) {
            logger.error(`Registration error: ${error.message}`);
            next(error);
        }
    }

    /**
     * Login user
     */
    async login(req, res, next) {
        try {
            const { email, password } = req.body;
            const normalizedEmail = email.toLowerCase();

            // Find user
            const user = await User.findOne({ email: normalizedEmail });
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

            const token = this.createAccessToken(user);
            const refreshToken = this.createRefreshToken(user);

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_LOGIN',
                entityType: 'User',
                entityId: String(user._id),
                ipAddress: req.ip || '',
            });

            logger.info(`User logged in: ${normalizedEmail}`);

            res.json({
                success: true,
                message: 'Login successful',
                token,
                refreshToken,
                user: user.toJSON(),
            });

        } catch (error) {
            logger.error(`Login error: ${error.message}`);
            next(error);
        }
    }

    /**
     * Refresh access token
     */
    async refreshToken(req, res, next) {
        try {
            const { refreshToken } = req.body;

            if (!refreshToken) {
                return res.status(400).json({
                    success: false,
                    message: 'Refresh token is required',
                });
            }

            const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
            const user = await User.findById(decoded.userId);

            if (!user || !user.isActive) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid refresh token',
                });
            }

            const nextAccessToken = this.createAccessToken(user);
            const nextRefreshToken = this.createRefreshToken(user);

            return res.json({
                success: true,
                token: nextAccessToken,
                refreshToken: nextRefreshToken,
            });
        } catch (error) {
            logger.error(`Refresh token error: ${error.message}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired refresh token',
            });
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
            logger.error(`Get profile error: ${error.message}`);
            next(error);
        }
    }

    /**
     * Update user profile
     */
    async updateProfile(req, res, next) {
        try {
            const { fullName, department } = req.body;
            const existing = await User.findById(req.user.userId);

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

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_PROFILE_UPDATE',
                entityType: 'User',
                entityId: String(user._id),
                before: existing ? { fullName: existing.fullName, department: existing.department } : null,
                after: { fullName: user.fullName, department: user.department },
                ipAddress: req.ip || '',
            });

            logger.info(`User profile updated: ${user.email}`);

            res.json({
                success: true,
                message: 'Profile updated successfully',
                user: user.toJSON(),
            });

        } catch (error) {
            logger.error(`Update profile error: ${error.message}`);
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

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_PASSWORD_CHANGE',
                entityType: 'User',
                entityId: String(user._id),
                ipAddress: req.ip || '',
            });

            logger.info(`Password changed for user: ${user.email}`);

            res.json({
                success: true,
                message: 'Password changed successfully',
            });

        } catch (error) {
            logger.error(`Change password error: ${error.message}`);
            next(error);
        }
    }
}

module.exports = new AuthController();

