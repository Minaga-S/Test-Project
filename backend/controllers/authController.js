/**
 * Authentication Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.

const User = require('../models/User');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const auditLogService = require('../services/auditLogService');
const totpService = require('../services/totpService');

const TWO_FACTOR_CHALLENGE_EXPIRATION = '5m';
const DEFAULT_TOTP_APP_NAME = 'HCGS';

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

    createTwoFactorChallengeToken(user) {
        return jwt.sign(
            { userId: user._id, type: '2fa_login' },
            process.env.JWT_SECRET,
            { expiresIn: TWO_FACTOR_CHALLENGE_EXPIRATION }
        );
    }

    getTwoFactorAppName() {
        return process.env.TOTP_APP_NAME || DEFAULT_TOTP_APP_NAME;
    }

    /**
     * Register user
     */
    async register(req, res, next) {
        try {
            const { email, password, fullName } = req.body;
            const normalizedEmail = email.toLowerCase();

            const existingUser = await User.findOne({ email: normalizedEmail });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already registered',
                });
            }

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

            return res.status(201).json({
                success: true,
                message: 'User registered successfully',
                token,
                refreshToken,
                promptToEnableTwoFactor: true,
                user: user.toJSON(),
            });
        } catch (error) {
            logger.error(`Registration error: ${error.message}`);
            return next(error);
        }
    }

    /**
     * Login user
     */
    async login(req, res, next) {
        try {
            const { email, password } = req.body;
            const normalizedEmail = email.toLowerCase();

            const user = await User.findOne({ email: normalizedEmail });
            if (!user) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials',
                });
            }

            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials',
                });
            }

            if (!user.isActive) {
                return res.status(403).json({
                    success: false,
                    message: 'User account is inactive',
                });
            }

            if (user.twoFactorEnabled && user.twoFactorSecret) {
                const challengeToken = this.createTwoFactorChallengeToken(user);
                return res.json({
                    success: true,
                    message: 'Two-factor authentication required',
                    requiresTwoFactor: true,
                    challengeToken,
                });
            }

            const shouldPromptToEnableTwoFactor = !user.twoFactorEnabled && Boolean(user.hasLoggedInOnce);

            if (!user.hasLoggedInOnce) {
                user.hasLoggedInOnce = true;
                user.updatedAt = new Date();
                await user.save();
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

            return res.json({
                success: true,
                message: 'Login successful',
                token,
                refreshToken,
                promptToEnableTwoFactor: shouldPromptToEnableTwoFactor,
                user: user.toJSON(),
            });
        } catch (error) {
            logger.error(`Login error: ${error.message}`);
            return next(error);
        }
    }

    async verifyTwoFactorLogin(req, res, next) {
        try {
            const { challengeToken, code } = req.body;

            let decoded;
            try {
                decoded = jwt.verify(challengeToken, process.env.JWT_SECRET);
            } catch (error) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid or expired 2FA challenge token',
                });
            }

            if (decoded.type !== '2fa_login') {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid 2FA challenge token',
                });
            }

            const user = await User.findById(decoded.userId);
            if (!user || !user.isActive) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid login attempt',
                });
            }

            if (!user.twoFactorEnabled || !user.twoFactorSecret) {
                return res.status(400).json({
                    success: false,
                    message: 'Two-factor authentication is not enabled for this account',
                });
            }

            const isCodeValid = totpService.verifyToken(user.twoFactorSecret, code);
            if (!isCodeValid) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid 2FA code',
                });
            }

            if (!user.hasLoggedInOnce) {
                user.hasLoggedInOnce = true;
                user.updatedAt = new Date();
                await user.save();
            }

            const token = this.createAccessToken(user);
            const refreshToken = this.createRefreshToken(user);

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_LOGIN_2FA',
                entityType: 'User',
                entityId: String(user._id),
                ipAddress: req.ip || '',
            });

            logger.info(`User logged in with 2FA: ${user.email}`);

            return res.json({
                success: true,
                message: '2FA verification successful',
                token,
                refreshToken,
                user: user.toJSON(),
            });
        } catch (error) {
            logger.error(`2FA login verification error: ${error.message}`);
            return next(error);
        }
    }

    async setupTwoFactor(req, res, next) {
        try {
            const user = await User.findById(req.user.userId);
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            if (user.twoFactorEnabled) {
                return res.status(400).json({
                    success: false,
                    message: 'Two-factor authentication is already enabled',
                });
            }

            const secret = totpService.generateSecret();
            const otpAuthUrl = totpService.buildOtpAuthUrl({
                appName: this.getTwoFactorAppName(),
                email: user.email,
                secret,
            });
            const qrCodeDataUrl = await totpService.generateQrCodeDataUrl(otpAuthUrl);

            user.twoFactorTempSecret = secret;
            user.updatedAt = new Date();
            await user.save();

            return res.json({
                success: true,
                message: '2FA setup generated successfully',
                qrCodeDataUrl,
                manualEntryKey: secret,
            });
        } catch (error) {
            logger.error(`2FA setup error: ${error.message}`);
            return next(error);
        }
    }

    async enableTwoFactor(req, res, next) {
        try {
            const { code } = req.body;
            const user = await User.findById(req.user.userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            if (!user.twoFactorTempSecret) {
                return res.status(400).json({
                    success: false,
                    message: '2FA setup has not been initialized',
                });
            }

            const isCodeValid = totpService.verifyToken(user.twoFactorTempSecret, code);
            if (!isCodeValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid 2FA code',
                });
            }

            user.twoFactorSecret = user.twoFactorTempSecret;
            user.twoFactorTempSecret = '';
            user.twoFactorEnabled = true;
            user.updatedAt = new Date();
            await user.save();

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_2FA_ENABLED',
                entityType: 'User',
                entityId: String(user._id),
                ipAddress: req.ip || '',
            });

            return res.json({
                success: true,
                message: 'Two-factor authentication enabled successfully',
            });
        } catch (error) {
            logger.error(`Enable 2FA error: ${error.message}`);
            return next(error);
        }
    }

    async disableTwoFactor(req, res, next) {
        try {
            const { code } = req.body;
            const user = await User.findById(req.user.userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            if (!user.twoFactorEnabled || !user.twoFactorSecret) {
                return res.status(400).json({
                    success: false,
                    message: 'Two-factor authentication is not enabled',
                });
            }

            const isCodeValid = totpService.verifyToken(user.twoFactorSecret, code);
            if (!isCodeValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid 2FA code',
                });
            }

            user.twoFactorEnabled = false;
            user.twoFactorSecret = '';
            user.twoFactorTempSecret = '';
            user.updatedAt = new Date();
            await user.save();

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_2FA_DISABLED',
                entityType: 'User',
                entityId: String(user._id),
                ipAddress: req.ip || '',
            });

            return res.json({
                success: true,
                message: 'Two-factor authentication disabled successfully',
            });
        } catch (error) {
            logger.error(`Disable 2FA error: ${error.message}`);
            return next(error);
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

            return res.json({
                success: true,
                user: user.toJSON(),
            });
        } catch (error) {
            logger.error(`Get profile error: ${error.message}`);
            return next(error);
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

            return res.json({
                success: true,
                message: 'Profile updated successfully',
                user: user.toJSON(),
            });
        } catch (error) {
            logger.error(`Update profile error: ${error.message}`);
            return next(error);
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

            const isPasswordValid = await user.comparePassword(currentPassword);
            if (!isPasswordValid) {
                return res.status(401).json({
                    success: false,
                    message: 'Current password is incorrect',
                });
            }

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

            return res.json({
                success: true,
                message: 'Password changed successfully',
            });
        } catch (error) {
            logger.error(`Change password error: ${error.message}`);
            return next(error);
        }
    }
}

module.exports = new AuthController();
