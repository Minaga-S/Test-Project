/**
 * Authentication Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.

const crypto = require('crypto');
const bcryptjs = require('bcryptjs');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const auditLogService = require('../services/auditLogService');
const totpService = require('../services/totpService');

const TWO_FACTOR_CHALLENGE_EXPIRATION = '5m';
const DEFAULT_TOTP_APP_NAME = 'HCGS';
const DEFAULT_ACCESS_TOKEN_EXPIRATION = '15m';
const DEFAULT_REFRESH_TOKEN_EXPIRATION = '7d';
const MAX_LOGIN_FAILED_ATTEMPTS = 5;
const LOGIN_LOCK_MINUTES = 15;
const PASSWORD_RESET_LOCK_MINUTES = 10;
const MAX_PASSWORD_RESET_FAILED_ATTEMPTS = 5;
const RECOVERY_CODE_COUNT = 8;
const SECURITY_QUESTION_COUNT = 3;

class AuthController {
    createAccessToken(user) {
        return jwt.sign(
            {
                userId: user._id,
                email: user.email,
                role: user.role,
                permissions: user.permissions || [],
                sessionVersion: this.getSessionVersion(user),
            },
            process.env.JWT_SECRET,
            { expiresIn: DEFAULT_ACCESS_TOKEN_EXPIRATION }
        );
    }

    createRefreshToken(user) {
        return jwt.sign(
            {
                userId: user._id,
                sessionVersion: this.getSessionVersion(user),
                refreshTokenVersion: this.getRefreshTokenVersion(user),
            },
            process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_REFRESH_EXPIRATION || DEFAULT_REFRESH_TOKEN_EXPIRATION }
        );
    }

    createTwoFactorChallengeToken(user) {
        return jwt.sign(
            { userId: user._id, type: '2fa_login', sessionVersion: this.getSessionVersion(user) },
            process.env.JWT_SECRET,
            { expiresIn: TWO_FACTOR_CHALLENGE_EXPIRATION }
        );
    }

    getSessionVersion(user) {
        return Number(user?.sessionVersion || 0);
    }

    getRefreshTokenVersion(user) {
        return Number(user?.refreshTokenVersion || 0);
    }

    normalizeRequestIp(requestIp) {
        return String(requestIp || '').trim();
    }

    bumpAuthenticationVersions(user) {
        user.sessionVersion = this.getSessionVersion(user) + 1;
        user.refreshTokenVersion = this.getRefreshTokenVersion(user) + 1;
    }

    isLoginLocked(user) {
        return Boolean(user.loginLockUntil && user.loginLockUntil.getTime() > Date.now());
    }

    async clearLoginFailures(user) {
        user.loginFailedAttempts = 0;
        user.loginLockUntil = null;
        user.updatedAt = new Date();
        await user.save();
    }

    async registerLoginFailure(user, requestIp) {
        user.loginFailedAttempts = (user.loginFailedAttempts || 0) + 1;
        user.lastFailedLoginAt = new Date();
        user.lastFailedLoginIp = this.normalizeRequestIp(requestIp);
        let isLocked = false;

        if (user.loginFailedAttempts >= MAX_LOGIN_FAILED_ATTEMPTS) {
            user.loginLockUntil = new Date(Date.now() + (LOGIN_LOCK_MINUTES * 60 * 1000));
            user.loginFailedAttempts = 0;
            isLocked = true;
        }

        user.updatedAt = new Date();
        await user.save();
        return isLocked;
    }

    async recordLoginAnomaly(user, requestIp) {
        const currentIp = this.normalizeRequestIp(requestIp);
        const previousIp = this.normalizeRequestIp(user.lastLoginIp);

        if (previousIp && currentIp && previousIp !== currentIp) {
            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_LOGIN_ANOMALY',
                entityType: 'User',
                entityId: String(user._id),
                before: { lastLoginIp: previousIp, lastLoginAt: user.lastLoginAt || null },
                after: { currentLoginIp: currentIp },
                ipAddress: currentIp,
            });
        }

        user.lastLoginAt = new Date();
        user.lastLoginIp = currentIp || previousIp || '';
        user.updatedAt = new Date();
        await user.save();
    }

    getTwoFactorAppName() {
        return process.env.TOTP_APP_NAME || DEFAULT_TOTP_APP_NAME;
    }

    getTwoFactorSetupAppName() {
        return this.getTwoFactorAppName();
    }

    getTwoFactorAccountName(email, secret) {
        const normalizedEmail = String(email || '').trim().toLowerCase();
        // The short suffix keeps authenticator labels distinct when users re-enroll 2FA,
        // reducing accidental reuse of stale app entries with the same email label.
        const suffix = String(secret || '')
            .replace(/[^A-Za-z0-9]/g, '')
            .slice(-6)
            .toUpperCase();

        if (!normalizedEmail || !suffix) {
            return normalizedEmail;
        }

        return `${normalizedEmail} - ${suffix}`;
    }

    normalizeTwoFactorCode(value) {
        return String(value || '').replace(/\D/g, '').slice(0, 6);
    }

    normalizeSecurityQuestionText(value) {
        return String(value || '').trim().replace(/\s+/g, ' ');
    }

    normalizeSecurityQuestionsInput(securityQuestions) {
        if (!Array.isArray(securityQuestions)) {
            return [];
        }

        return securityQuestions
            .map((item) => ({
                question: this.normalizeSecurityQuestionText(item?.question),
                answer: String(item?.answer || '').trim(),
            }))
            .filter((item) => item.question && item.answer);
    }

    hasRequiredSecurityQuestions(securityQuestions) {
        if (!Array.isArray(securityQuestions) || securityQuestions.length !== SECURITY_QUESTION_COUNT) {
            return false;
        }

        const uniqueQuestions = new Set(
            securityQuestions.map((item) => this.normalizeSecurityQuestionText(item.question).toLowerCase())
        );

        return uniqueQuestions.size === SECURITY_QUESTION_COUNT;
    }

    async hashSecurityQuestions(securityQuestions) {
        return Promise.all(
            securityQuestions.map(async (item) => ({
                question: item.question,
                answerHash: await bcryptjs.hash(item.answer.toLowerCase(), 10),
            }))
        );
    }

    async verifySecurityQuestionAnswers(user, securityAnswers) {
        if (!this.hasRequiredSecurityQuestions(securityAnswers)) {
            return false;
        }

        const storedQuestions = Array.isArray(user.securityQuestions) ? user.securityQuestions : [];
        if (!this.hasRequiredSecurityQuestions(storedQuestions)) {
            return false;
        }

        // Map answers by normalized question text so ordering from the client does not matter.
        const normalizedAnswers = new Map(
            securityAnswers.map((item) => [
                this.normalizeSecurityQuestionText(item.question).toLowerCase(),
                String(item.answer || '').trim().toLowerCase(),
            ])
        );

        for (const storedQuestion of storedQuestions) {
            const normalizedQuestion = this.normalizeSecurityQuestionText(storedQuestion.question).toLowerCase();
            const providedAnswer = normalizedAnswers.get(normalizedQuestion);

            if (!providedAnswer) {
                return false;
            }

            const isAnswerValid = await bcryptjs.compare(providedAnswer, storedQuestion.answerHash || '');
            if (!isAnswerValid) {
                return false;
            }
        }

        return true;
    }

    isStrongPassword(password) {
        const value = String(password || '');
        return value.length >= 12
            && /[A-Z]/.test(value)
            && /[a-z]/.test(value)
            && /\d/.test(value)
            && /[^A-Za-z0-9]/.test(value)
            && !/\s/.test(value);
    }

    createRecoveryCode() {
        return crypto.randomBytes(5).toString('hex').toUpperCase();
    }

    async createRecoveryCodes() {
        const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () => this.createRecoveryCode());
        const recoveryCodeHashes = await Promise.all(recoveryCodes.map((code) => bcryptjs.hash(code, 10)));

        return {
            recoveryCodes,
            recoveryCodeHashes,
        };
    }

    isResetLocked(user) {
        return Boolean(user.passwordResetLockUntil && user.passwordResetLockUntil.getTime() > Date.now());
    }

    async registerPasswordResetFailure(user) {
        user.passwordResetFailedAttempts = (user.passwordResetFailedAttempts || 0) + 1;

        // Rotate the counter after locking so a new lock window always reflects fresh failures.
        if (user.passwordResetFailedAttempts >= MAX_PASSWORD_RESET_FAILED_ATTEMPTS) {
            user.passwordResetLockUntil = new Date(Date.now() + (PASSWORD_RESET_LOCK_MINUTES * 60 * 1000));
            user.passwordResetFailedAttempts = 0;
        }

        user.updatedAt = new Date();
        await user.save();
    }

    async clearPasswordResetFailures(user) {
        user.passwordResetFailedAttempts = 0;
        user.passwordResetLockUntil = null;
        user.updatedAt = new Date();
        await user.save();
    }

    async verifyRecoveryCode(user, recoveryCode) {
        if (!Array.isArray(user.recoveryCodeHashes) || user.recoveryCodeHashes.length === 0) {
            return { isValid: false, remainingRecoveryCodeHashes: [] };
        }

        const normalizedCode = String(recoveryCode || '').trim().toUpperCase();
        if (!normalizedCode) {
            return { isValid: false, remainingRecoveryCodeHashes: user.recoveryCodeHashes };
        }

        for (let index = 0; index < user.recoveryCodeHashes.length; index += 1) {
            const isMatch = await bcryptjs.compare(normalizedCode, user.recoveryCodeHashes[index]);
            if (isMatch) {
                // Recovery codes are one-time credentials; remove the matched hash immediately.
                const remainingRecoveryCodeHashes = user.recoveryCodeHashes.filter((_, hashIndex) => hashIndex !== index);
                return {
                    isValid: true,
                    remainingRecoveryCodeHashes,
                };
            }
        }

        return {
            isValid: false,
            remainingRecoveryCodeHashes: user.recoveryCodeHashes,
        };
    }

    /**
     * Register user
     */
    async register(req, res, next) {
        try {
            const { email, password, fullName, department, securityQuestions } = req.body;
            const normalizedEmail = email.toLowerCase();
            const normalizedSecurityQuestions = this.normalizeSecurityQuestionsInput(securityQuestions);

            if (!this.hasRequiredSecurityQuestions(normalizedSecurityQuestions)) {
                return res.status(400).json({
                    success: false,
                    message: 'Provide exactly 3 unique security questions with answers.',
                });
            }

            const existingUser = await User.findOne({ email: normalizedEmail });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already registered',
                });
            }

            const hashedSecurityQuestions = await this.hashSecurityQuestions(normalizedSecurityQuestions);

            const user = new User({
                email: normalizedEmail,
                password,
                fullName,
                role: 'User',
                department,
                securityQuestions: hashedSecurityQuestions,
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

            if (this.isLoginLocked(user)) {
                return res.status(423).json({
                    success: false,
                    message: 'Account is temporarily locked due to repeated failed login attempts. Please try again later.',
                });
            }

            const isPasswordValid = await user.comparePassword(password);
            if (!isPasswordValid) {
                const isLocked = await this.registerLoginFailure(user, req.ip || '');
                return res.status(isLocked ? 423 : 401).json({
                    success: false,
                    message: isLocked
                        ? 'Account is temporarily locked due to repeated failed login attempts. Please try again later.'
                        : 'Invalid credentials',
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

            await this.clearLoginFailures(user);
            await this.recordLoginAnomaly(user, req.ip || '');

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

    async forgotPassword(req, res, next) {
        try {
            const normalizedEmail = String(req.body.email || '').toLowerCase().trim();
            const user = await User.findOne({ email: normalizedEmail });
            const resetOptions = {
                securityQuestions: [],
                canUseTwoFactor: false,
            };

            if (user?.isActive) {
                resetOptions.securityQuestions = Array.isArray(user.securityQuestions)
                    ? user.securityQuestions.map((item) => item.question).filter(Boolean)
                    : [];
                resetOptions.canUseTwoFactor = Boolean(user.twoFactorEnabled && user.twoFactorSecret);
            }

            if (user?.isActive) {
                await auditLogService.record({
                    actorUserId: user._id,
                    action: 'USER_PASSWORD_RESET_REQUESTED',
                    entityType: 'User',
                    entityId: String(user._id),
                    ipAddress: req.ip || '',
                });
            }

            return res.json({
                success: true,
                message: 'If an active account exists, answer your security questions to reset your password. You can also use 2FA if enabled.',
                resetOptions,
            });
        } catch (error) {
            logger.error(`Forgot password error: ${error.message}`);
            return next(error);
        }
    }

    async resetPassword(req, res, next) {
        try {
            const { email, newPassword, totpCode, recoveryCode, securityAnswers } = req.body;
            const normalizedEmail = String(email || '').toLowerCase().trim();
            const normalizedSecurityAnswers = this.normalizeSecurityQuestionsInput(securityAnswers);
            const hasSecurityAnswers = this.hasRequiredSecurityQuestions(normalizedSecurityAnswers);

            if (!this.isStrongPassword(newPassword)) {
                return res.status(400).json({
                    success: false,
                    message: 'Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.',
                });
            }

            const user = await User.findOne({ email: normalizedEmail });
            if (!user || !user.isActive) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid reset request',
                });
            }

            if (this.isResetLocked(user)) {
                return res.status(429).json({
                    success: false,
                    message: 'Password reset is temporarily locked due to repeated failed attempts. Please try again later.',
                });
            }

            const normalizedTotpCode = this.normalizeTwoFactorCode(totpCode);
            const hasTotpCode = /^\d{6}$/.test(normalizedTotpCode);
            const hasRecoveryCode = Boolean(String(recoveryCode || '').trim());
            const hasTwoFactorVerificationInput = hasTotpCode || hasRecoveryCode;

            let isVerified = false;
            let usedRecoveryCode = false;
            let remainingRecoveryCodeHashes = user.recoveryCodeHashes;

            if (hasSecurityAnswers) {
                isVerified = await this.verifySecurityQuestionAnswers(user, normalizedSecurityAnswers);
            }

            if (!isVerified && !hasSecurityAnswers && !hasTwoFactorVerificationInput) {
                return res.status(400).json({
                    success: false,
                    message: 'Provide answers for all 3 security questions or use 2FA verification.',
                });
            }

            if (!isVerified && hasTwoFactorVerificationInput) {
                if (!user.twoFactorEnabled || !user.twoFactorSecret) {
                    return res.status(403).json({
                        success: false,
                        message: 'Two-factor authentication is not enabled for this account. Use security questions instead.',
                    });
                }

                if (hasTotpCode) {
                    isVerified = totpService.verifyToken(user.twoFactorSecret, normalizedTotpCode);
                }

                if (!isVerified && hasRecoveryCode) {
                    const recoveryResult = await this.verifyRecoveryCode(user, recoveryCode);
                    isVerified = recoveryResult.isValid;
                    usedRecoveryCode = recoveryResult.isValid;
                    remainingRecoveryCodeHashes = recoveryResult.remainingRecoveryCodeHashes;
                }
            }

            if (!isVerified) {
                await this.registerPasswordResetFailure(user);
                return res.status(401).json({
                    success: false,
                    message: hasSecurityAnswers
                        ? 'Security question answers are incorrect'
                        : 'Invalid authenticator or recovery code',
                });
            }

            await this.clearPasswordResetFailures(user);
            user.password = newPassword;
            this.bumpAuthenticationVersions(user);
            user.passwordChangedAt = new Date();
            user.updatedAt = new Date();

            if (usedRecoveryCode) {
                user.recoveryCodeHashes = remainingRecoveryCodeHashes;
            }

            await user.save();

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_PASSWORD_RESET',
                entityType: 'User',
                entityId: String(user._id),
                after: { usedRecoveryCode },
                ipAddress: req.ip || '',
            });

            return res.json({
                success: true,
                message: 'Password reset successful. Please log in again.',
                forceReauth: true,
            });
        } catch (error) {
            logger.error(`Reset password error: ${error.message}`);
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

            if (Number(decoded.sessionVersion || 0) !== this.getSessionVersion(user)) {
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

            await this.clearLoginFailures(user);
            await this.recordLoginAnomaly(user, req.ip || '');

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
                appName: this.getTwoFactorSetupAppName(),
                email: user.email,
                accountName: this.getTwoFactorAccountName(user.email, secret),
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

            const { recoveryCodes, recoveryCodeHashes } = await this.createRecoveryCodes();

            user.twoFactorSecret = user.twoFactorTempSecret;
            user.twoFactorTempSecret = '';
            user.twoFactorEnabled = true;
            user.recoveryCodeHashes = recoveryCodeHashes;
            this.bumpAuthenticationVersions(user);
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
                recoveryCodes,
                forceReauth: true,
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
            user.recoveryCodeHashes = [];
            this.bumpAuthenticationVersions(user);
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
                forceReauth: true,
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

            if (Number(decoded.sessionVersion || 0) !== this.getSessionVersion(user)
                || Number(decoded.refreshTokenVersion || 0) !== this.getRefreshTokenVersion(user)) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid refresh token',
                });
            }

            user.refreshTokenVersion = this.getRefreshTokenVersion(user) + 1;
            user.updatedAt = new Date();
            await user.save();

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

            if (!this.isStrongPassword(newPassword)) {
                return res.status(400).json({
                    success: false,
                    message: 'Password must be at least 12 characters and include uppercase, lowercase, number, and symbol.',
                });
            }

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
            this.bumpAuthenticationVersions(user);
            user.passwordChangedAt = new Date();
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
                forceReauth: true,
            });
        } catch (error) {
            logger.error(`Change password error: ${error.message}`);
            return next(error);
        }
    }

    async getSecurityQuestions(req, res, next) {
        try {
            const user = await User.findById(req.user.userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            const securityQuestions = Array.isArray(user.securityQuestions)
                ? user.securityQuestions.map((item) => item.question).filter(Boolean)
                : [];

            return res.json({
                success: true,
                securityQuestions,
            });
        } catch (error) {
            logger.error(`Get security questions error: ${error.message}`);
            return next(error);
        }
    }

    async updateSecurityQuestions(req, res, next) {
        try {
            const normalizedSecurityQuestions = this.normalizeSecurityQuestionsInput(req.body.securityQuestions);
            if (!this.hasRequiredSecurityQuestions(normalizedSecurityQuestions)) {
                return res.status(400).json({
                    success: false,
                    message: 'Provide exactly 3 unique security questions with answers.',
                });
            }

            const user = await User.findById(req.user.userId);
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                });
            }

            const beforeQuestions = Array.isArray(user.securityQuestions)
                ? user.securityQuestions.map((item) => item.question).filter(Boolean)
                : [];

            user.securityQuestions = await this.hashSecurityQuestions(normalizedSecurityQuestions);
            user.updatedAt = new Date();
            await user.save();

            const updatedQuestions = user.securityQuestions.map((item) => item.question);

            await auditLogService.record({
                actorUserId: user._id,
                action: 'USER_SECURITY_QUESTIONS_UPDATED',
                entityType: 'User',
                entityId: String(user._id),
                before: { securityQuestions: beforeQuestions },
                after: { securityQuestions: updatedQuestions },
                ipAddress: req.ip || '',
            });

            return res.json({
                success: true,
                message: 'Security questions updated successfully',
                securityQuestions: updatedQuestions,
            });
        } catch (error) {
            logger.error(`Update security questions error: ${error.message}`);
            return next(error);
        }
    }
}

module.exports = new AuthController();























