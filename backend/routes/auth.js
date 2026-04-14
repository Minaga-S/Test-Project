// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const { authMiddleware } = require('../middleware/auth');
const { authLimiter, passwordResetLimiter } = require('../middleware/rateLimiter');
const { validateRequest } = require('../middleware/validateRequest');
const { DEPARTMENTS } = require('../utils/constants');

const router = express.Router();
const REQUIRED_SECURITY_QUESTION_COUNT = 3;

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

const hasValidSecurityQuestionSet = (value) => {
    if (!Array.isArray(value) || value.length !== REQUIRED_SECURITY_QUESTION_COUNT) {
        return false;
    }

    const normalizedQuestions = value
        .map((item) => String(item?.question || '').trim().toLowerCase())
        .filter(Boolean);

    if (normalizedQuestions.length !== REQUIRED_SECURITY_QUESTION_COUNT) {
        return false;
    }

    const hasUniqueQuestions = new Set(normalizedQuestions).size === REQUIRED_SECURITY_QUESTION_COUNT;
    const hasAnswers = value.every((item) => String(item?.answer || '').trim().length > 0);

    return hasUniqueQuestions && hasAnswers;
};

const registerValidation = [
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('fullName').trim().notEmpty().withMessage('Full name is required'),
    body('department').trim().isIn(DEPARTMENTS).withMessage('Valid department is required'),
    body('securityQuestions').custom((value) => {
        if (!hasValidSecurityQuestionSet(value)) {
            throw new Error('Provide exactly 3 unique security questions with answers');
        }

        return true;
    }),
    validateRequest,
];

const loginValidation = [
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required'),
    validateRequest,
];

const refreshValidation = [
    body('refreshToken').notEmpty().withMessage('Refresh token is required'),
    validateRequest,
];

const updateProfileValidation = [
    body('fullName').optional().trim().notEmpty().withMessage('Full name cannot be empty'),
    body('department').optional({ checkFalsy: true }).trim().isIn(DEPARTMENTS).withMessage('Valid department is required'),
    validateRequest,
];

const securityQuestionsValidation = [
    body('securityQuestions').custom((value) => {
        if (!hasValidSecurityQuestionSet(value)) {
            throw new Error('Provide exactly 3 unique security questions with answers');
        }

        return true;
    }),
    validateRequest,
];

const changePasswordValidation = [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters'),
    validateRequest,
];

const forgotPasswordValidation = [
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    validateRequest,
];

const resetPasswordValidation = [
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('newPassword').isLength({ min: 12 }).withMessage('New password must be at least 12 characters'),
    body('totpCode').optional({ nullable: true }).isString(),
    body('recoveryCode').optional({ nullable: true }).isString(),
    body('securityAnswers').optional({ nullable: true }).isArray(),
    body().custom((value) => {
        const hasTotpCode = Boolean(value?.totpCode && String(value.totpCode).trim());
        const hasRecoveryCode = Boolean(value?.recoveryCode && String(value.recoveryCode).trim());
        const hasSecurityAnswers = hasValidSecurityQuestionSet(value?.securityAnswers);

        if (!hasTotpCode && !hasRecoveryCode && !hasSecurityAnswers) {
            throw new Error('Provide security answers or a 2FA code/recovery code');
        }

        return true;
    }),
    validateRequest,
];

const twoFactorCodeValidation = [
    body('code').matches(/^\d{6}$/).withMessage('2FA code must be 6 digits'),
    validateRequest,
];

const verifyTwoFactorLoginValidation = [
    body('challengeToken').notEmpty().withMessage('Challenge token is required'),
    body('code').matches(/^\d{6}$/).withMessage('2FA code must be 6 digits'),
    validateRequest,
];

router.post('/register', authLimiter, registerValidation, withController(authController, 'register'));
router.post('/login', authLimiter, loginValidation, withController(authController, 'login'));
router.post('/refresh', authLimiter, refreshValidation, withController(authController, 'refreshToken'));
router.post('/forgot-password', passwordResetLimiter, forgotPasswordValidation, withController(authController, 'forgotPassword'));
router.post('/reset-password', passwordResetLimiter, resetPasswordValidation, withController(authController, 'resetPassword'));
router.post('/2fa/verify-login', authLimiter, verifyTwoFactorLoginValidation, withController(authController, 'verifyTwoFactorLogin'));
router.post('/2fa/setup', authMiddleware, withController(authController, 'setupTwoFactor'));
router.post('/2fa/enable', authMiddleware, twoFactorCodeValidation, withController(authController, 'enableTwoFactor'));
router.post('/2fa/disable', authMiddleware, twoFactorCodeValidation, withController(authController, 'disableTwoFactor'));
router.get('/profile', authMiddleware, withController(authController, 'getProfile'));
router.put('/profile', authMiddleware, updateProfileValidation, withController(authController, 'updateProfile'));
router.get('/security-questions', authMiddleware, withController(authController, 'getSecurityQuestions'));
router.put('/security-questions', authMiddleware, securityQuestionsValidation, withController(authController, 'updateSecurityQuestions'));
router.post('/change-password', authMiddleware, changePasswordValidation, withController(authController, 'changePassword'));

module.exports = router;
