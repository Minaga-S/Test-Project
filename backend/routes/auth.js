// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const { authMiddleware } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { validateRequest } = require('../middleware/validateRequest');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

const registerValidation = [
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('fullName').trim().notEmpty().withMessage('Full name is required'),
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
    body('department').optional().trim(),
    validateRequest,
];

const changePasswordValidation = [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters'),
    validateRequest,
];

router.post('/register', authLimiter, registerValidation, withController(authController, 'register'));
router.post('/login', authLimiter, loginValidation, withController(authController, 'login'));
router.post('/refresh', authLimiter, refreshValidation, withController(authController, 'refreshToken'));
router.get('/profile', authMiddleware, withController(authController, 'getProfile'));
router.put('/profile', authMiddleware, updateProfileValidation, withController(authController, 'updateProfile'));
router.post('/change-password', authMiddleware, changePasswordValidation, withController(authController, 'changePassword'));

module.exports = router;

