const express = require('express');
const authController = require('../controllers/authController');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.post('/register', withController(authController, 'register'));
router.post('/login', withController(authController, 'login'));
router.get('/profile', authMiddleware, withController(authController, 'getProfile'));
router.put('/profile', authMiddleware, withController(authController, 'updateProfile'));
router.post('/change-password', authMiddleware, withController(authController, 'changePassword'));

module.exports = router;