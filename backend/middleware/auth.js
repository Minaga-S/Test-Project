// NOTE: Middleware: runs before controllers for cross-cutting concerns like auth and validation.

const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

async function authMiddleware(req, res, next) {
    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'No token provided',
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();

    } catch (error) {
        logger.error('Auth error:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token',
        });
    }
}

module.exports = { authMiddleware };
