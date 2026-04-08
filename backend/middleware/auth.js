// NOTE: Middleware: runs before controllers for cross-cutting concerns like auth and validation.

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

function tokenIssuedBeforePasswordChange(decodedToken, user) {
    if (!decodedToken?.iat || !user?.passwordChangedAt) {
        return false;
    }

    const passwordChangedAtSeconds = Math.floor(user.passwordChangedAt.getTime() / 1000);
    return decodedToken.iat < passwordChangedAtSeconds;
}

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
        const user = await User.findById(decoded.userId).select('isActive passwordChangedAt');

        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired token',
            });
        }

        if (tokenIssuedBeforePasswordChange(decoded, user)) {
            return res.status(401).json({
                success: false,
                message: 'Session expired after password change. Please log in again.',
            });
        }

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

