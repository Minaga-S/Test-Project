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
        const user = await User.findById(decoded.userId).select('isActive passwordChangedAt permissions role sessionVersion');

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

        const tokenSessionVersion = Number(decoded.sessionVersion || 0);
        const currentSessionVersion = Number(user.sessionVersion || 0);
        if (tokenSessionVersion !== currentSessionVersion) {
            return res.status(401).json({
                success: false,
                message: 'Session expired after a security change. Please log in again.',
            });
        }

        req.user = {
            ...decoded,
            role: user.role || decoded.role,
            permissions: Array.isArray(user.permissions) ? user.permissions : (decoded.permissions || []),
        };
        next();
    } catch (error) {
        logger.error('Auth error:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token',
        });
    }
}

function requirePermission(requiredPermission) {
    return function permissionMiddleware(req, res, next) {
        const permissions = Array.isArray(req.user?.permissions) ? req.user.permissions : [];

        if (!permissions.includes(requiredPermission)) {
            return res.status(403).json({
                success: false,
                message: 'Forbidden',
            });
        }

        return next();
    };
}

function requireRole(requiredRole) {
    return function roleMiddleware(req, res, next) {
        const role = String(req.user?.role || '').trim();

        if (role !== requiredRole) {
            return res.status(403).json({
                success: false,
                message: 'Forbidden',
            });
        }

        return next();
    };
}

module.exports = { authMiddleware, requirePermission, requireRole };

