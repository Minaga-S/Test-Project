// NOTE: Middleware: runs before controllers for cross-cutting concerns like auth and validation.

const logger = require('../utils/logger');

function sanitizeForLog(err) {
    return {
        message: String(err?.message || 'Unknown error')
            .replace(/(password|token|secret|apikey|api_key)=([^\s]+)/gi, '$1=[REDACTED]'),
        stack: err?.stack || '',
        code: err?.code || '',
        name: err?.name || 'Error',
    };
}

function errorHandler(err, req, res, next) {
    const safeError = sanitizeForLog(err);

    logger.error('Unhandled error', {
        message: safeError.message,
        stack: safeError.stack,
        code: safeError.code,
        name: safeError.name,
        path: req.path,
        method: req.method,
    });

    if (err.name === 'ValidationError') {
        const messages = Object.values(err.errors).map((e) => e.message);
        return res.status(400).json({
            success: false,
            message: 'Validation error',
            errors: messages,
        });
    }

    if (err.code === 11000) {
        return res.status(400).json({
            success: false,
            message: 'Duplicate field value',
        });
    }

    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            message: 'Invalid token',
        });
    }

    if (err.status && err.status < 500) {
        return res.status(err.status).json({
            success: false,
            message: err.message || 'Request failed',
        });
    }

    return res.status(500).json({
        success: false,
        message: 'Internal server error',
    });
}

module.exports = { errorHandler };