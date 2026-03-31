// NOTE: Middleware: runs before controllers for cross-cutting concerns like auth and validation.

const rateLimit = require('express-rate-limit');

const WINDOW_MS = 15 * 60 * 1000;

const apiLimiter = rateLimit({
    windowMs: WINDOW_MS,
    max: 500,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many requests. Please try again later.',
    },
});

const authLimiter = rateLimit({
    windowMs: WINDOW_MS,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many authentication attempts. Please try again later.',
    },
});

module.exports = {
    apiLimiter,
    authLimiter,
};

