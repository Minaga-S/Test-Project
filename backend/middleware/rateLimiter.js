// NOTE: Middleware: runs before controllers for cross-cutting concerns like auth and validation.

const rateLimit = require('express-rate-limit');

const WINDOW_MS = 15 * 60 * 1000;

function getRequestIdentity(req) {
    if (req?.user?.userId) {
        return String(req.user.userId);
    }

    return req.ip;
}

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

const passwordResetLimiter = rateLimit({
    windowMs: WINDOW_MS,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many password reset attempts. Please try again shortly.',
    },
});

const enrichmentLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyGenerator: getRequestIdentity,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many enrichment requests. Please slow down.',
    },
});

module.exports = {
    apiLimiter,
    authLimiter,
    passwordResetLimiter,
    enrichmentLimiter,
};
