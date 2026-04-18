/**
 * Hotel Cybersecurity Governance System
 * Main Server File
 */
// NOTE: Application entrypoint: wires middleware, routes, and server startup lifecycle.


const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const { connectDatabase, closeDatabase } = require('./config/database');
const { errorHandler } = require('./middleware/errorHandler');
const { authMiddleware } = require('./middleware/auth');
const { apiLimiter } = require('./middleware/rateLimiter');
const logger = require('./utils/logger');

const app = express();

// ============== MIDDLEWARE ==============

// Security middleware
app.set('trust proxy', 1);
app.use(helmet());
app.use(apiLimiter);

app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim()),
    },
}));

const normalizeOrigin = (value = '') => value
    .trim()
    .replace(/^['\"]|['\"]$/g, '')
    .replace(/\/$/, '')
    .toLowerCase();

const allowedOrigins = (process.env.CORS_ORIGIN || '')
    .split(',')
    .map((origin) => normalizeOrigin(origin))
    .filter(Boolean);

const defaultAllowedOrigins = [
    'https://minaga-s.github.io',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5500',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:5500',
    'http://192.168.21.1:3000',
];

const effectiveAllowedOrigins = [
    ...new Set([...defaultAllowedOrigins, ...allowedOrigins]),
];

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) {
            // Allow non-browser and same-origin calls (health checks, server-to-server).
            return callback(null, true);
        }

        const requestOrigin = normalizeOrigin(origin);
        const isAllowed = effectiveAllowedOrigins.includes(requestOrigin);

        if (isAllowed) {
            return callback(null, true);
        }

        return callback(new Error(`Not allowed by CORS: ${requestOrigin}`));
    },
    credentials: true,
    optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// ============== ROUTES ==============

// Auth routes (no authentication required)
app.use('/api/auth', require('./routes/auth'));
app.use('/api/local-scanner', require('./routes/localScanner'));

// Protected routes (authentication required)
app.use('/api/assets', authMiddleware, require('./routes/assets'));
app.use('/api/incidents', authMiddleware, require('./routes/incidents'));
app.use('/api/threats', authMiddleware, require('./routes/threats'));
app.use('/api/risk', authMiddleware, require('./routes/risk'));
app.use('/api/nist', authMiddleware, require('./routes/nist'));
app.use('/api/dashboard', authMiddleware, require('./routes/dashboard'));
app.use('/api/audit-logs', authMiddleware, require('./routes/auditLogs'));

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date() });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Hotel Cybersecurity Governance API is running',
        health: '/health',
    });
});

// ============== ERROR HANDLING ==============

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found',
        path: req.path,
    });
});

// Global error handler
app.use(errorHandler);

// ============== SERVER STARTUP ==============

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '127.0.0.1';

async function startServer() {
    try {
        // Connect to database
        await connectDatabase();
        console.log('? Database connected');

        // Start server
        const server = app.listen(PORT, HOST, () => {
            console.log(`? Server running on http://${HOST}:${PORT}`);
            console.log(`? Environment: ${process.env.NODE_ENV}`);
        });

        // Graceful shutdown
        process.on('SIGINT', async () => {
            console.log('\n? SIGINT received, shutting down gracefully...');
            server.close(async () => {
                await closeDatabase();
                console.log('? Server closed');
                process.exit(0);
            });
        });

        process.on('SIGTERM', async () => {
            console.log('\n? SIGTERM received, shutting down gracefully...');
            server.close(async () => {
                await closeDatabase();
                console.log('? Server closed');
                process.exit(0);
            });
        });

    } catch (error) {
        console.error('? Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();

module.exports = app;


