/**
 * Hotel Cybersecurity Governance System
 * Main Server File
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const { connectDatabase, closeDatabase } = require('./config/database');
const { errorHandler } = require('./middleware/errorHandler');
const { authMiddleware } = require('./middleware/auth');
const { seedDatabase } = require('./scripts/seedDatabase');

const app = express();

// ============== MIDDLEWARE ==============

// Security middleware
app.use(helmet());

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
];

const effectiveAllowedOrigins = allowedOrigins.length > 0
    ? allowedOrigins
    : defaultAllowedOrigins;

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) {
            return callback(null, true);
        }

        const requestOrigin = normalizeOrigin(origin);
        const isGithubPagesOrigin = /^https:\/\/[a-z0-9-]+\.github\.io$/i.test(requestOrigin);
        const isAllowed = effectiveAllowedOrigins.includes(requestOrigin) || isGithubPagesOrigin;

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

// Protected routes (authentication required)
app.use('/api/assets', authMiddleware, require('./routes/assets'));
app.use('/api/incidents', authMiddleware, require('./routes/incidents'));
app.use('/api/threats', authMiddleware, require('./routes/threats'));
app.use('/api/risk', authMiddleware, require('./routes/risk'));
app.use('/api/nist', authMiddleware, require('./routes/nist'));
app.use('/api/dashboard', authMiddleware, require('./routes/dashboard'));

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

async function startServer() {
    try {
        // Connect to database
        await connectDatabase();
        console.log('✓ Database connected');

        // Seed database with test users
        await seedDatabase();

        // Start server
        const server = app.listen(PORT, () => {
            console.log(`✓ Server running on port ${PORT}`);
            console.log(`✓ Environment: ${process.env.NODE_ENV}`);
        });

        // Graceful shutdown
        process.on('SIGINT', async () => {
            console.log('\n✗ SIGINT received, shutting down gracefully...');
            server.close(async () => {
                await closeDatabase();
                console.log('✓ Server closed');
                process.exit(0);
            });
        });

        process.on('SIGTERM', async () => {
            console.log('\n✗ SIGTERM received, shutting down gracefully...');
            server.close(async () => {
                await closeDatabase();
                console.log('✓ Server closed');
                process.exit(0);
            });
        });

    } catch (error) {
        console.error('✗ Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();

module.exports = app;