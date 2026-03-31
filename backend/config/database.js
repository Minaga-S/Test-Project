/**
 * MongoDB Database Configuration
 */
// NOTE: Configuration: centralizes setup for external systems and runtime options.


const mongoose = require('mongoose');
const logger = require('../utils/logger');

let db = null;

async function connectDatabase() {
    try {
        const mongoURI = process.env.MONGODB_URI;

        if (!mongoURI) {
            throw new Error('MONGODB_URI is required');
        }

        const connection = await mongoose.connect(mongoURI, {
            maxPoolSize: 20,
            minPoolSize: 5,
            maxIdleTimeMS: 30000,
            waitQueueTimeoutMS: 5000,
            retryWrites: true,
            w: 'majority',
        });

        db = connection;

        // Event listeners
        mongoose.connection.on('connected', () => {
            logger.info('Mongoose connected to MongoDB');
        });

        mongoose.connection.on('error', (err) => {
            logger.error('Mongoose connection error:', err);
        });

        mongoose.connection.on('disconnected', () => {
            logger.warn('Mongoose disconnected from MongoDB');
        });

        return connection;

    } catch (error) {
        logger.error('Database connection failed:', error.message);
        throw error;
    }
}

async function closeDatabase() {
    try {
        if (db) {
            await mongoose.connection.close();
            logger.info('Database connection closed');
        }
    } catch (error) {
        logger.error('Error closing database:', error.message);
    }
}

function getDatabase() {
    if (!db) {
        throw new Error('Database not connected');
    }
    return db;
}

module.exports = {
    connectDatabase,
    closeDatabase,
    getDatabase,
};
