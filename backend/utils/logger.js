/**
 * Logger Utility
 */
// NOTE: Utility helpers: shared reusable functions/constants used across modules.


const winston = require('winston');

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ level, message, timestamp, stack }) => {
            if (stack) {
                return `${timestamp} [${level.toUpperCase()}]: ${message}\n${stack}`;
            }
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.printf(({ level, message, timestamp }) => {
                    return `${timestamp} ${level}: ${message}`;
                })
            ),
        }),
        new winston.transports.File({
            filename: 'logs/error.log',
            level: 'error',
            maxsize: 5242880,
            maxFiles: 5,
        }),
        new winston.transports.File({
            filename: 'logs/combined.log',
            maxsize: 5242880,
            maxFiles: 5,
        }),
    ],
});

module.exports = logger;
