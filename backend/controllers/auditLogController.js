/**
 * Audit Log Controller
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

function toPositiveInteger(value, fallbackValue) {
    const parsedValue = Number.parseInt(value, 10);
    if (!Number.isInteger(parsedValue) || parsedValue <= 0) {
        return fallbackValue;
    }

    return parsedValue;
}

function parseDate(value) {
    if (!value) {
        return null;
    }

    const dateValue = new Date(value);
    if (Number.isNaN(dateValue.getTime())) {
        return null;
    }

    return dateValue;
}

class AuditLogController {
    async getAuditLogs(req, res, next) {
        try {
            const page = toPositiveInteger(req.query.page, DEFAULT_PAGE);
            const requestedLimit = toPositiveInteger(req.query.limit, DEFAULT_LIMIT);
            const limit = Math.min(requestedLimit, MAX_LIMIT);
            const skip = (page - 1) * limit;

            const filters = {};
            const requestedScope = String(req.query.scope || 'me').trim().toLowerCase();
            const canReadAll = req.user?.role === 'Admin';

            if (!canReadAll || requestedScope !== 'all') {
                filters.actorUserId = req.user.userId;
            }

            const action = String(req.query.action || '').trim();
            if (action) {
                filters.action = action;
            }

            const entityType = String(req.query.entityType || '').trim();
            if (entityType) {
                filters.entityType = entityType;
            }

            const fromDate = parseDate(req.query.from);
            const toDate = parseDate(req.query.to);
            if (fromDate || toDate) {
                filters.createdAt = {};
                if (fromDate) {
                    filters.createdAt.$gte = fromDate;
                }
                if (toDate) {
                    filters.createdAt.$lte = toDate;
                }
            }

            const searchTerm = String(req.query.search || '').trim();
            if (searchTerm) {
                const searchPattern = new RegExp(searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
                filters.$or = [
                    { action: searchPattern },
                    { entityType: searchPattern },
                    { entityId: searchPattern },
                    { ipAddress: searchPattern },
                ];
            }

            const [logs, total] = await Promise.all([
                AuditLog.find(filters)
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit),
                AuditLog.countDocuments(filters),
            ]);

            return res.json({
                success: true,
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit),
                logs,
            });
        } catch (error) {
            logger.error('Get audit logs error:', error.message);
            return next(error);
        }
    }

    async getAuditLogSummary(req, res, next) {
        try {
            const canReadAll = req.user?.role === 'Admin';
            const baseMatch = {};
            if (!canReadAll) {
                baseMatch.actorUserId = req.user.userId;
            }

            const [actionSummary, entitySummary] = await Promise.all([
                AuditLog.aggregate([
                    { $match: baseMatch },
                    { $group: { _id: '$action', count: { $sum: 1 } } },
                    { $sort: { count: -1 } },
                ]),
                AuditLog.aggregate([
                    { $match: baseMatch },
                    { $group: { _id: '$entityType', count: { $sum: 1 } } },
                    { $sort: { count: -1 } },
                ]),
            ]);

            return res.json({
                success: true,
                actions: actionSummary,
                entities: entitySummary,
            });
        } catch (error) {
            logger.error('Get audit log summary error:', error.message);
            return next(error);
        }
    }
}

module.exports = new AuditLogController();
