// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const { query } = require('express-validator');
const auditLogController = require('../controllers/auditLogController');
const { requirePermission, requireRole } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validateRequest');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

const auditLogQueryValidation = [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('scope').optional().isIn(['me', 'all']).withMessage('Scope must be me or all'),
    query('from').optional().isISO8601().withMessage('from must be a valid ISO date'),
    query('to').optional().isISO8601().withMessage('to must be a valid ISO date'),
    validateRequest,
];

router.get('/', requireRole('Admin'), requirePermission('user:manage'), auditLogQueryValidation, withController(auditLogController, 'getAuditLogs'));
router.get('/summary', requireRole('Admin'), requirePermission('user:manage'), withController(auditLogController, 'getAuditLogSummary'));

module.exports = router;
