// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const { body, param } = require('express-validator');
const incidentController = require('../controllers/incidentController');
const { requirePermission } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validateRequest');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

const incidentIdValidation = [
    param('id').isMongoId().withMessage('Invalid incident id'),
    validateRequest,
];

const createIncidentValidation = [
    body('assetId').isMongoId().withMessage('Asset id must be a valid ObjectId'),
    body('description').trim().isLength({ min: 20 }).withMessage('Description must be at least 20 characters'),
    body('guestAffected').optional().isBoolean().withMessage('guestAffected must be a boolean'),
    body('paymentsAffected').optional().isBoolean().withMessage('paymentsAffected must be a boolean'),
    body('sensitiveDataInvolved').optional().isBoolean().withMessage('sensitiveDataInvolved must be a boolean'),
    body('clientSecurityContext').optional().isObject().withMessage('clientSecurityContext must be an object'),
    validateRequest,
];

router.post('/', requirePermission('incident:write'), createIncidentValidation, withController(incidentController, 'createIncident'));
router.get('/', requirePermission('incident:read'), withController(incidentController, 'getIncidents'));
router.get('/search', requirePermission('incident:read'), withController(incidentController, 'searchIncidents'));
router.get('/:id', requirePermission('incident:read'), incidentIdValidation, withController(incidentController, 'getIncident'));
router.put('/:id', requirePermission('incident:write'), incidentIdValidation, withController(incidentController, 'updateIncident'));
router.put('/:id/status', requirePermission('incident:write'), incidentIdValidation, withController(incidentController, 'updateIncidentStatus'));
router.post('/:id/notes', requirePermission('incident:write'), incidentIdValidation, withController(incidentController, 'addNote'));
router.delete('/:id', requirePermission('incident:write'), incidentIdValidation, withController(incidentController, 'deleteIncident'));

module.exports = router;