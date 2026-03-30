const express = require('express');
const { body, param } = require('express-validator');
const incidentController = require('../controllers/incidentController');
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
    validateRequest,
];

router.post('/', createIncidentValidation, withController(incidentController, 'createIncident'));
router.get('/', withController(incidentController, 'getIncidents'));
router.get('/search', withController(incidentController, 'searchIncidents'));
router.get('/:id', incidentIdValidation, withController(incidentController, 'getIncident'));
router.put('/:id', incidentIdValidation, withController(incidentController, 'updateIncident'));
router.put('/:id/status', incidentIdValidation, withController(incidentController, 'updateIncidentStatus'));
router.post('/:id/notes', incidentIdValidation, withController(incidentController, 'addNote'));
router.delete('/:id', incidentIdValidation, withController(incidentController, 'deleteIncident'));

module.exports = router;
