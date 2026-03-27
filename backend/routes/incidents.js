const express = require('express');
const incidentController = require('../controllers/incidentController');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.post('/', withController(incidentController, 'createIncident'));
router.get('/', withController(incidentController, 'getIncidents'));
router.get('/search', withController(incidentController, 'searchIncidents'));
router.get('/:id', withController(incidentController, 'getIncident'));
router.put('/:id', withController(incidentController, 'updateIncident'));
router.put('/:id/status', withController(incidentController, 'updateIncidentStatus'));
router.post('/:id/notes', withController(incidentController, 'addNote'));
router.delete('/:id', withController(incidentController, 'deleteIncident'));

module.exports = router;