// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const nistController = require('../controllers/nistController');
const { requirePermission } = require('../middleware/auth');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.get('/functions', requirePermission('incident:read'), withController(nistController, 'getFunctions'));
router.get('/controls/:threatType', requirePermission('incident:read'), withController(nistController, 'getControlsForThreatType'));
router.get('/mapping/:incidentId', requirePermission('incident:read'), withController(nistController, 'getMappingForIncident'));
router.get('/recommendations/:threatType', requirePermission('incident:read'), withController(nistController, 'getRecommendationsForThreatType'));
router.get('/compliance-report', requirePermission('incident:read'), withController(nistController, 'getComplianceReport'));

module.exports = router;
