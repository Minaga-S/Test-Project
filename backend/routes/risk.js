// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const riskController = require('../controllers/riskController');
const { requirePermission } = require('../middleware/auth');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.post('/calculate', requirePermission('incident:write'), withController(riskController, 'calculateRisk'));
router.get('/assessment/:incidentId', requirePermission('incident:read'), withController(riskController, 'getRiskAssessment'));
router.get('/matrix', requirePermission('incident:read'), withController(riskController, 'getRiskMatrix'));
router.get('/trends', requirePermission('incident:read'), withController(riskController, 'getRiskTrends'));
router.get('/by-asset', requirePermission('incident:read'), withController(riskController, 'getRiskByAsset'));
router.get('/summary', requirePermission('incident:read'), withController(riskController, 'getRiskSummary'));

module.exports = router;
