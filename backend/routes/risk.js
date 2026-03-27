const express = require('express');
const riskController = require('../controllers/riskController');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.post('/calculate', withController(riskController, 'calculateRisk'));
router.get('/assessment/:incidentId', withController(riskController, 'getRiskAssessment'));
router.get('/matrix', withController(riskController, 'getRiskMatrix'));
router.get('/trends', withController(riskController, 'getRiskTrends'));
router.get('/by-asset', withController(riskController, 'getRiskByAsset'));
router.get('/summary', withController(riskController, 'getRiskSummary'));

module.exports = router;