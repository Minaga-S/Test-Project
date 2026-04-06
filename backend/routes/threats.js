// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const threatController = require('../controllers/threatController');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

// Threat analysis endpoints - use AI + live threat intelligence
router.post('/analyze', withController(threatController, 'analyzeThreat'));
router.post('/classify', withController(threatController, 'classifyThreat'));

// Threat type endpoints - sourced from nistThreatIntelService
router.get('/types', withController(threatController, 'getThreatTypes'));
router.get('/details/:threatType', withController(threatController, 'getThreatDetails'));

// NOTE: Removed endpoints:
// - GET /threats/knowledge-base (use /types and /details instead)
// - GET /threats/categories (inferred from threat types)

module.exports = router;
