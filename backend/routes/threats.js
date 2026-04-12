// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const threatController = require('../controllers/threatController');
const { requirePermission } = require('../middleware/auth');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

// Threat analysis endpoints - use AI + live threat intelligence
router.post('/analyze', requirePermission('incident:write'), withController(threatController, 'analyzeThreat'));
router.post('/classify', requirePermission('incident:write'), withController(threatController, 'classifyThreat'));

// Threat type endpoints - sourced from nistThreatIntelService
router.get('/types', requirePermission('incident:read'), withController(threatController, 'getThreatTypes'));
router.get('/details/:threatType', requirePermission('incident:read'), withController(threatController, 'getThreatDetails'));

// NOTE: Removed endpoints:
// - GET /threats/knowledge-base (use /types and /details instead)
// - GET /threats/categories (inferred from threat types)

module.exports = router;
