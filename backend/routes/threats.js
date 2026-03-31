// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const threatController = require('../controllers/threatController');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.post('/analyze', withController(threatController, 'analyzeThreat'));
router.post('/classify', withController(threatController, 'classifyThreat'));
router.get('/knowledge-base', withController(threatController, 'getKnowledgeBase'));
router.get('/categories', withController(threatController, 'getThreatCategories'));
router.get('/types', withController(threatController, 'getThreatTypes'));
router.get('/details/:threatType', withController(threatController, 'getThreatDetails'));

module.exports = router;
