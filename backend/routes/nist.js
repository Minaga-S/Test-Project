// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const nistController = require('../controllers/nistController');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.get('/functions', withController(nistController, 'getFunctions'));
router.get('/controls/:threatType', withController(nistController, 'getControlsForThreatType'));
router.get('/mapping/:incidentId', withController(nistController, 'getMappingForIncident'));
router.get('/recommendations/:threatType', withController(nistController, 'getRecommendationsForThreatType'));

module.exports = router;
