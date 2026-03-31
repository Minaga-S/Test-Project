// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const dashboardController = require('../controllers/dashboardController');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.get('/metrics', withController(dashboardController, 'getMetrics'));
router.get('/charts/risk-distribution', withController(dashboardController, 'getRiskDistributionChart'));
router.get('/charts/threat-categories', withController(dashboardController, 'getThreatCategoriesChart'));
router.get('/charts/vulnerable-assets', withController(dashboardController, 'getVulnerableAssetsChart'));
router.get('/recent-incidents', withController(dashboardController, 'getRecentIncidents'));
router.get('/overview', withController(dashboardController, 'getOverview'));

module.exports = router;
