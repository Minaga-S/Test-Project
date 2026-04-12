// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const dashboardController = require('../controllers/dashboardController');
const { requirePermission } = require('../middleware/auth');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.get('/metrics', requirePermission('dashboard:read'), withController(dashboardController, 'getMetrics'));
router.get('/metrics/trends', requirePermission('dashboard:read'), withController(dashboardController, 'getMetricsTrends'));
router.get('/charts/risk-distribution', requirePermission('dashboard:read'), withController(dashboardController, 'getRiskDistributionChart'));
router.get('/charts/threat-categories', requirePermission('dashboard:read'), withController(dashboardController, 'getThreatCategoriesChart'));
router.get('/charts/vulnerable-assets', requirePermission('dashboard:read'), withController(dashboardController, 'getVulnerableAssetsChart'));
router.get('/recent-incidents', requirePermission('dashboard:read'), withController(dashboardController, 'getRecentIncidents'));
router.get('/overview', requirePermission('dashboard:read'), withController(dashboardController, 'getOverview'));

module.exports = router;
