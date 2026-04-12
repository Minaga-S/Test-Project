// NOTE: Local scanner routes provide a secure bridge between browser and local nmap companion app.

const express = require('express');
const { body } = require('express-validator');
const localScannerController = require('../controllers/localScannerController');
const { authMiddleware, requirePermission } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validateRequest');
const { enrichmentLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

const PROFILE_TEXT_PATTERN = /^[a-zA-Z0-9 .,_\-/():|+%]{0,160}$/;
const PROFILE_VERSION_PATTERN = /^[a-zA-Z0-9 ._\-]{0,40}$/;

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

const createScanRequestValidation = [
    body('assetId').optional().isString().trim(),
    body('assetName').optional().isString().trim(),
    body('assetType').optional().isString().trim(),
    body('liveScan.target').isString().trim().notEmpty().withMessage('liveScan.target is required'),
    body('liveScan.ports').optional().isString().trim(),
    body('vulnerabilityProfile.osName').optional().trim().matches(PROFILE_TEXT_PATTERN).withMessage('OS name contains invalid characters'),
    body('vulnerabilityProfile.vendor').optional().trim().matches(PROFILE_TEXT_PATTERN).withMessage('Vendor contains invalid characters'),
    body('vulnerabilityProfile.product').optional().trim().matches(PROFILE_TEXT_PATTERN).withMessage('Product contains invalid characters'),
    body('vulnerabilityProfile.productVersion').optional().trim().matches(PROFILE_VERSION_PATTERN).withMessage('Product version contains invalid characters'),
    body('vulnerabilityProfile.cpeUri').optional().isString().trim(),
    validateRequest,
];

const submitResultValidation = [
    body('bridgeToken').isString().trim().notEmpty().withMessage('bridgeToken is required'),
    body('scanResult').isObject().withMessage('scanResult is required'),
    body('scanResult.target').optional().isString().trim(),
    body('scanResult.requestedPorts').optional().isString().trim(),
    body('scanResult.openPorts').optional().isArray(),
    body('scanResult.services').optional().isArray(),
    body('scanResult.osInfo').optional().isString().trim(),
    body('scanResult.osCpe').optional().isString().trim(),
    body('scanResult.rawOutput').optional().isString(),
    validateRequest,
];

router.post('/requests', authMiddleware, requirePermission('asset:write'), enrichmentLimiter, createScanRequestValidation, withController(localScannerController, 'createScanRequest'));
router.post('/results', enrichmentLimiter, submitResultValidation, withController(localScannerController, 'submitScanResult'));

module.exports = router;
