// NOTE: Route map: connects URL endpoints to controller methods and request validation.

const express = require('express');
const { body, param } = require('express-validator');
const assetController = require('../controllers/assetController');
const { requirePermission } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validateRequest');
const { enrichmentLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

const LIVE_SCAN_FREQUENCIES = ['OnDemand', 'Daily', 'Weekly'];
const CPE_URI_PATTERN = /^(cpe:2\.3:[aho]:[a-z0-9._-]+:[a-z0-9._-]+:[a-z0-9*._-]*(:[a-z0-9*._-]*){0,7}|cpe:\/[aho]:[a-z0-9._-]+:[a-z0-9._-]+(:[a-z0-9*._-]*){0,7})$/i;
const PROFILE_TEXT_PATTERN = /^[a-zA-Z0-9 .,_\-/():|+%]{0,160}$/;
const PROFILE_VERSION_PATTERN = /^[a-zA-Z0-9 ._\-]{0,40}$/;

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

function normalizeCpeUri(value) {
    const rawValue = String(value || '').trim();
    if (!rawValue) {
        return '';
    }

    const tokenMatch = rawValue.match(/(cpe:2\.3:[^\s,;]+|cpe:\/[^\s,;]+)/i);
    if (!tokenMatch) {
        return '';
    }

    return tokenMatch[1].replace(/[)\].,;\/]+$/, '');
}

function isValidCpeUri(value) {
    const normalized = normalizeCpeUri(value);
    return normalized === '' || CPE_URI_PATTERN.test(normalized);
}

const objectIdValidation = [
    param('id').isMongoId().withMessage('Invalid asset id'),
    validateRequest,
];

const assetBodyValidation = [
    body('assetName').optional().trim().notEmpty().withMessage('Asset name is required'),
    body('assetType').optional().trim().notEmpty().withMessage('Asset type is required'),
    body('liveScan.enabled').optional().isBoolean().withMessage('Live scan enabled must be a boolean'),
    body('liveScan.target').optional().isString().trim(),
    body('liveScan.ports').optional().isString().trim(),
    body('liveScan.frequency').optional().isIn(LIVE_SCAN_FREQUENCIES).withMessage('Invalid live scan frequency'),
    body('vulnerabilityProfile.osName').optional().trim().matches(PROFILE_TEXT_PATTERN).withMessage('OS name contains invalid characters'),
    body('vulnerabilityProfile.vendor').optional().trim().matches(PROFILE_TEXT_PATTERN).withMessage('Vendor contains invalid characters'),
    body('vulnerabilityProfile.product').optional().trim().matches(PROFILE_TEXT_PATTERN).withMessage('Product contains invalid characters'),
    body('vulnerabilityProfile.productVersion').optional().trim().matches(PROFILE_VERSION_PATTERN).withMessage('Product version contains invalid characters'),
    body('vulnerabilityProfile.cpeUri').optional().trim().custom((value, { req }) => {
        const normalizedCpeUri = normalizeCpeUri(value);
        if (req.body?.vulnerabilityProfile) {
            req.body.vulnerabilityProfile.cpeUri = normalizedCpeUri;
        }

        return isValidCpeUri(normalizedCpeUri);
    }).withMessage('CPE URI must use cpe:2.3 or cpe:/ format'),
    validateRequest,
];

const createAssetValidation = [
    body('assetName').trim().notEmpty().withMessage('Asset name is required'),
    body('assetType').trim().notEmpty().withMessage('Asset type is required'),
    ...assetBodyValidation,
];

router.post('/', requirePermission('asset:write'), createAssetValidation, withController(assetController, 'createAsset'));
router.get('/', requirePermission('asset:read'), withController(assetController, 'getAssets'));
router.get('/asset-types', requirePermission('asset:read'), withController(assetController, 'getAssetTypes'));
router.get('/search', requirePermission('asset:read'), withController(assetController, 'searchAssets'));
router.get('/:id/security-context', requirePermission('asset:read'), enrichmentLimiter, objectIdValidation, withController(assetController, 'getAssetSecurityContext'));
router.get('/:id/scan-history', requirePermission('asset:read'), objectIdValidation, withController(assetController, 'getAssetScanHistory'));

router.get('/:id', requirePermission('asset:read'), objectIdValidation, withController(assetController, 'getAsset'));
router.put('/:id', requirePermission('asset:write'), objectIdValidation, assetBodyValidation, withController(assetController, 'updateAsset'));
router.delete('/:id', requirePermission('asset:write'), objectIdValidation, withController(assetController, 'deleteAsset'));

module.exports = router;





