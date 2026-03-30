const express = require('express');
const { body, param } = require('express-validator');
const assetController = require('../controllers/assetController');
const { validateRequest } = require('../middleware/validateRequest');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

const objectIdValidation = [
    param('id').isMongoId().withMessage('Invalid asset id'),
    validateRequest,
];

const createAssetValidation = [
    body('assetName').trim().notEmpty().withMessage('Asset name is required'),
    body('assetType').trim().notEmpty().withMessage('Asset type is required'),
    validateRequest,
];

router.post('/', createAssetValidation, withController(assetController, 'createAsset'));
router.get('/', withController(assetController, 'getAssets'));
router.get('/asset-types', withController(assetController, 'getAssetTypes'));
router.get('/search', withController(assetController, 'searchAssets'));
router.get('/:id', objectIdValidation, withController(assetController, 'getAsset'));
router.put('/:id', objectIdValidation, withController(assetController, 'updateAsset'));
router.delete('/:id', objectIdValidation, withController(assetController, 'deleteAsset'));

module.exports = router;
