const express = require('express');
const assetController = require('../controllers/assetController');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

router.post('/', withController(assetController, 'createAsset'));
router.get('/', withController(assetController, 'getAssets'));
router.get('/asset-types', withController(assetController, 'getAssetTypes'));
router.get('/search', withController(assetController, 'searchAssets'));
router.get('/:id', withController(assetController, 'getAsset'));
router.put('/:id', withController(assetController, 'updateAsset'));
router.delete('/:id', withController(assetController, 'deleteAsset'));

module.exports = router;