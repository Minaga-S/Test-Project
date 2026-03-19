/**
 * Asset Controller
 */

const Asset = require('../models/Asset');
const { ASSET_TYPES } = require('../utils/constants');
const { validateAsset } = require('../utils/validators');
const logger = require('../utils/logger');

class AssetController {
    /**
     * Create asset
     */
    async createAsset(req, res, next) {
        try {
            // Validate input
            const validation = validateAsset(req.body);
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: validation.errors,
                });
            }

            const asset = new Asset({
                assetName: req.body.assetName,
                assetType: req.body.assetType,
                description: req.body.description,
                location: req.body.location,
                status: req.body.status || 'Active',
                criticality: req.body.criticality || 'Medium',
                owner: req.body.owner,
                userId: req.user.userId,
            });

            await asset.save();

            logger.info(`Asset created: ${asset._id} by user ${req.user.userId}`);

            res.status(201).json({
                success: true,
                message: 'Asset created successfully',
                asset,
            });

        } catch (error) {
            logger.error('Create asset error:', error.message);
            next(error);
        }
    }

    /**
     * Get all assets
     */
    async getAssets(req, res, next) {
        try {
            const assets = await Asset.find({ userId: req.user.userId })
                .sort({ createdAt: -1 });

            res.json({
                success: true,
                count: assets.length,
                assets,
            });

        } catch (error) {
            logger.error('Get assets error:', error.message);
            next(error);
        }
    }

    /**
     * Get asset by ID
     */
    async getAsset(req, res, next) {
        try {
            const asset = await Asset.findOne({
                _id: req.params.id,
                userId: req.user.userId,
            });

            if (!asset) {
                return res.status(404).json({
                    success: false,
                    message: 'Asset not found',
                });
            }

            res.json({
                success: true,
                asset,
            });

        } catch (error) {
            logger.error('Get asset error:', error.message);
            next(error);
        }
    }

    /**
     * Update asset
     */
    async updateAsset(req, res, next) {
        try {
            const asset = await Asset.findOne({
                _id: req.params.id,
                userId: req.user.userId,
            });

            if (!asset) {
                return res.status(404).json({
                    success: false,
                    message: 'Asset not found',
                });
            }

            // Update fields
            if (req.body.assetName) asset.assetName = req.body.assetName;
            if (req.body.assetType) asset.assetType = req.body.assetType;
            if (req.body.description !== undefined) asset.description = req.body.description;
            if (req.body.location !== undefined) asset.location = req.body.location;
            if (req.body.status) asset.status = req.body.status;
            if (req.body.criticality) asset.criticality = req.body.criticality;
            if (req.body.owner !== undefined) asset.owner = req.body.owner;
            
            asset.updatedAt = new Date();
            await asset.save();

            logger.info(`Asset updated: ${asset._id}`);

            res.json({
                success: true,
                message: 'Asset updated successfully',
                asset,
            });

        } catch (error) {
            logger.error('Update asset error:', error.message);
            next(error);
        }
    }

    /**
     * Delete asset
     */
    async deleteAsset(req, res, next) {
        try {
            const asset = await Asset.findOneAndDelete({
                _id: req.params.id,
                userId: req.user.userId,
            });

            if (!asset) {
                return res.status(404).json({
                    success: false,
                    message: 'Asset not found',
                });
            }

            logger.info(`Asset deleted: ${asset._id}`);

            res.json({
                success: true,
                message: 'Asset deleted successfully',
            });

        } catch (error) {
            logger.error('Delete asset error:', error.message);
            next(error);
        }
    }

    /**
     * Search assets
     */
    async searchAssets(req, res, next) {
        try {
            const query = req.query.query || '';

            const assets = await Asset.find({
                userId: req.user.userId,
                $or: [
                    { assetName: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } },
                    { location: { $regex: query, $options: 'i' } },
                ],
            });

            res.json({
                success: true,
                count: assets.length,
                assets,
            });

        } catch (error) {
            logger.error('Search assets error:', error.message);
            next(error);
        }
    }

    /**
     * Get asset types
     */
    async getAssetTypes(req, res, next) {
        try {
            res.json({
                success: true,
                assetTypes: ASSET_TYPES,
            });
        } catch (error) {
            logger.error('Get asset types error:', error.message);
            next(error);
        }
    }
}

module.exports = new AssetController();