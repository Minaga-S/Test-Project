/**
 * Asset Controller
 */
// NOTE: Controller: handles incoming API requests, validates access, and returns responses.

const Asset = require('../models/Asset');
const { ASSET_TYPES } = require('../utils/constants');
const { validateAsset } = require('../utils/validators');
const logger = require('../utils/logger');
const auditLogService = require('../services/auditLogService');
const assetSecurityContextService = require('../services/assetSecurityContextService');
const scanHistoryService = require('../services/scanHistoryService');
const nmapScanService = require('../services/nmapScanService');

const DEFAULT_SCAN_FREQUENCY = 'OnDemand';

function sanitizeLiveScanInput(liveScanInput = {}) {
    return {
        enabled: liveScanInput.enabled === true || liveScanInput.enabled === 'true',
        target: typeof liveScanInput.target === 'string' ? liveScanInput.target.trim() : '',
        ports: typeof liveScanInput.ports === 'string' ? liveScanInput.ports.trim() : '',
        frequency: typeof liveScanInput.frequency === 'string' ? liveScanInput.frequency : DEFAULT_SCAN_FREQUENCY,
    };
}

function sanitizeVulnerabilityProfileInput(profileInput = {}) {
    return {
        osName: typeof profileInput.osName === 'string' ? profileInput.osName.trim() : '',
        vendor: typeof profileInput.vendor === 'string' ? profileInput.vendor.trim() : '',
        product: typeof profileInput.product === 'string' ? profileInput.product.trim() : '',
        productVersion: typeof profileInput.productVersion === 'string' ? profileInput.productVersion.trim() : '',
        cpeUri: typeof profileInput.cpeUri === 'string' ? profileInput.cpeUri.trim() : '',
    };
}

function getLiveScanScopeError(liveScanInput = {}, requestIp = '') {
    const liveScan = sanitizeLiveScanInput(liveScanInput);
    if (!liveScan.target) {
        return '';
    }

    if (!nmapScanService.isAllowedScanTarget(liveScan.target)) {
        return 'Live scan target must be localhost or a private-network address';
    }

    try {
        nmapScanService.assertTargetWithinRequesterNetwork(liveScan.target, requestIp);
        return '';
    } catch (error) {
        return error.message;
    }
}

class AssetController {
    async createAsset(req, res, next) {
        try {
            const validation = validateAsset(req.body);
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: validation.errors,
                });
            }

            const createScopeError = getLiveScanScopeError(req.body.liveScan, req.ip);
            if (createScopeError) {
                return res.status(400).json({
                    success: false,
                    message: createScopeError,
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
                liveScan: sanitizeLiveScanInput(req.body.liveScan),
                vulnerabilityProfile: sanitizeVulnerabilityProfileInput(req.body.vulnerabilityProfile),
                userId: req.user.userId,
            });

            await asset.save();

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'ASSET_CREATE',
                entityType: 'Asset',
                entityId: String(asset._id),
                after: { assetName: asset.assetName, assetType: asset.assetType, criticality: asset.criticality },
                ipAddress: req.ip || '',
            });

            logger.info(`Asset created: ${asset._id} by user ${req.user.userId}`);

            res.status(201).json({
                success: true,
                message: 'Asset created successfully',
                asset,
            });
        } catch (error) {
            logger.error(`Create asset error: ${error.message}`);
            next(error);
        }
    }

    async getAssets(req, res, next) {
        try {
            const assets = await Asset.find({ userId: req.user.userId }).sort({ createdAt: -1 });

            res.json({
                success: true,
                count: assets.length,
                assets,
            });
        } catch (error) {
            logger.error(`Get assets error: ${error.message}`);
            next(error);
        }
    }

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
            logger.error(`Get asset error: ${error.message}`);
            next(error);
        }
    }

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

            const validation = validateAsset({
                assetName: req.body.assetName || asset.assetName,
                assetType: req.body.assetType || asset.assetType,
                criticality: req.body.criticality || asset.criticality,
                liveScan: req.body.liveScan !== undefined ? req.body.liveScan : asset.liveScan,
            });
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: validation.errors,
                });
            }

            const updateScopeError = getLiveScanScopeError(req.body.liveScan !== undefined ? req.body.liveScan : asset.liveScan, req.ip);
            if (updateScopeError) {
                return res.status(400).json({
                    success: false,
                    message: updateScopeError,
                });
            }

            const before = {
                assetName: asset.assetName,
                assetType: asset.assetType,
                status: asset.status,
                criticality: asset.criticality,
            };

            if (req.body.assetName) asset.assetName = req.body.assetName;
            if (req.body.assetType) asset.assetType = req.body.assetType;
            if (req.body.description !== undefined) asset.description = req.body.description;
            if (req.body.location !== undefined) asset.location = req.body.location;
            if (req.body.status) asset.status = req.body.status;
            if (req.body.criticality) asset.criticality = req.body.criticality;
            if (req.body.owner !== undefined) asset.owner = req.body.owner;
            if (req.body.liveScan !== undefined) asset.liveScan = sanitizeLiveScanInput(req.body.liveScan);
            if (req.body.vulnerabilityProfile !== undefined) {
                asset.vulnerabilityProfile = sanitizeVulnerabilityProfileInput(req.body.vulnerabilityProfile);
            }

            asset.updatedAt = new Date();
            await asset.save();

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'ASSET_UPDATE',
                entityType: 'Asset',
                entityId: String(asset._id),
                before,
                after: {
                    assetName: asset.assetName,
                    assetType: asset.assetType,
                    status: asset.status,
                    criticality: asset.criticality,
                },
                ipAddress: req.ip || '',
            });

            logger.info(`Asset updated: ${asset._id}`);

            res.json({
                success: true,
                message: 'Asset updated successfully',
                asset,
            });
        } catch (error) {
            logger.error(`Update asset error: ${error.message}`);
            next(error);
        }
    }

    async deleteAsset(req, res, next) {
        try {
            const asset = await Asset.findOneAndUpdate(
                {
                    _id: req.params.id,
                    userId: req.user.userId,
                },
                {
                    isDeleted: true,
                    deletedAt: new Date(),
                    updatedAt: new Date(),
                },
                { new: true }
            );

            if (!asset) {
                return res.status(404).json({
                    success: false,
                    message: 'Asset not found',
                });
            }

            await auditLogService.record({
                actorUserId: req.user.userId,
                action: 'ASSET_DELETE',
                entityType: 'Asset',
                entityId: String(asset._id),
                before: { assetName: asset.assetName, assetType: asset.assetType },
                ipAddress: req.ip || '',
            });

            logger.info(`Asset soft-deleted: ${asset._id}`);

            res.json({
                success: true,
                message: 'Asset deleted successfully',
            });
        } catch (error) {
            logger.error(`Delete asset error: ${error.message}`);
            next(error);
        }
    }

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
            logger.error(`Search assets error: ${error.message}`);
            next(error);
        }
    }

    async getAssetTypes(req, res, next) {
        try {
            res.json({
                success: true,
                assetTypes: ASSET_TYPES,
            });
        } catch (error) {
            logger.error(`Get asset types error: ${error.message}`);
            next(error);
        }
    }

    async getAssetSecurityContext(req, res, next) {
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

            const securityContextScopeError = getLiveScanScopeError(asset.liveScan, req.ip);
            if (securityContextScopeError) {
                return res.status(400).json({
                    success: false,
                    message: securityContextScopeError,
                });
            }
            const latestScanHistory = await scanHistoryService.getLatestScanHistory(asset._id, req.user.userId);
            const securityContext = latestScanHistory
                ? assetSecurityContextService.buildForAsset(asset, latestScanHistory)
                : await scanHistoryService.buildOnDemandSecurityContext(asset, req.user.userId, { ipAddress: req.ip || '' });
            res.json({
                success: true,
                securityContext,
                latestScanHistory,
            });
        } catch (error) {
            logger.error(`Get asset security context error: ${error.message}`);
            next(error);
        }
    }

    async getAssetScanHistory(req, res, next) {
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

            const scanHistory = await scanHistoryService.getAssetScanHistory(asset._id, req.user.userId);
            res.json({
                success: true,
                count: scanHistory.length,
                scanHistory,
            });
        } catch (error) {
            logger.error(`Get asset scan history error: ${error.message}`);
            next(error);
        }
    }

    async scanAssetPreview(req, res, next) {
        try {
            const liveScan = sanitizeLiveScanInput(req.body.liveScan);
            const vulnerabilityProfile = sanitizeVulnerabilityProfileInput(req.body.vulnerabilityProfile);

            const scopeError = getLiveScanScopeError(liveScan, req.ip);
            if (scopeError) {
                return res.status(400).json({
                    success: false,
                    message: scopeError,
                });
            }

            const assetDraft = {
                _id: '',
                assetName: req.body.assetName || 'Asset Draft',
                assetType: req.body.assetType || 'Other',
                liveScan: {
                    enabled: true,
                    target: liveScan.target,
                    ports: liveScan.ports,
                    frequency: liveScan.frequency || DEFAULT_SCAN_FREQUENCY,
                },
                vulnerabilityProfile,
            };

            const preview = await scanHistoryService.runPreviewScan(assetDraft, req.user.userId, {
                ipAddress: req.ip || '',
            });

            return res.json({
                success: true,
                message: 'Live scan preview completed',
                preview,
            });
        } catch (error) {
            logger.error(`Scan preview error: ${error.message}`);
            return next(error);
        }
    }
    async scanAssets(req, res, next) {
        try {
            const assetIds = Array.isArray(req.body.assetIds) ? req.body.assetIds : [];
            if (assetIds.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'assetIds is required and must be a non-empty array',
                });
            }

            const assets = await Asset.find({
                _id: { $in: assetIds },
                userId: req.user.userId,
            });

            if (assets.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No assets found for the provided ids',
                });
            }

            const scans = [];
            for (const asset of assets) {
                const scanScopeError = getLiveScanScopeError(asset.liveScan, req.ip);
                if (scanScopeError) {
                    return res.status(400).json({
                        success: false,
                        message: scanScopeError,
                    });
                }

                const scanResult = await scanHistoryService.runAssetScan(asset, req.user.userId, { ipAddress: req.ip || '' });
                scans.push({
                    assetId: String(asset._id),
                    assetName: asset.assetName,
                    status: scanResult.scanHistory.status,
                    scanHistoryId: String(scanResult.scanHistory._id),
                    securityContext: scanResult.securityContext,
                });
            }

            const scannedCount = scans.filter((scan) => scan.status === 'Completed').length;
            res.json({
                success: true,
                scannedCount,
                scans,
            });
        } catch (error) {
            logger.error(`Scan assets error: ${error.message}`);
            next(error);
        }
    }
}

module.exports = new AssetController();