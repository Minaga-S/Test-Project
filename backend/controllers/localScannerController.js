/**
 * Local Scanner Controller
 */
// NOTE: Handles secure handshake and ingestion for scans executed by the local scanner app.

const logger = require('../utils/logger');
const localScannerBridgeService = require('../services/localScannerBridgeService');
const scanHistoryService = require('../services/scanHistoryService');

function getBaseUrl(req) {
    return `${req.protocol}://${req.get('host')}`;
}

function mapBridgeError(error) {
    if (error instanceof localScannerBridgeService.LocalScannerBridgeError) {
        return {
            statusCode: error.statusCode || 400,
            message: error.message,
            code: error.code || 'LOCAL_SCANNER_ERROR',
        };
    }

    return {
        statusCode: 500,
        message: 'Local scanner request failed',
        code: 'LOCAL_SCANNER_ERROR',
    };
}

class LocalScannerController {
    async createScanRequest(req, res, next) {
        try {
            const issued = localScannerBridgeService.issueScanToken(req.body || {}, {
                userId: req.user?.userId,
                ipAddress: req.ip || '',
            });

            res.json({
                success: true,
                scanRequest: {
                    bridgeToken: issued.bridgeToken,
                    expiresAt: issued.expiresAt,
                    target: issued.scanRequest.liveScan.target,
                    ports: issued.scanRequest.liveScan.ports,
                    uploadUrl: `${getBaseUrl(req)}/api/local-scanner/results`,
                },
            });
        } catch (error) {
            const mapped = mapBridgeError(error);
            if (mapped.statusCode >= 500) {
                logger.error(`Create local scan request error: ${error.message}`);
                return next(error);
            }

            return res.status(mapped.statusCode).json({
                success: false,
                message: mapped.message,
                code: mapped.code,
            });
        }
    }

    async submitScanResult(req, res, next) {
        try {
            const { bridgeToken, scanResult } = req.body || {};
            const consumed = localScannerBridgeService.consumeScanToken(bridgeToken);

            const result = await scanHistoryService.ingestLocalScanResult(
                consumed.asset,
                consumed.userId,
                scanResult,
                {
                    ipAddress: req.ip || '',
                    initiatedBy: 'local-scanner',
                }
            );

            res.status(201).json({
                success: true,
                message: 'Local scan result ingested',
                preview: {
                    scanResult: result.scanResult,
                    cveResult: result.cveResult,
                    inferredProfile: result.inferredProfile,
                    securityContext: result.securityContext,
                },
                persisted: result.persisted,
                scanHistoryId: result.scanHistory?._id ? String(result.scanHistory._id) : '',
            });
        } catch (error) {
            const mapped = mapBridgeError(error);
            if (mapped.statusCode >= 500 || !(error instanceof localScannerBridgeService.LocalScannerBridgeError)) {
                logger.error(`Submit local scan result error: ${error.message}`);
                return next(error);
            }

            return res.status(mapped.statusCode).json({
                success: false,
                message: mapped.message,
                code: mapped.code,
            });
        }
    }
}

module.exports = new LocalScannerController();
