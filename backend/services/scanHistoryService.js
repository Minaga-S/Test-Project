/**
 * Scan History Service
 */
// NOTE: Orchestrates Nmap, NIST CVE lookups, and persisted scan history.

const ScanHistory = require('../models/ScanHistory');
const assetSecurityContextService = require('./assetSecurityContextService');
const nmapScanService = require('./nmapScanService');
const nistCveService = require('./nistCveService');

function buildAssetSnapshot(asset) {
    return {
        assetName: asset?.assetName || '',
        assetType: asset?.assetType || '',
        location: asset?.location || '',
        criticality: asset?.criticality || '',
        owner: asset?.owner || '',
    };
}

function buildCveProfile(asset, scanResult) {
    const vulnerabilityProfile = asset?.vulnerabilityProfile || {};
    return {
        cpeUri: vulnerabilityProfile.cpeUri || '',
        vendor: vulnerabilityProfile.vendor || '',
        product: vulnerabilityProfile.product || '',
        productVersion: vulnerabilityProfile.productVersion || '',
        osName: vulnerabilityProfile.osName || '',
        serviceNames: Array.isArray(scanResult?.services)
            ? scanResult.services.map((service) => service.service)
            : [],
    };
}

class ScanHistoryService {
    async runAssetScan(asset, userId) {
        const target = String(asset?.liveScan?.target || '').trim();
        const requestedPorts = String(asset?.liveScan?.ports || '').trim();
        const startedAt = new Date();

        if (!target) {
            const securityContext = assetSecurityContextService.buildFallbackContext(asset, 'Scan target is not configured');
            const skippedHistory = await ScanHistory.create({
                assetId: asset._id,
                userId,
                assetSnapshot: buildAssetSnapshot(asset),
                status: 'Skipped',
                target: '',
                ports: requestedPorts,
                command: '',
                startedAt,
                completedAt: new Date(),
                scanDurationMs: 0,
                nmapResult: {},
                cveResult: {},
                securityContext,
                errorMessage: 'Scan target is not configured',
                initiatedBy: 'asset-scan',
            });

            return {
                scanHistory: skippedHistory,
                securityContext,
                skipped: true,
            };
        }

        try {
            const nmapResult = await nmapScanService.runScan({ target, ports: requestedPorts });
            const cveResult = await nistCveService.lookupCves(buildCveProfile(asset, nmapResult));
            const completedAt = new Date();
            const securityContext = assetSecurityContextService.buildFromScanResult(asset, nmapResult, cveResult);

            const scanHistory = await ScanHistory.create({
                assetId: asset._id,
                userId,
                assetSnapshot: buildAssetSnapshot(asset),
                status: 'Completed',
                target,
                ports: requestedPorts,
                command: `nmap ${nmapResult.args.join(' ')}`,
                startedAt,
                completedAt,
                scanDurationMs: completedAt.getTime() - startedAt.getTime(),
                nmapResult,
                cveResult,
                securityContext,
                errorMessage: '',
                initiatedBy: 'asset-scan',
            });

            return {
                scanHistory,
                securityContext,
                skipped: false,
            };
        } catch (error) {
            const completedAt = new Date();
            const securityContext = assetSecurityContextService.buildFallbackContext(asset, error.message);
            const failedHistory = await ScanHistory.create({
                assetId: asset._id,
                userId,
                assetSnapshot: buildAssetSnapshot(asset),
                status: 'Failed',
                target,
                ports: requestedPorts,
                command: '',
                startedAt,
                completedAt,
                scanDurationMs: completedAt.getTime() - startedAt.getTime(),
                nmapResult: {},
                cveResult: {},
                securityContext,
                errorMessage: error.message,
                initiatedBy: 'asset-scan',
            });

            return {
                scanHistory: failedHistory,
                securityContext,
                skipped: false,
                error,
            };
        }
    }

    async getLatestScanHistory(assetId, userId) {
        return ScanHistory.findOne({ assetId, userId }).sort({ createdAt: -1 });
    }

    async getAssetScanHistory(assetId, userId, limit = 10) {
        return ScanHistory.find({ assetId, userId }).sort({ createdAt: -1 }).limit(limit);
    }
}

module.exports = new ScanHistoryService();