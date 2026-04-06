/**
 * Scan History Service
 */
// NOTE: Orchestrates real scan execution and provider-based CVE enrichment.

const ScanHistory = require('../models/ScanHistory');
const assetSecurityContextService = require('./assetSecurityContextService');
const cveEnrichmentService = require('./cveEnrichmentService');
const nmapScanService = require('./nmapScanService');

function buildAssetSnapshot(asset) {
    return {
        assetName: asset?.assetName || '',
        assetType: asset?.assetType || '',
        location: asset?.location || '',
        criticality: asset?.criticality || '',
        owner: asset?.owner || '',
    };
}

function buildCveProfile(asset, scanResult = {}) {
    const vulnerabilityProfile = asset?.vulnerabilityProfile || {};
    const serviceNames = Array.isArray(scanResult.services)
        ? scanResult.services
            .map((service) => service.service)
            .filter((serviceName) => Boolean(serviceName))
        : [];

    return {
        assetName: asset?.assetName || '',
        assetType: asset?.assetType || '',
        cpeUri: vulnerabilityProfile.cpeUri || '',
        vendor: vulnerabilityProfile.vendor || '',
        product: vulnerabilityProfile.product || '',
        productVersion: vulnerabilityProfile.productVersion || '',
        osName: vulnerabilityProfile.osName || '',
        serviceNames: serviceNames.length > 0 ? serviceNames : vulnerabilityProfile.serviceNames || [],
    };
}

function buildEmptyScanResult(asset, target = '') {
    return {
        command: 'nmap',
        args: [],
        target,
        requestedPorts: [],
        openPorts: [],
        services: [],
        hostState: {
            hostAddress: target,
            hostName: String(asset?.assetName || ''),
            state: 'unknown',
        },
        rawOutput: '',
    };
}

function shouldRunNmap(asset, target) {
    return Boolean(asset?.liveScan?.enabled && target && nmapScanService.isAllowedScanTarget(target));
}

function buildScanStatusReason(asset, target, scanError = null) {
    if (!asset?.liveScan?.enabled) {
        return 'Live scan disabled.';
    }

    if (!target) {
        return 'Scan target is not configured.';
    }

    if (!nmapScanService.isAllowedScanTarget(target)) {
        return 'Scan target is outside the allowed private-network scope.';
    }

    if (scanError) {
        return `Live scan unavailable; enrichment only (${scanError.message}).`;
    }

    return 'On-demand CVE enrichment.';
}

function shouldFallbackToEnrichment(error) {
    const message = String(error?.message || '').toLowerCase();
    return message.includes('nmap is not installed') || message.includes('nmap scan failed');
}

class ScanHistoryService {
    async runAssetScan(asset, userId, requestMeta = {}) {
        const target = String(asset?.liveScan?.target || '').trim();
        const requestedPortsText = String(asset?.liveScan?.ports || '').trim();
        const startedAt = new Date();
        const canRunNmap = shouldRunNmap(asset, target);
        let scanResult = buildEmptyScanResult(asset, target);
        let scanError = null;

        if (canRunNmap) {
            try {
                scanResult = await nmapScanService.runScan({ target, ports: requestedPortsText });
            } catch (error) {
                if (!shouldFallbackToEnrichment(error)) {
                    throw error;
                }

                scanError = error;
            }
        }

        const cveResult = await cveEnrichmentService.enrichForAsset(
            buildCveProfile(asset, scanResult),
            target,
            {
                userId,
                assetId: String(asset?._id || ''),
                ipAddress: requestMeta.ipAddress || '',
            }
        );

        const ranLiveScan = canRunNmap && !scanError;
        const securityContext = ranLiveScan
            ? assetSecurityContextService.buildFromScanResult(asset, scanResult, cveResult)
            : assetSecurityContextService.buildFallbackContext(asset, buildScanStatusReason(asset, target, scanError), cveResult);

        const scanHistory = await ScanHistory.create({
            assetId: asset._id,
            userId,
            assetSnapshot: buildAssetSnapshot(asset),
            status: ranLiveScan ? 'Completed' : 'Skipped',
            target,
            ports: requestedPortsText,
            command: ranLiveScan ? 'nmap' : 'cve-enrichment',
            startedAt,
            completedAt: new Date(),
            scanDurationMs: ranLiveScan ? Date.now() - startedAt.getTime() : 0,
            nmapResult: scanResult,
            cveResult,
            securityContext,
            errorMessage: '',
            initiatedBy: 'asset-scan',
        });

        return {
            scanHistory,
            securityContext,
            skipped: !ranLiveScan,
        };
    }

    async buildOnDemandSecurityContext(asset, userId, requestMeta = {}) {
        const target = String(asset?.liveScan?.target || '').trim();
        const canRunNmap = shouldRunNmap(asset, target);

        if (canRunNmap) {
            try {
                const scanResult = await nmapScanService.runScan({ target, ports: asset?.liveScan?.ports || '' });
                const cveResult = await cveEnrichmentService.enrichForAsset(
                    buildCveProfile(asset, scanResult),
                    target,
                    {
                        userId,
                        assetId: String(asset?._id || ''),
                        ipAddress: requestMeta.ipAddress || '',
                    }
                );

                return assetSecurityContextService.buildFallbackContext(
                    asset,
                    'On-demand live scan completed.',
                    cveResult
                );
            } catch (error) {
                if (!shouldFallbackToEnrichment(error)) {
                    throw error;
                }

                const cveResult = await cveEnrichmentService.enrichForAsset(
                    buildCveProfile(asset),
                    target,
                    {
                        userId,
                        assetId: String(asset?._id || ''),
                        ipAddress: requestMeta.ipAddress || '',
                    }
                );

                return assetSecurityContextService.buildFallbackContext(
                    asset,
                    buildScanStatusReason(asset, target, error),
                    cveResult
                );
            }
        }

        const cveResult = await cveEnrichmentService.enrichForAsset(
            buildCveProfile(asset),
            target,
            {
                userId,
                assetId: String(asset?._id || ''),
                ipAddress: requestMeta.ipAddress || '',
            }
        );

        return assetSecurityContextService.buildFallbackContext(
            asset,
            buildScanStatusReason(asset, target),
            cveResult
        );
    }

    async getLatestScanHistory(assetId, userId) {
        return ScanHistory.findOne({ assetId, userId }).sort({ createdAt: -1 });
    }

    async getAssetScanHistory(assetId, userId, limit = 10) {
        return ScanHistory.find({ assetId, userId }).sort({ createdAt: -1 }).limit(limit);
    }
}

module.exports = new ScanHistoryService();
