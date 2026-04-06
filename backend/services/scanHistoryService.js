/**
 * Scan History Service
 */
// NOTE: Orchestrates simulated live-scan context and real NIST CVE enrichment for Phase 1.

const ScanHistory = require('../models/ScanHistory');
const assetSecurityContextService = require('./assetSecurityContextService');
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

function normalizePorts(portsInput) {
    const raw = String(portsInput || '').trim();
    if (!raw) {
        return [];
    }

    return raw
        .split(',')
        .map((port) => Number(port.trim()))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
}

function mapPortToService(port) {
    const serviceMap = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
    };

    return serviceMap[port] || 'unknown';
}

function buildSimulatedScanResult(asset) {
    const requestedPorts = normalizePorts(asset?.liveScan?.ports);
    const openPorts = requestedPorts.length > 0 ? requestedPorts : [443];

    return {
        command: 'simulated-scan',
        args: ['phase-1-simulated'],
        target: String(asset?.liveScan?.target || '').trim(),
        requestedPorts,
        openPorts,
        services: openPorts.map((port) => ({
            port,
            protocol: 'tcp',
            service: mapPortToService(port),
            state: 'open',
        })),
        hostState: {
            hostAddress: String(asset?.liveScan?.target || '').trim(),
            hostName: String(asset?.assetName || '').trim(),
            state: 'up',
        },
        rawOutput: 'Simulated scan output (Phase 1: active scanning disabled)',
    };
}

function buildCveProfile(asset, scanResult = {}) {
    const vulnerabilityProfile = asset?.vulnerabilityProfile || {};
    return {
        cpeUri: vulnerabilityProfile.cpeUri || '',
        vendor: vulnerabilityProfile.vendor || '',
        product: vulnerabilityProfile.product || '',
        productVersion: vulnerabilityProfile.productVersion || '',
        osName: vulnerabilityProfile.osName || '',
        serviceNames: Array.isArray(scanResult.services)
            ? scanResult.services.map((service) => service.service)
            : [],
    };
}

class ScanHistoryService {
    async runAssetScan(asset, userId, requestMeta = {}) {
        const target = String(asset?.liveScan?.target || '').trim();
        const requestedPortsText = String(asset?.liveScan?.ports || '').trim();
        const startedAt = new Date();
        const simulatedScanResult = buildSimulatedScanResult(asset);

        const cveResult = await nistCveService.lookupCves(
            buildCveProfile(asset, simulatedScanResult),
            {
                userId,
                assetId: String(asset?._id || ''),
                ipAddress: requestMeta.ipAddress || '',
            }
        );

        if (!asset?.liveScan?.enabled || !target) {
            const reason = !asset?.liveScan?.enabled
                ? 'Live scan disabled. Simulated context with NIST enrichment only.'
                : 'Scan target is not configured. Simulated context with NIST enrichment only.';

            const securityContext = assetSecurityContextService.buildFallbackContext(asset, reason, cveResult);
            const skippedHistory = await ScanHistory.create({
                assetId: asset._id,
                userId,
                assetSnapshot: buildAssetSnapshot(asset),
                status: 'Skipped',
                target,
                ports: requestedPortsText,
                command: 'simulated-scan phase-1-simulated',
                startedAt,
                completedAt: new Date(),
                scanDurationMs: 0,
                nmapResult: simulatedScanResult,
                cveResult,
                securityContext,
                errorMessage: '',
                initiatedBy: 'asset-scan',
            });

            return {
                scanHistory: skippedHistory,
                securityContext,
                skipped: true,
            };
        }

        const completedAt = new Date();
        const securityContext = assetSecurityContextService.buildFromScanResult(asset, simulatedScanResult, cveResult);

        const scanHistory = await ScanHistory.create({
            assetId: asset._id,
            userId,
            assetSnapshot: buildAssetSnapshot(asset),
            status: 'Completed',
            target,
            ports: requestedPortsText,
            command: 'simulated-scan phase-1-simulated',
            startedAt,
            completedAt,
            scanDurationMs: completedAt.getTime() - startedAt.getTime(),
            nmapResult: simulatedScanResult,
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
    }

    async buildOnDemandSecurityContext(asset, userId, requestMeta = {}) {
        const simulatedScanResult = buildSimulatedScanResult(asset);
        const cveResult = await nistCveService.lookupCves(
            buildCveProfile(asset, simulatedScanResult),
            {
                userId,
                assetId: String(asset?._id || ''),
                ipAddress: requestMeta.ipAddress || '',
            }
        );

        return assetSecurityContextService.buildFallbackContext(
            asset,
            'No completed scan history yet (Phase 1 simulated scan).',
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