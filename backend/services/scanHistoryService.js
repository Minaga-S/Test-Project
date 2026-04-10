/**
 * Scan History Service
 */
// NOTE: Orchestrates real scan execution and provider-based CVE enrichment.

const ScanHistory = require('../models/ScanHistory');
const Asset = require('../models/Asset');
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
            .map((service) => {
                const name = String(service?.service || '').trim();
                const version = String(service?.version || '').trim();
                return version ? `${name} ${version}` : name;
            })
            .filter((serviceName) => Boolean(serviceName))
        : [];

    return {
        assetName: asset?.assetName || '',
        assetType: asset?.assetType || '',
        cpeUri: String(scanResult.osCpe || '').trim() || String(vulnerabilityProfile.cpeUri || '').trim(),
        vendor: vulnerabilityProfile.vendor || '',
        product: vulnerabilityProfile.product || '',
        productVersion: vulnerabilityProfile.productVersion || '',
        osName: String(scanResult.osInfo || '').trim() || (isLikelyOperatingSystem(vulnerabilityProfile.osName) ? vulnerabilityProfile.osName : ''),
        serviceNames: serviceNames.length > 0 ? serviceNames : vulnerabilityProfile.serviceNames || [],
    };
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

function sanitizeOpenPorts(openPortsInput = []) {
    if (!Array.isArray(openPortsInput)) {
        return [];
    }

    return openPortsInput
        .map((port) => Number(port))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
}

function sanitizeServiceList(servicesInput = []) {
    if (!Array.isArray(servicesInput)) {
        return [];
    }

    return servicesInput
        .map((service) => {
            const port = Number(service?.port);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                return null;
            }

            return {
                port,
                state: 'open',
                protocol: String(service?.protocol || 'tcp').trim() || 'tcp',
                service: String(service?.service || 'unknown').trim() || 'unknown',
                version: String(service?.version || '').trim(),
            };
        })
        .filter((service) => Boolean(service));
}

function sanitizeLocalScanResult(asset, scanResultInput = {}) {
    const target = String(scanResultInput?.target || asset?.liveScan?.target || '').trim();
    const requestedPortsText = String(scanResultInput?.requestedPorts || asset?.liveScan?.ports || '').trim();
    const services = sanitizeServiceList(scanResultInput?.services || []);
    const openPorts = sanitizeOpenPorts(scanResultInput?.openPorts || services.map((service) => service.port));

    return {
        command: 'nmap',
        args: [],
        target,
        requestedPorts: requestedPortsText,
        openPorts,
        services,
        hostState: {
            hostAddress: target,
            hostName: String(scanResultInput?.hostState?.hostName || asset?.assetName || '').trim(),
            state: String(scanResultInput?.hostState?.state || 'up').trim() || 'up',
        },
        osInfo: String(scanResultInput?.osInfo || '').trim(),
        osCpe: String(scanResultInput?.osCpe || '').trim(),
        rawOutput: String(scanResultInput?.rawOutput || '').trim(),
    };
}

function isLikelyOperatingSystem(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized) {
        return false;
    }

    return [
        'windows',
        'linux',
        'ubuntu',
        'debian',
        'kali',
        'mac os',
        'macos',
        'android',
        'ios',
        'freebsd',
        'openbsd',
        'netbsd',
        'solaris',
        'aix',
        'hp-ux',
        'unix',
        'red hat',
        'centos',
        'fedora',
        'arch',
        'opensuse',
        'suse',
        'openwrt'
    ].some((keyword) => normalized.includes(keyword));
}

function inferProfileUpdates(asset, scanResult) {
    const existingProfile = asset?.vulnerabilityProfile || {};
    const currentOsName = String(existingProfile.osName || '').trim();
    const currentVendor = String(existingProfile.vendor || '').trim();
    const currentProduct = String(existingProfile.product || '').trim();
    const currentCpeUri = String(existingProfile.cpeUri || '').trim();
    const detectedOsName = String(scanResult?.osInfo || '').trim();
    const detectedCpeUri = String(scanResult?.osCpe || '').trim();

    const nextProfile = {
        ...existingProfile,
        osName: currentOsName || detectedOsName,
        vendor: currentVendor,
        product: currentProduct,
        cpeUri: currentCpeUri || detectedCpeUri,
    };

    const hasChanges = nextProfile.osName !== currentOsName
        || nextProfile.vendor !== currentVendor
        || nextProfile.product !== currentProduct
        || nextProfile.cpeUri !== currentCpeUri;

    return {
        hasChanges,
        nextProfile,
    };
}

async function persistInferredProfile(asset, userId, scanResult) {
    const inferred = inferProfileUpdates(asset, scanResult);
    if (!inferred.hasChanges || !asset?._id) {
        return;
    }

    await Asset.updateOne(
        { _id: asset._id, userId },
        {
            $set: {
                vulnerabilityProfile: inferred.nextProfile,
                updatedAt: new Date(),
            },
        }
    );

    asset.vulnerabilityProfile = inferred.nextProfile;
}

class ScanHistoryService {
    async buildOnDemandSecurityContext(asset, userId, requestMeta = {}) {
        const target = String(asset?.liveScan?.target || '').trim();
        const requesterIp = requestMeta.ipAddress || '';

        const cveResult = await cveEnrichmentService.enrichForAsset(
            buildCveProfile(asset),
            target,
            {
                userId,
                assetId: String(asset?._id || ''),
                ipAddress: requesterIp,
            }
        );

        return assetSecurityContextService.buildFallbackContext(
            asset,
            buildScanStatusReason(asset, target),
            cveResult
        );
    }

    async ingestLocalScanResult(assetDraft = {}, userId, scanResultInput = {}, requestMeta = {}) {
        const target = String(assetDraft?.liveScan?.target || '').trim();
        const requesterIp = requestMeta.ipAddress || '';

        if (!target) {
            throw new Error('Scan target is required for local scanner ingestion');
        }

        if (!nmapScanService.isAllowedScanTarget(target)) {
            throw new Error('Nmap scans are restricted to localhost and private-network targets');
        }

        const scanResult = sanitizeLocalScanResult(assetDraft, scanResultInput);
        const cveResult = await cveEnrichmentService.enrichForAsset(
            buildCveProfile(assetDraft, scanResult),
            target,
            {
                userId,
                assetId: String(assetDraft?._id || assetDraft?.assetId || ''),
                ipAddress: requesterIp,
            }
        );

        const inferred = inferProfileUpdates(assetDraft, scanResult);
        const enrichedAssetDraft = {
            ...assetDraft,
            vulnerabilityProfile: inferred.nextProfile,
        };

        const securityContext = assetSecurityContextService.buildFromScanResult(
            enrichedAssetDraft,
            scanResult,
            cveResult,
            {
                _id: '',
                status: 'Completed',
                completedAt: new Date().toISOString(),
            }
        );

        const assetId = String(assetDraft?._id || assetDraft?.assetId || '').trim();
        if (!assetId) {
            return {
                scanResult,
                cveResult,
                inferredProfile: inferred.nextProfile,
                securityContext,
                scanHistory: null,
                persisted: false,
            };
        }

        await persistInferredProfile({ ...assetDraft, _id: assetId }, userId, scanResult);

        const startedAt = new Date();
        const scanHistory = await ScanHistory.create({
            assetId,
            userId,
            assetSnapshot: buildAssetSnapshot(assetDraft),
            status: 'Completed',
            target,
            ports: String(assetDraft?.liveScan?.ports || '').trim(),
            command: 'nmap',
            startedAt,
            completedAt: new Date(),
            scanDurationMs: Number(scanResultInput?.scanDurationMs) || 0,
            nmapResult: scanResult,
            cveResult,
            securityContext,
            errorMessage: '',
            initiatedBy: requestMeta.initiatedBy || 'local-scanner',
        });

        return {
            scanResult,
            cveResult,
            inferredProfile: inferred.nextProfile,
            securityContext,
            scanHistory,
            persisted: true,
        };
    }

    async getLatestScanHistory(assetId, userId) {
        return ScanHistory.findOne({ assetId, userId }).sort({ createdAt: -1 });
    }

    async getAssetScanHistory(assetId, userId, limit = 10) {
        return ScanHistory.find({ assetId, userId }).sort({ createdAt: -1 }).limit(limit);
    }
}

module.exports = new ScanHistoryService();








