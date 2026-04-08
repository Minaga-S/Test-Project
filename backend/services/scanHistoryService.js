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
        osName: isLikelyOperatingSystem(vulnerabilityProfile.osName) ? vulnerabilityProfile.osName : '',
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

function inferVendorFromServices(serviceNames = []) {
    const normalized = serviceNames.map((item) => String(item || '').toLowerCase());

    if (normalized.some((service) => service.includes('microsoft'))) {
        return 'Microsoft';
    }

    if (normalized.some((service) => service.includes('ssh'))) {
        return 'OpenSSH';
    }

    if (normalized.some((service) => service.includes('http'))) {
        return 'Web Service';
    }

    return '';
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

    const detectedServices = Array.isArray(scanResult?.services)
        ? scanResult.services
            .map((service) => String(service?.service || '').trim())
            .filter(Boolean)
        : [];
    const uniqueServices = [...new Set(detectedServices)];

    const nextProfile = {
        ...existingProfile,
        osName: currentOsName,
        vendor: currentVendor,
        product: currentProduct,
    };

    if (!nextProfile.product && uniqueServices.length > 0) {
        nextProfile.product = uniqueServices.slice(0, 3).join(', ');
    }

    if (!nextProfile.vendor) {
        nextProfile.vendor = inferVendorFromServices(uniqueServices);
    }

    const hasChanges = nextProfile.osName !== currentOsName
        || nextProfile.vendor !== currentVendor
        || nextProfile.product !== currentProduct;

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
    async runAssetScan(asset, userId, requestMeta = {}) {
        const target = String(asset?.liveScan?.target || '').trim();
        const requestedPortsText = String(asset?.liveScan?.ports || '').trim();
        const requesterIp = requestMeta.ipAddress || '';
        const startedAt = new Date();
        const canRunNmap = shouldRunNmap(asset, target);
        let scanResult = buildEmptyScanResult(asset, target);
        let scanError = null;

        if (canRunNmap) {
            try {
                scanResult = await nmapScanService.runScan({ target, ports: requestedPortsText, requestIp: requesterIp });
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
                ipAddress: requesterIp,
            }
        );

        const ranLiveScan = canRunNmap && !scanError;
        if (ranLiveScan) {
            await persistInferredProfile(asset, userId, scanResult);
        }

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
        const requesterIp = requestMeta.ipAddress || '';
        const canRunNmap = shouldRunNmap(asset, target);

        if (canRunNmap) {
            try {
                const scanResult = await nmapScanService.runScan({
                    target,
                    ports: asset?.liveScan?.ports || '',
                    requestIp: requesterIp,
                });
                const cveResult = await cveEnrichmentService.enrichForAsset(
                    buildCveProfile(asset, scanResult),
                    target,
                    {
                        userId,
                        assetId: String(asset?._id || ''),
                        ipAddress: requesterIp,
                    }
                );

                return assetSecurityContextService.buildFromScanResult(
                    asset,
                    scanResult,
                    cveResult,
                    {
                        _id: '',
                        status: 'Completed',
                        completedAt: new Date().toISOString(),
                    }
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
                        ipAddress: requesterIp,
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
                ipAddress: requesterIp,
            }
        );

        return assetSecurityContextService.buildFallbackContext(
            asset,
            buildScanStatusReason(asset, target),
            cveResult
        );
    }

    async runPreviewScan(assetDraft = {}, userId, requestMeta = {}) {
        const target = String(assetDraft?.liveScan?.target || '').trim();
        const requestedPortsText = String(assetDraft?.liveScan?.ports || '').trim();
        const requesterIp = requestMeta.ipAddress || '';

        if (!target) {
            throw new Error('Scan target is required for preview');
        }

        if (!nmapScanService.isAllowedScanTarget(target)) {
            throw new Error('Nmap scans are restricted to localhost and private-network targets');
        }

        nmapScanService.assertTargetWithinRequesterNetwork(target, requesterIp);

        const scanResult = await nmapScanService.runScan({
            target,
            ports: requestedPortsText,
            requestIp: requesterIp,
        });

        let cveResult;
        try {
            cveResult = await cveEnrichmentService.enrichForAsset(
                buildCveProfile(assetDraft, scanResult),
                target,
                {
                    userId,
                    assetId: String(assetDraft?._id || ''),
                    ipAddress: requesterIp,
                }
            );
        } catch (error) {
            cveResult = {
                source: 'NIST NVD API',
                query: {},
                matches: [],
                totalMatches: 0,
                retrievedAt: new Date().toISOString(),
                error: error.message,
            };
        }

        const inferred = inferProfileUpdates(assetDraft, scanResult);
        const enrichedAssetDraft = {
            ...assetDraft,
            vulnerabilityProfile: inferred.nextProfile,
        };

        if (assetDraft?._id) {
            await persistInferredProfile(assetDraft, userId, scanResult);
        }

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

        return {
            scanResult,
            cveResult,
            inferredProfile: inferred.nextProfile,
            securityContext,
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








