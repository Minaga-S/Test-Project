/**
 * Asset Security Context Service
 */
// NOTE: Formats persisted scan history into the structure used by incident analysis.

const ENRICHMENT_STALE_HOURS = Number(process.env.CVE_ENRICHMENT_STALE_HOURS || 72);

function normalize(value) {
    return String(value || '').trim();
}

function normalizePorts(portsInput) {
    const raw = normalize(portsInput);
    if (!raw) {
        return [];
    }

    return raw
        .split(',')
        .map((port) => Number(port.trim()))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
}

function buildCveQuery(profile = {}) {
    return {
        cpeUri: normalize(profile.cpeUri),
        vendor: normalize(profile.vendor),
        product: normalize(profile.product),
        productVersion: normalize(profile.productVersion),
        osName: normalize(profile.osName),
    };
}

function buildDataSources(cveResult = null) {
    const source = normalize(cveResult?.source);
    const scanSource = normalize(cveResult?.scanSource) || (source ? 'Live Nmap Scan' : 'Live scan pending');

    return {
        scan: scanSource,
        cve: source ? `${source} Enriched` : 'Enrichment Pending',
    };
}

function buildEnrichmentMetadata(cveResult = null) {
    const retrievedAt = normalize(cveResult?.retrievedAt);
    if (!retrievedAt) {
        return {
            source: normalize(cveResult?.source) || 'Unknown',
            lastEnrichedAt: '',
            confidence: normalize(cveResult?.confidence) || 'Low',
            cacheHit: Boolean(cveResult?.cacheHit),
            ageHours: null,
            isStale: true,
        };
    }

    const parsed = new Date(retrievedAt);
    const ageHours = Number.isNaN(parsed.getTime())
        ? null
        : Number(((Date.now() - parsed.getTime()) / (1000 * 60 * 60)).toFixed(2));

    return {
        source: normalize(cveResult?.source) || 'Unknown',
        lastEnrichedAt: retrievedAt,
        confidence: normalize(cveResult?.confidence) || 'Low',
        cacheHit: Boolean(cveResult?.cacheHit),
        ageHours,
        isStale: ageHours === null ? true : ageHours > ENRICHMENT_STALE_HOURS,
    };
}

function buildFallbackContext(asset, reason = 'No completed scan history yet', cveResult = null) {
    const liveScan = asset?.liveScan || {};
    const vulnerabilityProfile = asset?.vulnerabilityProfile || {};
    const requestedPorts = normalizePorts(liveScan.ports);
    const cveMatches = Array.isArray(cveResult?.matches) ? cveResult.matches : [];

    return {
        generatedAt: new Date().toISOString(),
        source: 'asset-profile',
        dataSources: buildDataSources({ ...cveResult, scanSource: liveScan.enabled ? 'Live scan pending' : 'Live scan disabled' }),
        enrichment: buildEnrichmentMetadata(cveResult),
        asset: {
            assetId: asset?._id ? String(asset._id) : '',
            assetName: normalize(asset?.assetName),
            assetType: normalize(asset?.assetType),
        },
        liveScan: {
            enabled: Boolean(liveScan.enabled),
            target: normalize(liveScan.target),
            frequency: normalize(liveScan.frequency) || 'OnDemand',
            requestedPorts,
            observedOpenPorts: [],
            services: [],
            status: reason,
        },
        cve: {
            source: cveResult?.source || 'Unknown',
            query: cveResult?.query || buildCveQuery(vulnerabilityProfile),
            matches: cveMatches,
            totalMatches: cveMatches.length,
            retrievedAt: cveResult?.retrievedAt || '',
            confidence: cveResult?.confidence || 'Low',
        },
    };
}

function buildFromScanResult(asset, scanResult = {}, cveResult = {}, scanHistory = null) {
    const liveScan = asset?.liveScan || {};
    const vulnerabilityProfile = asset?.vulnerabilityProfile || {};
    const requestedPorts = Array.isArray(scanResult.requestedPorts)
        ? scanResult.requestedPorts
        : normalizePorts(liveScan.ports);
    const observedOpenPorts = Array.isArray(scanResult.openPorts)
        ? scanResult.openPorts
        : [];
    const services = Array.isArray(scanResult.services)
        ? scanResult.services
        : [];
    const cveMatches = Array.isArray(cveResult.matches)
        ? cveResult.matches
        : [];

    return {
        generatedAt: scanHistory?.completedAt || new Date().toISOString(),
        source: 'persisted-scan-history',
        dataSources: buildDataSources({ ...cveResult, scanSource: liveScan.enabled ? 'Live scan pending' : 'Live scan disabled' }),
        enrichment: buildEnrichmentMetadata(cveResult),
        scanHistoryId: scanHistory?._id ? String(scanHistory._id) : '',
        asset: {
            assetId: asset?._id ? String(asset._id) : '',
            assetName: normalize(asset?.assetName),
            assetType: normalize(asset?.assetType),
        },
        liveScan: {
            enabled: true,
            target: normalize(scanResult.target || liveScan.target),
            frequency: normalize(liveScan.frequency) || 'OnDemand',
            requestedPorts,
            observedOpenPorts,
            services,
            status: scanHistory?.status || 'Completed',
        },
        cve: {
            source: cveResult.source || 'Unknown',
            query: cveResult.query || buildCveQuery(vulnerabilityProfile),
            matches: cveMatches,
            totalMatches: cveMatches.length,
            retrievedAt: cveResult.retrievedAt || '',
            confidence: cveResult.confidence || 'Low',
        },
    };
}

function buildFromScanHistory(asset, scanHistory) {
    if (!scanHistory) {
        return buildFallbackContext(asset);
    }

    if (scanHistory.securityContext && Object.keys(scanHistory.securityContext).length > 0) {
        return scanHistory.securityContext;
    }

    return buildFromScanResult(asset, scanHistory.nmapResult || {}, scanHistory.cveResult || {}, scanHistory);
}

function buildForAsset(asset, scanHistory = null) {
    return buildFromScanHistory(asset, scanHistory);
}

function buildForAssets(assets) {
    return (assets || []).map((asset) => ({
        assetId: String(asset._id),
        assetName: asset.assetName,
        securityContext: buildForAsset(asset, asset.latestScanHistory || null),
    }));
}

module.exports = {
    buildForAsset,
    buildForAssets,
    buildFallbackContext,
    buildFromScanResult,
    buildFromScanHistory,
    buildCveQuery,
    normalizePorts,
};
