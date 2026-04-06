/**
 * NIST CVE Lookup Service
 */
// NOTE: Queries the public NIST NVD API and normalizes CVE results for the app.

const axios = require('axios');
const auditLogService = require('./auditLogService');
const logger = require('../utils/logger');

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const ALLOWED_HOSTS = new Set(['services.nvd.nist.gov']);
const DEFAULT_RESULTS_PER_PAGE = 10;
const REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_CACHE_TTL_MS = Number(process.env.NVD_CACHE_TTL_MS || 15 * 60 * 1000);
const MAX_RETRIES = Number(process.env.NVD_MAX_RETRIES || 2);
const ENABLE_FALLBACK_TERM_SEARCH = process.env.NVD_ENABLE_FALLBACK_TERMS === 'true';
const RETRYABLE_STATUS_CODES = new Set([408, 429, 500, 502, 503, 504]);

const enrichmentCache = new Map();

const SERVICE_KEYWORD_ALIASES = new Map([
    ['ssh', ['openssh']],
    ['http', ['apache http server', 'apache']],
    ['https', ['openssl', 'tls', 'nginx']],
    ['mysql', ['mysql server', 'mariadb']],
    ['tomcat', ['apache tomcat']],
    ['nginx', ['nginx']],
    ['ftp', ['vsftpd', 'proftpd']],
    ['smb', ['samba']],
    ['smtp', ['postfix', 'exim']],
    ['dns', ['bind', 'isc bind']],
    ['snmp', ['net-snmp']],
    ['postgres', ['postgresql']],
    ['redis', ['redis']],
    ['mongodb', ['mongodb']],
    ['rdp', ['remote desktop', 'mstsc']],
]);

function normalize(value) {
    return String(value || '').trim();
}

function pushUnique(values, value) {
    const normalizedValue = normalize(value).toLowerCase();
    if (!normalizedValue || values.includes(normalizedValue)) {
        return;
    }

    values.push(normalizedValue);
}

function maskValue(value, visibleCharacters = 4) {
    const normalizedValue = normalize(value);
    if (!normalizedValue) {
        return '';
    }

    const suffix = normalizedValue.slice(-visibleCharacters);
    return `***${suffix}`;
}

function buildSafeMeta(meta = {}) {
    return {
        userId: meta.userId ? String(meta.userId) : '',
        assetId: meta.assetId ? String(meta.assetId) : '',
        ipAddress: normalize(meta.ipAddress),
    };
}

function enforceOutboundHostPolicy(url) {
    const parsed = new URL(url);
    if (!ALLOWED_HOSTS.has(parsed.hostname)) {
        throw new Error(`Outbound host is not allowlisted: ${parsed.hostname}`);
    }
}

function getCacheKey(searchTerms) {
    return searchTerms.join('|');
}

function getCachedResult(cacheKey) {
    const entry = enrichmentCache.get(cacheKey);
    if (!entry) {
        return null;
    }

    if (Date.now() > entry.expiresAt) {
        enrichmentCache.delete(cacheKey);
        return null;
    }

    return entry.value;
}

function setCachedResult(cacheKey, value) {
    enrichmentCache.set(cacheKey, {
        value,
        expiresAt: Date.now() + DEFAULT_CACHE_TTL_MS,
    });
}

function computeConfidence(profile, matchesCount) {
    const hasCpe = normalize(profile.cpeUri).length > 0;
    const hasVendorProduct = normalize(profile.vendor).length > 0 && normalize(profile.product).length > 0;
    const hasVersion = normalize(profile.productVersion).length > 0;

    if (matchesCount > 0 && (hasCpe || (hasVendorProduct && hasVersion))) {
        return 'High';
    }

    if (matchesCount > 0 || hasCpe || hasVendorProduct) {
        return 'Medium';
    }

    return 'Low';
}

function shouldRetry(error) {
    const status = error?.response?.status;
    if (status && RETRYABLE_STATUS_CODES.has(status)) {
        return true;
    }

    return error?.code === 'ECONNABORTED' || error?.code === 'ETIMEDOUT';
}

async function sleep(ms) {
    await new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

async function recordAuditLog(action, meta, detail = {}) {
    await auditLogService.record({
        actorUserId: meta.userId || null,
        action,
        entityType: 'CveEnrichment',
        entityId: meta.assetId || '',
        ipAddress: meta.ipAddress || '',
        meta: {
            cacheHit: Boolean(detail.cacheHit),
            attempts: detail.attempts || 0,
            durationMs: detail.durationMs || 0,
            searchTermsCount: detail.searchTermsCount || 0,
            matches: detail.matches || 0,
            confidence: detail.confidence || '',
            errorCode: detail.errorCode || '',
            statusCode: detail.statusCode || 0,
            safeProfile: {
                vendor: maskValue(detail.vendor),
                product: maskValue(detail.product),
                cpeUri: maskValue(detail.cpeUri),
            },
        },
    });
}

function buildSearchTerms(profile = {}) {
    const terms = [];

    [
        profile.cpeUri,
        profile.vendor,
        profile.product,
        profile.productVersion,
        profile.osName,
        profile.assetName,
        profile.assetType,
    ].forEach((value) => pushUnique(terms, value));

    if (Array.isArray(profile.serviceNames)) {
        const orderedServiceNames = [...profile.serviceNames]
            .map((serviceName) => normalize(serviceName).toLowerCase())
            .filter(Boolean)
            .sort();
        orderedServiceNames.forEach((serviceName) => pushUnique(terms, serviceName));
    }

    return terms.sort();
}

function buildPrimarySearchTerms(profile = {}) {
    const cpeUri = normalize(profile.cpeUri).toLowerCase();
    if (cpeUri) {
        return [cpeUri];
    }

    const preferredTerms = [];
    [profile.vendor, profile.product, profile.productVersion, profile.osName]
        .forEach((value) => pushUnique(preferredTerms, value));

    if (preferredTerms.length >= 2) {
        return preferredTerms;
    }

    const baseTerms = buildSearchTerms(profile);
    if (baseTerms.length === 0) {
        return [];
    }

    return baseTerms.slice(0, 4);
}

function buildDeterministicQueryCandidates(profile = {}) {
    const candidates = [];
    const cpeUri = normalize(profile.cpeUri).toLowerCase();
    const vendor = normalize(profile.vendor).toLowerCase();
    const product = normalize(profile.product).toLowerCase();
    const productVersion = normalize(profile.productVersion).toLowerCase();
    const osName = normalize(profile.osName).toLowerCase();

    if (cpeUri) {
        pushUnique(candidates, cpeUri);
    }

    if (vendor && product && productVersion) {
        pushUnique(candidates, `${vendor} ${product} ${productVersion}`);
    }

    if (vendor && product) {
        pushUnique(candidates, `${vendor} ${product}`);
    }

    if (product) {
        pushUnique(candidates, product);
    }

    if (osName) {
        pushUnique(candidates, osName);
    }

    const serviceNames = Array.isArray(profile.serviceNames)
        ? profile.serviceNames
            .map((serviceName) => normalize(serviceName).toLowerCase())
            .filter(Boolean)
            .sort()
        : [];
    serviceNames.slice(0, 2).forEach((serviceName) => pushUnique(candidates, serviceName));

    if (candidates.length > 0) {
        return candidates;
    }

    return buildPrimarySearchTerms(profile);
}

function buildFallbackSearchTerms(profile = {}) {
    const terms = [];
    const primaryTerms = buildSearchTerms(profile);

    primaryTerms.forEach((term) => pushUnique(terms, term));

    if (Array.isArray(profile.serviceNames)) {
        profile.serviceNames.forEach((serviceName) => {
            const normalizedServiceName = normalize(serviceName).toLowerCase();
            const aliases = SERVICE_KEYWORD_ALIASES.get(normalizedServiceName) || [];
            aliases.forEach((alias) => pushUnique(terms, alias));
        });
    }

    return terms;
}

function mergeCveMatches(targetMatches = [], sourceMatches = []) {
    const seen = new Set(targetMatches.map((entry) => entry.cveId));

    sourceMatches.forEach((entry) => {
        if (entry?.cveId && !seen.has(entry.cveId)) {
            seen.add(entry.cveId);
            targetMatches.push(entry);
        }
    });

    return targetMatches;
}

function extractCvssScore(metrics = {}) {
    const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
    if (v31) {
        return {
            version: '3.1',
            score: v31.baseScore,
            severity: v31.baseSeverity,
        };
    }

    const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
    if (v30) {
        return {
            version: '3.0',
            score: v30.baseScore,
            severity: v30.baseSeverity,
        };
    }

    const v2 = metrics.cvssMetricV2?.[0]?.cvssData;
    if (v2) {
        return {
            version: '2.0',
            score: v2.baseScore,
            severity: metrics.cvssMetricV2?.[0]?.baseSeverity,
        };
    }

    return {
        version: '',
        score: null,
        severity: 'UNKNOWN',
    };
}

function mapCve(vulnerability) {
    const cve = vulnerability?.cve || {};
    const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
    const descriptionEntry = descriptions.find((entry) => entry?.lang === 'en') || descriptions[0] || {};
    const cvss = extractCvssScore(cve.metrics || {});

    return {
        cveId: cve.id || '',
        description: descriptionEntry.value || '',
        severity: cvss.severity || 'UNKNOWN',
        cvssScore: cvss.score,
        cvssVersion: cvss.version,
        published: cve.published || '',
        lastModified: cve.lastModified || '',
    };
}

class NistCveService {
    async lookupCves(profile = {}, requestMeta = {}) {
        enforceOutboundHostPolicy(NVD_API_URL);

        const queryCandidates = buildDeterministicQueryCandidates(profile);
        const safeMeta = buildSafeMeta(requestMeta);

        if (queryCandidates.length === 0) {
            return {
                source: 'NIST NVD API',
                query: {},
                matches: [],
                totalMatches: 0,
                retrievedAt: new Date().toISOString(),
                confidence: 'Low',
                cacheHit: false,
            };
        }

        const cacheKey = getCacheKey(queryCandidates);
        const cachedResult = getCachedResult(cacheKey);

        if (cachedResult) {
            await recordAuditLog('CVE_ENRICHMENT_CACHE_HIT', safeMeta, {
                cacheHit: true,
                searchTermsCount: queryCandidates.length,
                matches: cachedResult.totalMatches,
                confidence: cachedResult.confidence,
                vendor: profile.vendor,
                product: profile.product,
                cpeUri: profile.cpeUri,
            });

            return {
                ...cachedResult,
                cacheHit: true,
            };
        }

        const headers = {};
        if (process.env.NVD_API_KEY) {
            headers.apiKey = process.env.NVD_API_KEY;
        }

        let attempt = 0;
        const startedAt = Date.now();

        while (attempt <= MAX_RETRIES) {
            try {
                let matches = [];
                let matchedKeywordSearch = '';

                for (const queryCandidate of queryCandidates) {
                    const response = await axios.get(NVD_API_URL, {
                        params: {
                            keywordSearch: queryCandidate,
                            resultsPerPage: DEFAULT_RESULTS_PER_PAGE,
                        },
                        headers,
                        timeout: REQUEST_TIMEOUT_MS,
                    });

                    const vulnerabilities = Array.isArray(response?.data?.vulnerabilities)
                        ? response.data.vulnerabilities
                        : [];
                    const queryMatches = vulnerabilities.map(mapCve).filter((entry) => entry.cveId);

                    if (queryMatches.length > 0) {
                        matches = queryMatches;
                        matchedKeywordSearch = queryCandidate;
                        break;
                    }
                }

                if (matches.length > 0) {
                    const result = {
                        source: 'NIST NVD API',
                        query: {
                            keywordSearch: matchedKeywordSearch,
                            queryCandidates,
                        },
                        matches,
                        totalMatches: matches.length,
                        retrievedAt: new Date().toISOString(),
                        confidence: computeConfidence(profile, matches.length),
                        cacheHit: false,
                    };

                    setCachedResult(cacheKey, result);

                    await recordAuditLog('CVE_ENRICHMENT_SUCCESS', safeMeta, {
                        cacheHit: false,
                        durationMs: Date.now() - startedAt,
                        attempts: attempt + 1,
                        searchTermsCount: queryCandidates.length,
                        matches: matches.length,
                        confidence: result.confidence,
                        vendor: profile.vendor,
                        product: profile.product,
                        cpeUri: profile.cpeUri,
                    });

                    return result;
                }

                const fallbackTerms = ENABLE_FALLBACK_TERM_SEARCH
                    ? buildFallbackSearchTerms(profile).filter((term) => !queryCandidates.includes(term))
                    : [];
                const fallbackMatches = [];

                for (const term of fallbackTerms) {
                    try {
                        const fallbackResponse = await axios.get(NVD_API_URL, {
                            params: {
                                keywordSearch: term,
                                resultsPerPage: DEFAULT_RESULTS_PER_PAGE,
                            },
                            headers,
                            timeout: REQUEST_TIMEOUT_MS,
                        });

                        const fallbackVulnerabilities = Array.isArray(fallbackResponse?.data?.vulnerabilities)
                            ? fallbackResponse.data.vulnerabilities
                            : [];
                        const termMatches = fallbackVulnerabilities.map(mapCve).filter((entry) => entry.cveId);
                        mergeCveMatches(fallbackMatches, termMatches);
                    } catch (fallbackError) {
                        if (!shouldRetry(fallbackError)) {
                            continue;
                        }
                    }
                }

                const result = {
                    source: 'NIST NVD API',
                    query: {
                        queryCandidates,
                        fallbackSearchTerms: fallbackTerms,
                    },
                    matches: fallbackMatches,
                    totalMatches: fallbackMatches.length,
                    retrievedAt: new Date().toISOString(),
                    confidence: computeConfidence(profile, fallbackMatches.length),
                    cacheHit: false,
                };

                setCachedResult(cacheKey, result);

                await recordAuditLog('CVE_ENRICHMENT_SUCCESS', safeMeta, {
                    cacheHit: false,
                    durationMs: Date.now() - startedAt,
                    attempts: attempt + 1,
                    searchTermsCount: queryCandidates.length + fallbackTerms.length,
                    matches: fallbackMatches.length,
                    confidence: result.confidence,
                    vendor: profile.vendor,
                    product: profile.product,
                    cpeUri: profile.cpeUri,
                });

                return result;
            } catch (error) {
                const canRetry = attempt < MAX_RETRIES && shouldRetry(error);
                if (!canRetry) {
                    await recordAuditLog('CVE_ENRICHMENT_FAILURE', safeMeta, {
                        durationMs: Date.now() - startedAt,
                        attempts: attempt + 1,
                        searchTermsCount: queryCandidates.length,
                        errorCode: error?.code || '',
                        statusCode: error?.response?.status || 0,
                        vendor: profile.vendor,
                        product: profile.product,
                        cpeUri: profile.cpeUri,
                    });

                    logger.error(`NVD enrichment failed: ${error.message}`);
                    throw error;
                }

                const backoffMs = 250 * (2 ** attempt);
                await sleep(backoffMs);
                attempt += 1;
            }
        }

        throw new Error('NVD enrichment failed after retries');
    }
}

module.exports = new NistCveService();
module.exports.buildSearchTerms = buildSearchTerms;
module.exports.computeConfidence = computeConfidence;
module.exports._cache = enrichmentCache;