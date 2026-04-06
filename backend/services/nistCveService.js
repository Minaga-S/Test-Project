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
const RETRYABLE_STATUS_CODES = new Set([408, 429, 500, 502, 503, 504]);

const enrichmentCache = new Map();

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
    ].forEach((value) => pushUnique(terms, value));

    if (Array.isArray(profile.serviceNames)) {
        profile.serviceNames.forEach((serviceName) => pushUnique(terms, serviceName));
    }

    return terms;
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

        const searchTerms = buildSearchTerms(profile);
        const safeMeta = buildSafeMeta(requestMeta);

        if (searchTerms.length === 0) {
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

        const keywordSearch = searchTerms.join(' ');
        const cacheKey = getCacheKey(searchTerms);
        const cachedResult = getCachedResult(cacheKey);

        if (cachedResult) {
            await recordAuditLog('CVE_ENRICHMENT_CACHE_HIT', safeMeta, {
                cacheHit: true,
                searchTermsCount: searchTerms.length,
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
                const response = await axios.get(NVD_API_URL, {
                    params: {
                        keywordSearch,
                        resultsPerPage: DEFAULT_RESULTS_PER_PAGE,
                    },
                    headers,
                    timeout: REQUEST_TIMEOUT_MS,
                });

                const vulnerabilities = Array.isArray(response?.data?.vulnerabilities)
                    ? response.data.vulnerabilities
                    : [];

                const matches = vulnerabilities.map(mapCve).filter((entry) => entry.cveId);
                const result = {
                    source: 'NIST NVD API',
                    query: {
                        keywordSearch,
                        searchTerms,
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
                    searchTermsCount: searchTerms.length,
                    matches: matches.length,
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
                        searchTermsCount: searchTerms.length,
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