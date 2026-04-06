/**
 * Shodan Enrichment Service
 */
// NOTE: Enriches internet-facing assets with Shodan host intelligence.

const axios = require('axios');

const SHODAN_API_URL = 'https://api.shodan.io/shodan/host';
const ALLOWED_HOSTS = new Set(['api.shodan.io']);
const REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_CACHE_TTL_MS = Number(process.env.SHODAN_CACHE_TTL_MS || 10 * 60 * 1000);

const enrichmentCache = new Map();

function normalize(value) {
    return String(value || '').trim();
}

function enforceOutboundHostPolicy(url) {
    const parsed = new URL(url);
    if (!ALLOWED_HOSTS.has(parsed.hostname)) {
        throw new Error(`Outbound host is not allowlisted: ${parsed.hostname}`);
    }
}

function getCachedResult(cacheKey) {
    const cacheEntry = enrichmentCache.get(cacheKey);
    if (!cacheEntry) {
        return null;
    }

    if (Date.now() > cacheEntry.expiresAt) {
        enrichmentCache.delete(cacheKey);
        return null;
    }

    return cacheEntry.value;
}

function setCachedResult(cacheKey, value) {
    enrichmentCache.set(cacheKey, {
        value,
        expiresAt: Date.now() + DEFAULT_CACHE_TTL_MS,
    });
}

function mapShodanVulns(vulns = {}) {
    return Object.entries(vulns)
        .map(([cveId, details]) => ({
            cveId,
            description: normalize(details?.summary),
            severity: normalize(details?.cvss && details.cvss >= 9 ? 'CRITICAL' : details?.cvss && details.cvss >= 7 ? 'HIGH' : details?.cvss && details.cvss >= 4 ? 'MEDIUM' : 'LOW'),
            cvssScore: typeof details?.cvss === 'number' ? details.cvss : null,
            cvssVersion: '',
            published: '',
            lastModified: '',
        }))
        .filter((entry) => normalize(entry.cveId).length > 0);
}

class ShodanEnrichmentService {
    async lookupCves({ target, profile = {} } = {}) {
        enforceOutboundHostPolicy(SHODAN_API_URL);

        const normalizedTarget = normalize(target);
        if (!normalizedTarget) {
            return {
                source: 'Shodan API',
                query: { target: '' },
                matches: [],
                totalMatches: 0,
                retrievedAt: new Date().toISOString(),
                confidence: 'Low',
                cacheHit: false,
            };
        }

        if (!process.env.SHODAN_API_KEY) {
            throw new Error('Missing SHODAN_API_KEY');
        }

        const cacheKey = normalizedTarget.toLowerCase();
        const cachedResult = getCachedResult(cacheKey);
        if (cachedResult) {
            return {
                ...cachedResult,
                cacheHit: true,
            };
        }

        const response = await axios.get(`${SHODAN_API_URL}/${encodeURIComponent(normalizedTarget)}`, {
            params: {
                key: process.env.SHODAN_API_KEY,
            },
            timeout: REQUEST_TIMEOUT_MS,
        });

        const matches = mapShodanVulns(response?.data?.vulns || {});
        const result = {
            source: 'Shodan API',
            query: {
                target: normalizedTarget,
                vendor: normalize(profile.vendor),
                product: normalize(profile.product),
            },
            matches,
            totalMatches: matches.length,
            retrievedAt: new Date().toISOString(),
            confidence: matches.length > 0 ? 'High' : 'Medium',
            cacheHit: false,
        };

        setCachedResult(cacheKey, result);
        return result;
    }
}

module.exports = new ShodanEnrichmentService();
module.exports._cache = enrichmentCache;
