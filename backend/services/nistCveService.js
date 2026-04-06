/**
 * NIST CVE Lookup Service
 */
// NOTE: Queries the public NIST NVD API and normalizes CVE results for the app.

const axios = require('axios');

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const DEFAULT_RESULTS_PER_PAGE = 10;
const REQUEST_TIMEOUT_MS = 10000;

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
    async lookupCves(profile = {}) {
        const searchTerms = buildSearchTerms(profile);
        if (searchTerms.length === 0) {
            return {
                source: 'NIST NVD API',
                query: {},
                matches: [],
                totalMatches: 0,
                retrievedAt: new Date().toISOString(),
            };
        }

        const keywordSearch = searchTerms.join(' ');
        const headers = {};

        if (process.env.NVD_API_KEY) {
            headers.apiKey = process.env.NVD_API_KEY;
        }

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

        return {
            source: 'NIST NVD API',
            query: {
                keywordSearch,
                searchTerms,
            },
            matches,
            totalMatches: matches.length,
            retrievedAt: new Date().toISOString(),
        };
    }
}

module.exports = new NistCveService();
module.exports.buildSearchTerms = buildSearchTerms;