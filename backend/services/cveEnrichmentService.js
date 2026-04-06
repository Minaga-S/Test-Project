/**
 * CVE Enrichment Service
 */
// NOTE: Chooses enrichment providers by target type and falls back safely.

const nistCveService = require('./nistCveService');
const shodanEnrichmentService = require('./shodanEnrichmentService');

function normalize(value) {
    return String(value || '').trim().toLowerCase();
}

function isIpv4(value) {
    return /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/.test(String(value || '').trim());
}

function isPrivateOrReservedIpv4(ipAddress) {
    const parts = String(ipAddress || '').split('.').map(Number);
    if (parts.length !== 4) {
        return true;
    }

    const first = parts[0];
    const second = parts[1];

    if (first === 10) return true;
    if (first === 127) return true;
    if (first === 169 && second === 254) return true;
    if (first === 172 && second >= 16 && second <= 31) return true;
    if (first === 192 && second === 168) return true;
    if (first === 100 && second >= 64 && second <= 127) return true;
    return false;
}

function isLikelyExternalTarget(target) {
    const normalizedTarget = normalize(target);
    if (!normalizedTarget) {
        return false;
    }

    if (isIpv4(normalizedTarget)) {
        return !isPrivateOrReservedIpv4(normalizedTarget);
    }

    if (normalizedTarget.endsWith('.local') || normalizedTarget.endsWith('.internal') || normalizedTarget.endsWith('.lan')) {
        return false;
    }

    return true;
}

class CveEnrichmentService {
    async enrichForAsset(profile = {}, scanTarget = '', requestMeta = {}) {
        const isExternalTarget = isLikelyExternalTarget(scanTarget);

        if (isExternalTarget) {
            try {
                return await shodanEnrichmentService.lookupCves({ target: scanTarget, profile }, requestMeta);
            } catch (error) {
                const fallbackResult = await nistCveService.lookupCves(profile, requestMeta);
                return {
                    ...fallbackResult,
                    providerFallback: {
                        attemptedPrimary: 'Shodan API',
                        fallbackProvider: 'NIST NVD API',
                        reason: error.message,
                    },
                };
            }
        }

        return nistCveService.lookupCves(profile, requestMeta);
    }
}

module.exports = new CveEnrichmentService();
module.exports.isLikelyExternalTarget = isLikelyExternalTarget;
