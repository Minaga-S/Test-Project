/**
 * CVE Enrichment Service
 */
// NOTE: Uses NIST NVD enrichment for all targets; external-network scanning is disallowed upstream.

const nistCveService = require('./nistCveService');

class CveEnrichmentService {
    async enrichForAsset(profile = {}, scanTarget = '', requestMeta = {}) {
        return nistCveService.lookupCves(profile, requestMeta);
    }
}

module.exports = new CveEnrichmentService();