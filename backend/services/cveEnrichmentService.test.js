const nistCveService = require('./nistCveService');
const shodanEnrichmentService = require('./shodanEnrichmentService');
const cveEnrichmentService = require('./cveEnrichmentService');

jest.mock('./nistCveService', () => ({
    lookupCves: jest.fn(),
}));

jest.mock('./shodanEnrichmentService', () => ({
    lookupCves: jest.fn(),
}));

describe('cveEnrichmentService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should use Shodan first for external targets', async () => {
        shodanEnrichmentService.lookupCves.mockResolvedValue({ source: 'Shodan API' });

        const result = await cveEnrichmentService.enrichForAsset({}, '8.8.8.8', {});

        expect(result.source).toBe('Shodan API');
    });

    it('should fall back to NIST when Shodan fails', async () => {
        shodanEnrichmentService.lookupCves.mockRejectedValue(new Error('Missing SHODAN_API_KEY'));
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API' });

        const result = await cveEnrichmentService.enrichForAsset({}, '8.8.8.8', {});

        expect(result.providerFallback.fallbackProvider).toBe('NIST NVD API');
    });

    it('should use NIST directly for private targets', async () => {
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API' });

        const result = await cveEnrichmentService.enrichForAsset({}, '10.0.0.12', {});

        expect(result.source).toBe('NIST NVD API');
    });
});
