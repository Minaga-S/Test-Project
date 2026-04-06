const nistCveService = require('./nistCveService');
const cveEnrichmentService = require('./cveEnrichmentService');

jest.mock('./nistCveService', () => ({
    lookupCves: jest.fn(),
}));

describe('cveEnrichmentService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should use NIST enrichment for external targets', async () => {
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API' });

        const result = await cveEnrichmentService.enrichForAsset({}, '8.8.8.8', {});

        expect(result.source).toBe('NIST NVD API');
    });

    it('should use NIST enrichment for private targets', async () => {
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API' });

        const result = await cveEnrichmentService.enrichForAsset({}, '10.0.0.12', {});

        expect(result.source).toBe('NIST NVD API');
    });
});