const axios = require('axios');

jest.mock('axios');

const shodanEnrichmentService = require('./shodanEnrichmentService');

describe('shodanEnrichmentService', () => {
    const originalApiKey = process.env.SHODAN_API_KEY;

    beforeEach(() => {
        axios.get.mockReset();
        shodanEnrichmentService._cache.clear();
        process.env.SHODAN_API_KEY = 'test-key';
    });

    afterAll(() => {
        process.env.SHODAN_API_KEY = originalApiKey;
    });

    it('should map Shodan vulns to normalized CVE matches', async () => {
        axios.get.mockResolvedValue({
            data: {
                vulns: {
                    'CVE-2021-44228': {
                        cvss: 10,
                        summary: 'Log4Shell',
                    },
                },
            },
        });

        const result = await shodanEnrichmentService.lookupCves({ target: '8.8.8.8', profile: {} });

        expect(result.matches[0].cveId).toBe('CVE-2021-44228');
    });

    it('should return cached result on repeated target lookup', async () => {
        axios.get.mockResolvedValue({ data: { vulns: {} } });

        await shodanEnrichmentService.lookupCves({ target: '8.8.8.8', profile: {} });
        const result = await shodanEnrichmentService.lookupCves({ target: '8.8.8.8', profile: {} });

        expect(result.cacheHit).toBe(true);
    });
});
