const axios = require('axios');
const nistCveService = require('./nistCveService');

jest.mock('axios');

describe('nistCveService', () => {
    beforeEach(() => {
        axios.get.mockReset();
    });

    it('should query NVD using profile terms', async () => {
        axios.get.mockResolvedValue({ data: { vulnerabilities: [] } });

        await nistCveService.lookupCves({
            vendor: 'Apache',
            product: 'Log4j',
        });

        expect(axios.get.mock.calls[0][1].params.keywordSearch).toBe('apache log4j');
    });

    it('should map NVD vulnerabilities into normalized CVE matches', async () => {
        axios.get.mockResolvedValue({
            data: {
                vulnerabilities: [
                    {
                        cve: {
                            id: 'CVE-2021-44228',
                            descriptions: [{ lang: 'en', value: 'Log4j remote code execution' }],
                            metrics: {
                                cvssMetricV31: [
                                    {
                                        cvssData: {
                                            baseScore: 10.0,
                                            baseSeverity: 'CRITICAL',
                                        },
                                    },
                                ],
                            },
                            published: '2021-12-10T00:00:00.000',
                            lastModified: '2024-01-01T00:00:00.000',
                        },
                    },
                ],
            },
        });

        const result = await nistCveService.lookupCves({ vendor: 'Apache' });

        expect(result.matches[0].cveId).toBe('CVE-2021-44228');
    });
});