const axios = require('axios');

jest.mock('axios');
jest.mock('./auditLogService', () => ({
    record: jest.fn().mockResolvedValue(undefined),
}));

const nistCveService = require('./nistCveService');

describe('nistCveService', () => {
    const validUserId = '64b4c0b9f3b0c2a1d4e5f678';

    beforeEach(() => {
        axios.get.mockReset();
        nistCveService._cache.clear();
    });

    it('should query NVD using profile terms', async () => {
        axios.get.mockResolvedValue({ data: { vulnerabilities: [] } });

        await nistCveService.lookupCves({
            vendor: 'Apache',
            product: 'Log4j',
        }, { userId: validUserId, assetId: 'asset-1' });

        expect(axios.get.mock.calls[0][1].params.keywordSearch).toBe('apache log4j');
    });

    it('should search service aliases when the primary query has no matches', async () => {
        axios.get
            .mockResolvedValueOnce({ data: { vulnerabilities: [] } })
            .mockResolvedValueOnce({
                data: {
                    vulnerabilities: [
                        {
                            cve: {
                                id: 'CVE-2024-0001',
                                descriptions: [{ lang: 'en', value: 'OpenSSH vulnerability' }],
                                metrics: {
                                    cvssMetricV31: [
                                        {
                                            cvssData: {
                                                baseScore: 7.5,
                                                baseSeverity: 'HIGH',
                                            },
                                        },
                                    ],
                                },
                            },
                        },
                    ],
                },
            });

        const result = await nistCveService.lookupCves({ serviceNames: ['ssh'] }, { userId: validUserId, assetId: 'asset-1' });

        expect(result.totalMatches).toBe(1);
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

        const result = await nistCveService.lookupCves({ vendor: 'Apache' }, { userId: validUserId, assetId: 'asset-1' });

        expect(result.matches[0].cveId).toBe('CVE-2021-44228');
    });

    it('should return cached data on repeated query', async () => {
        axios.get.mockResolvedValue({ data: { vulnerabilities: [] } });

        await nistCveService.lookupCves({ vendor: 'Apache' }, { userId: validUserId, assetId: 'asset-1' });
        const secondResult = await nistCveService.lookupCves({ vendor: 'Apache' }, { userId: validUserId, assetId: 'asset-1' });

        expect(secondResult.cacheHit).toBe(true);
    });

    it('should retry when NVD request times out', async () => {
        axios.get
            .mockRejectedValueOnce({ code: 'ECONNABORTED', message: 'timeout' })
            .mockResolvedValue({ data: { vulnerabilities: [] } });

        const result = await nistCveService.lookupCves({ vendor: 'Apache' }, { userId: validUserId, assetId: 'asset-1' });

        expect(result.source).toBe('NIST NVD API');
    });

    it('should throw when NVD API keeps failing', async () => {
        axios.get.mockRejectedValue({ response: { status: 503 }, message: 'service unavailable' });

        await expect(
            nistCveService.lookupCves({ vendor: 'Apache' }, { userId: validUserId, assetId: 'asset-1' })
        ).rejects.toMatchObject({ message: 'service unavailable' });
    });
});