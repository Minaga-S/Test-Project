const ScanHistory = require('../models/ScanHistory');
const assetSecurityContextService = require('./assetSecurityContextService');
const nistCveService = require('./nistCveService');
const scanHistoryService = require('./scanHistoryService');

jest.mock('../models/ScanHistory', () => ({
    create: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
}));

jest.mock('./nistCveService', () => ({
    lookupCves: jest.fn(),
}));

jest.mock('./assetSecurityContextService', () => ({
    buildFallbackContext: jest.fn((asset, reason, cveResult) => ({
        source: 'asset-profile',
        liveScan: { status: reason },
        cve: { matches: cveResult?.matches || [] },
    })),
    buildFromScanResult: jest.fn((asset, scanResult, cveResult) => ({
        source: 'persisted-scan-history',
        liveScan: { observedOpenPorts: scanResult.openPorts || [] },
        cve: { matches: cveResult.matches || [] },
    })),
}));

describe('scanHistoryService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should create skipped scan history when target is missing', async () => {
        ScanHistory.create.mockResolvedValue({ status: 'Skipped' });
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const result = await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            liveScan: { enabled: true, target: '', ports: '22' },
            vulnerabilityProfile: {},
        }, 'user-1');

        expect(result.skipped).toBe(true);
    });

    it('should persist a completed simulated scan history when live scan is enabled', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-1', status: 'Completed' });
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const result = await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22' },
            vulnerabilityProfile: { vendor: 'Apache' },
        }, 'user-1');

        expect(result.scanHistory.status).toBe('Completed');
    });

    it('should build on-demand security context with NIST enrichment', async () => {
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const result = await scanHistoryService.buildOnDemandSecurityContext({
            _id: 'asset-1',
            liveScan: { enabled: false, target: '', ports: '' },
            vulnerabilityProfile: { vendor: 'Apache' },
        }, 'user-1');

        expect(result.source).toBe('asset-profile');
    });

    it('should return the latest scan history from storage', async () => {
        ScanHistory.findOne.mockReturnValue({ sort: jest.fn().mockResolvedValue({ _id: 'history-1' }) });

        const result = await scanHistoryService.getLatestScanHistory('asset-1', 'user-1');

        expect(result._id).toBe('history-1');
    });
});