const ScanHistory = require('../models/ScanHistory');
const assetSecurityContextService = require('./assetSecurityContextService');
const nmapScanService = require('./nmapScanService');
const nistCveService = require('./nistCveService');
const scanHistoryService = require('./scanHistoryService');

jest.mock('../models/ScanHistory', () => ({
    create: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
}));

jest.mock('./nmapScanService', () => ({
    runScan: jest.fn(),
}));

jest.mock('./nistCveService', () => ({
    lookupCves: jest.fn(),
}));

jest.mock('./assetSecurityContextService', () => ({
    buildFallbackContext: jest.fn((asset, reason) => ({
        source: 'asset-profile',
        liveScan: { status: reason },
        cve: { matches: [] },
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

        const result = await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            liveScan: { target: '', ports: '22' },
            vulnerabilityProfile: {},
        }, 'user-1');

        expect(result.skipped).toBe(true);
    });

    it('should persist a completed scan history when scan services succeed', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-1', status: 'Completed' });
        nmapScanService.runScan.mockResolvedValue({
            args: ['-Pn', '-sV'],
            target: '10.0.0.10',
            requestedPorts: '22',
            openPorts: [22],
            services: [{ port: 22, service: 'ssh' }],
        });
        nistCveService.lookupCves.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const result = await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            liveScan: { target: '10.0.0.10', ports: '22' },
            vulnerabilityProfile: { vendor: 'Apache' },
        }, 'user-1');

        expect(result.scanHistory.status).toBe('Completed');
    });

    it('should return the latest scan history from storage', async () => {
        ScanHistory.findOne.mockReturnValue({ sort: jest.fn().mockResolvedValue({ _id: 'history-1' }) });

        const result = await scanHistoryService.getLatestScanHistory('asset-1', 'user-1');

        expect(result._id).toBe('history-1');
    });
});