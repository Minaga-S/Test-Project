const ScanHistory = require('../models/ScanHistory');
const Asset = require('../models/Asset');
const assetSecurityContextService = require('./assetSecurityContextService');
const cveEnrichmentService = require('./cveEnrichmentService');
const nmapScanService = require('./nmapScanService');
const scanHistoryService = require('./scanHistoryService');

jest.mock('../models/ScanHistory', () => ({
    create: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
}));

jest.mock('../models/Asset', () => ({
    updateOne: jest.fn(),
}));

jest.mock('./cveEnrichmentService', () => ({
    enrichForAsset: jest.fn(),
}));

jest.mock('./nmapScanService', () => ({
    isAllowedScanTarget: jest.fn(),
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
        Asset.updateOne.mockResolvedValue({ acknowledged: true, modifiedCount: 1 });
    });

    it('should ingest local scanner result and return preview context for draft asset', async () => {
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const result = await scanHistoryService.ingestLocalScanResult({
            assetId: '',
            assetName: 'Draft Gateway',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,80' },
            vulnerabilityProfile: {},
        }, 'user-1', {
            target: '10.0.0.10',
            requestedPorts: '22,80',
            openPorts: [22, 80],
            services: [
                { port: 22, protocol: 'tcp', service: 'ssh', version: 'OpenSSH 8.0' },
                { port: 80, protocol: 'tcp', service: 'http', version: 'nginx 1.24' },
            ],
            osInfo: 'Linux 6.x',
            osCpe: 'cpe:/o:linux:linux_kernel:6',
        }, {
            ipAddress: '10.0.0.20',
            initiatedBy: 'local-scanner',
        });

        expect(result.persisted).toBe(false);
    });

    it('should persist local scanner result when asset id exists', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-local-1', status: 'Completed' });
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const result = await scanHistoryService.ingestLocalScanResult({
            _id: 'asset-1',
            assetName: 'Persisted Gateway',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,80' },
            vulnerabilityProfile: {},
        }, 'user-1', {
            target: '10.0.0.10',
            requestedPorts: '22,80',
            openPorts: [22],
            services: [
                { port: 22, protocol: 'tcp', service: 'ssh', version: 'OpenSSH 8.0' },
            ],
            osInfo: 'Linux 6.x',
            osCpe: 'cpe:/o:linux:linux_kernel:6',
        }, {
            ipAddress: '10.0.0.20',
            initiatedBy: 'local-scanner',
        });

        expect(result.persisted).toBe(true);
    });

    it('should return enrichment fallback context for on-demand security context', async () => {
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const context = await scanHistoryService.buildOnDemandSecurityContext({
            _id: 'asset-1',
            assetName: 'Internal Database Server',
            liveScan: { enabled: true, target: '192.168.1.100', ports: '22,80' },
            vulnerabilityProfile: {},
        }, 'user-1', { ipAddress: '192.168.1.22' });

        expect(context.liveScan.status).toContain('On-demand CVE enrichment');
    });

    it('should reject local scanner ingestion for disallowed targets', async () => {
        nmapScanService.isAllowedScanTarget.mockReturnValue(false);

        await expect(scanHistoryService.ingestLocalScanResult({
            assetName: 'Draft Gateway',
            liveScan: { enabled: true, target: '8.8.8.8', ports: '22,80' },
            vulnerabilityProfile: {},
        }, 'user-1', {
            target: '8.8.8.8',
            requestedPorts: '22,80',
            openPorts: [22, 80],
            services: [],
        }, {
            ipAddress: '10.0.0.20',
            initiatedBy: 'local-scanner',
        })).rejects.toThrow('Nmap scans are restricted to localhost and private-network targets');
    });

    it('should return the latest scan history from storage', async () => {
        ScanHistory.findOne.mockReturnValue({ sort: jest.fn().mockResolvedValue({ _id: 'history-1' }) });

        const result = await scanHistoryService.getLatestScanHistory('asset-1', 'user-1');

        expect(result._id).toBe('history-1');
    });

    it('should return scan history list with provided limit', async () => {
        const limitMock = jest.fn().mockResolvedValue([{ _id: 'history-1' }, { _id: 'history-2' }]);
        const sortMock = jest.fn(() => ({ limit: limitMock }));
        ScanHistory.find.mockReturnValue({ sort: sortMock });

        const result = await scanHistoryService.getAssetScanHistory('asset-1', 'user-1', 2);

        expect(result.length).toBe(2);
    });
});



