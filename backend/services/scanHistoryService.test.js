const ScanHistory = require('../models/ScanHistory');
const assetSecurityContextService = require('./assetSecurityContextService');
const cveEnrichmentService = require('./cveEnrichmentService');
const nmapScanService = require('./nmapScanService');
const scanHistoryService = require('./scanHistoryService');

jest.mock('../models/ScanHistory', () => ({
    create: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
}));

jest.mock('./cveEnrichmentService', () => ({
    enrichForAsset: jest.fn(),
}));

jest.mock('./nmapScanService', () => ({
    runScan: jest.fn(),
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
    });

    it('should create skipped scan history when target is missing', async () => {
        ScanHistory.create.mockResolvedValue({ status: 'Skipped' });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });
        nmapScanService.isAllowedScanTarget.mockReturnValue(false);

        const result = await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            assetName: 'Internal Database Server',
            liveScan: { enabled: true, target: '', ports: '22' },
            vulnerabilityProfile: {},
        }, 'user-1');

        expect(result.skipped).toBe(true);
    });

    it('should run Nmap when live scan is enabled for a private target', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-1', status: 'Completed' });
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockResolvedValue({
            command: 'nmap',
            target: '10.0.0.10',
            requestedPorts: ['22', '443'],
            openPorts: [22, 443],
            services: [
                { port: 22, service: 'ssh' },
                { port: 443, service: 'https' },
            ],
            hostState: { state: 'up' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,443' },
            vulnerabilityProfile: { vendor: 'nginx' },
        }, 'user-1');

        expect(nmapScanService.runScan).toHaveBeenCalledWith({ target: '10.0.0.10', ports: '22,443' });
    });

    it('should pass scanned services to CVE enrichment', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-1', status: 'Completed' });
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockResolvedValue({
            command: 'nmap',
            target: '10.0.0.10',
            requestedPorts: ['22', '443'],
            openPorts: [22, 443],
            services: [
                { port: 22, service: 'ssh' },
                { port: 443, service: 'https' },
            ],
            hostState: { state: 'up' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,443' },
            vulnerabilityProfile: { vendor: 'nginx' },
        }, 'user-1');

        expect(cveEnrichmentService.enrichForAsset.mock.calls[0][0].serviceNames).toEqual(['ssh', 'https']);
    });

    it('should fall back to enrichment when Nmap is unavailable', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-1', status: 'Skipped' });
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockRejectedValue(new Error('Nmap is not installed or not available on PATH'));
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.buildOnDemandSecurityContext({
            _id: 'asset-1',
            assetName: 'Internal Database Server',
            liveScan: { enabled: true, target: '192.168.1.100', ports: '5432' },
            vulnerabilityProfile: { vendor: 'PostgreSQL', product: 'PostgreSQL' },
        }, 'user-1');

        expect(cveEnrichmentService.enrichForAsset).toHaveBeenCalled();
    });

    it('should return the latest scan history from storage', async () => {
        ScanHistory.findOne.mockReturnValue({ sort: jest.fn().mockResolvedValue({ _id: 'history-1' }) });

        const result = await scanHistoryService.getLatestScanHistory('asset-1', 'user-1');

        expect(result._id).toBe('history-1');
    });
});
