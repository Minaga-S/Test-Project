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
    runScan: jest.fn(),
    isAllowedScanTarget: jest.fn(),
    assertTargetWithinRequesterNetwork: jest.fn(),
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
                { port: 22, service: 'ssh', version: 'OpenSSH 8.0' },
                { port: 443, service: 'https', version: 'Apache 2.4' },
            ],
            hostState: { state: 'up', hostName: 'db-local' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,443' },
            vulnerabilityProfile: { vendor: 'nginx' },
        }, 'user-1', { ipAddress: '10.0.0.50' });

        expect(nmapScanService.runScan).toHaveBeenCalledWith({ target: '10.0.0.10', ports: '22,443', requestIp: '10.0.0.50' });
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
                { port: 22, service: 'ssh', version: 'OpenSSH 8.0' },
                { port: 443, service: 'https', version: 'Apache 2.4' },
            ],
            hostState: { state: 'up' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
            osInfo: 'Linux 5.x',
            osCpe: 'cpe:/o:linux:linux_kernel:5',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,443' },
            vulnerabilityProfile: { vendor: 'nginx' },
        }, 'user-1', { ipAddress: '10.0.0.9' });

        expect(cveEnrichmentService.enrichForAsset.mock.calls[0][0]).toEqual(expect.objectContaining({
            serviceNames: ['ssh OpenSSH 8.0', 'https Apache 2.4'],
            osName: 'Linux 5.x',
            cpeUri: 'cpe:/o:linux:linux_kernel:5',
        }));
    });

    it('should infer and persist missing vulnerability profile fields from scan output', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-1', status: 'Completed' });
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockResolvedValue({
            command: 'nmap',
            target: '10.0.0.10',
            requestedPorts: ['22', '443'],
            openPorts: [22, 443],
            services: [
                { port: 22, service: 'ssh', version: 'OpenSSH 8.0' },
                { port: 443, service: 'https', version: 'Apache 2.4' },
            ],
            hostState: { state: 'up', hostName: 'edge-gateway.local' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,443' },
            vulnerabilityProfile: { vendor: '', product: '', osName: '' },
        }, 'user-1', { ipAddress: '10.0.0.9' });

        expect(Asset.updateOne).toHaveBeenCalled();
    });

    it('should persist inferred vulnerability profile during preview for an existing asset', async () => {
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockResolvedValue({
            command: 'nmap',
            target: '10.0.0.10',
            requestedPorts: ['22', '443'],
            openPorts: [22, 443],
            services: [
                { port: 22, service: 'ssh', version: 'OpenSSH 8.0' },
                { port: 443, service: 'https', version: 'Apache 2.4' },
            ],
            hostState: { state: 'up' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
            osInfo: 'Linux 5.x',
            osCpe: 'cpe:/o:linux:linux_kernel:5',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runPreviewScan({
            _id: 'asset-1',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22,443' },
            vulnerabilityProfile: { vendor: '', product: '', osName: '' },
        }, 'user-1', { ipAddress: '10.0.0.9' });

        expect(Asset.updateOne).toHaveBeenCalledWith(
            { _id: 'asset-1', userId: 'user-1' },
            expect.objectContaining({
                $set: expect.objectContaining({
                    vulnerabilityProfile: expect.objectContaining({
                        vendor: 'OpenSSH',
                        product: 'ssh OpenSSH 8.0, https Apache 2.4',
                        osName: 'Linux 5.x',
                        cpeUri: 'cpe:/o:linux:linux_kernel:5',
                    }),
                }),
            })
        );
    });

    it('should not persist preview scan results for a draft asset without an id', async () => {
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockResolvedValue({
            command: 'nmap',
            target: '10.0.0.10',
            requestedPorts: ['22'],
            openPorts: [22],
            services: [{ port: 22, service: 'ssh' }],
            hostState: { state: 'up' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
            osInfo: 'Linux 5.x',
            osCpe: 'cpe:/o:linux:linux_kernel:5',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runPreviewScan({
            _id: '',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22' },
            vulnerabilityProfile: { vendor: '', product: '', osName: '' },
        }, 'user-1', { ipAddress: '10.0.0.9' });

        expect(Asset.updateOne).not.toHaveBeenCalled();
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
        }, 'user-1', { ipAddress: '192.168.1.22' });

        expect(cveEnrichmentService.enrichForAsset).toHaveBeenCalled();
    });

    it('should include observed open ports when on-demand live scan succeeds', async () => {
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockResolvedValue({
            command: 'nmap',
            target: '192.168.1.100',
            requestedPorts: ['22', '80'],
            openPorts: [22, 80],
            services: [
                { port: 22, service: 'ssh' },
                { port: 80, service: 'http' },
            ],
            hostState: { state: 'up' },
            rawOutput: 'Host: 192.168.1.100 () Status: Up',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        const context = await scanHistoryService.buildOnDemandSecurityContext({
            _id: 'asset-1',
            assetName: 'Internal Database Server',
            liveScan: { enabled: true, target: '192.168.1.100', ports: '22,80' },
            vulnerabilityProfile: {},
        }, 'user-1', { ipAddress: '192.168.1.22' });

        expect(context.liveScan.observedOpenPorts).toEqual([22, 80]);
    });

    it('should not persist hostname as osName when scan output only includes host name', async () => {
        ScanHistory.create.mockResolvedValue({ _id: 'history-1', status: 'Completed' });
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
        nmapScanService.runScan.mockResolvedValue({
            command: 'nmap',
            target: '10.0.0.10',
            requestedPorts: ['22'],
            openPorts: [22],
            services: [],
            hostState: { state: 'up', hostName: 'edge-gateway.local' },
            rawOutput: 'Host: 10.0.0.10 () Status: Up',
        });
        cveEnrichmentService.enrichForAsset.mockResolvedValue({ source: 'NIST NVD API', matches: [] });

        await scanHistoryService.runAssetScan({
            _id: 'asset-1',
            assetName: 'Production API Server',
            liveScan: { enabled: true, target: '10.0.0.10', ports: '22' },
            vulnerabilityProfile: { vendor: '', product: '', osName: '' },
        }, 'user-1', { ipAddress: '10.0.0.9' });

        expect(Asset.updateOne).not.toHaveBeenCalled();
    });
    it('should return the latest scan history from storage', async () => {
        ScanHistory.findOne.mockReturnValue({ sort: jest.fn().mockResolvedValue({ _id: 'history-1' }) });

        const result = await scanHistoryService.getLatestScanHistory('asset-1', 'user-1');

        expect(result._id).toBe('history-1');
    });
});



