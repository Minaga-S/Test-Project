const assetSecurityContextService = require('./assetSecurityContextService');

describe('assetSecurityContextService', () => {
    it('should return fallback context when no scan history exists', () => {
        const context = assetSecurityContextService.buildForAsset({
            _id: 'asset-1',
            assetName: 'Core Server',
            assetType: 'Server',
            liveScan: {
                enabled: true,
                target: '10.0.0.10',
                ports: '22,443',
                frequency: 'Daily',
            },
            vulnerabilityProfile: {
                vendor: 'Apache',
                product: 'Log4j',
            },
        });

        expect(context.liveScan.status).toBe('No completed scan history yet');
    });

    it('should preserve persisted scan history context when available', () => {
        const persistedContext = {
            source: 'persisted-scan-history',
            liveScan: {
                status: 'Completed',
            },
        };

        const context = assetSecurityContextService.buildForAsset(
            { _id: 'asset-1', assetName: 'Core Server', assetType: 'Server' },
            { securityContext: persistedContext }
        );

        expect(context).toBe(persistedContext);
    });

    it('should include observed ports from a scan result', () => {
        const context = assetSecurityContextService.buildFromScanResult(
            {
                _id: 'asset-1',
                assetName: 'Core Server',
                assetType: 'Server',
                vulnerabilityProfile: {},
            },
            {
                target: '10.0.0.10',
                requestedPorts: [22, 443],
                openPorts: [22, 443],
                services: [
                    { port: 22, service: 'ssh' },
                    { port: 443, service: 'https' },
                ],
            },
            {
                source: 'NIST NVD API',
                matches: [],
            }
        );

        expect(context.liveScan.observedOpenPorts.length).toBe(2);
    });
});