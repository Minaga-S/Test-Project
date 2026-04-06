const { validateAsset } = require('./validators');

describe('validateAsset', () => {
    it('should fail when asset name is missing', () => {
        const result = validateAsset({
            assetType: 'Server',
            criticality: 'High',
        });

        expect(result.errors.assetName).toBe('Asset name is required');
    });

    it('should fail when live scan is enabled without target', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            liveScan: {
                enabled: true,
                target: '',
            },
        });

        expect(result.errors.scanTarget).toBe('Scan target is required when live scan is enabled');
    });

    it('should fail when live scan enabled is string true without target', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            liveScan: {
                enabled: 'true',
                target: '',
            },
        });

        expect(result.errors.scanTarget).toBe('Scan target is required when live scan is enabled');
    });

    it('should fail when scan target format is invalid', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            liveScan: {
                enabled: false,
                target: 'host name with spaces',
            },
        });

        expect(result.errors.scanTarget).toBe('Scan target must be a valid IPv4 address or hostname');
    });

    it('should fail when scan ports contain invalid characters', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            liveScan: {
                ports: '80,443,abc',
            },
        });

        expect(result.errors.scanPorts).toBe('Scan ports must be a comma-separated list of port numbers');
    });

    it('should fail when scan frequency value is invalid', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            liveScan: {
                frequency: 'Hourly',
            },
        });

        expect(result.errors.scanFrequency).toBe('Scan frequency is invalid');
    });

    it('should fail when vulnerability vendor contains illegal characters', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            vulnerabilityProfile: {
                vendor: 'Apache<script>',
            },
        });

        expect(result.errors.vendor).toBe('Vendor contains invalid characters');
    });

    it('should fail when CPE URI format is invalid', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            vulnerabilityProfile: {
                cpeUri: 'invalid-cpe-format',
            },
        });

        expect(result.errors.cpeUri).toBe('CPE URI must use cpe:2.3 format');
    });


    it('should pass when vulnerability product contains commas', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            vulnerabilityProfile: {
                product: 'ftp, ssh, telnet',
            },
        });

        expect(result.errors.product).toBeUndefined();
    });
    it('should pass for valid live scan details', () => {
        const result = validateAsset({
            assetName: 'Core Server',
            assetType: 'Server',
            criticality: 'High',
            liveScan: {
                enabled: true,
                target: '10.0.0.12',
                ports: '22,80,443',
                frequency: 'Daily',
            },
            vulnerabilityProfile: {
                cpeUri: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
                vendor: 'Apache',
                product: 'Log4j',
                productVersion: '2.14.1',
            },
        });

        expect(result.isValid).toBe(true);
    });
});