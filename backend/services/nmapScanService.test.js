const nmapScanService = require('./nmapScanService');

describe('nmapScanService', () => {
    it('should allow localhost target', () => {
        expect(nmapScanService.isAllowedScanTarget('localhost')).toBe(true);
    });

    it('should allow private IPv4 target', () => {
        expect(nmapScanService.isAllowedScanTarget('192.168.1.20')).toBe(true);
    });

    it('should reject public IPv4 target', () => {
        expect(nmapScanService.isAllowedScanTarget('8.8.8.8')).toBe(false);
    });

    it('should allow local hostname suffix', () => {
        expect(nmapScanService.isAllowedScanTarget('edge-gateway.local')).toBe(true);
    });

    it('should normalize requester localhost IPv6 address', () => {
        expect(nmapScanService.normalizeRequesterIp('::1')).toBe('127.0.0.1');
    });

    it('should allow same-subnet target for private requester', () => {
        expect(() => nmapScanService.assertTargetWithinRequesterNetwork('10.0.0.10', '10.0.0.50')).not.toThrow();
    });

    it('should reject cross-subnet target for private requester', () => {
        expect(() => nmapScanService.assertTargetWithinRequesterNetwork('10.0.0.10', '10.0.1.25')).toThrow('Scan target must be on the same private subnet as the requester');
    });

    it('should bypass subnet check for localhost requester', () => {
        expect(() => nmapScanService.assertTargetWithinRequesterNetwork('192.168.1.25', '127.0.0.1')).not.toThrow();
    });
});
