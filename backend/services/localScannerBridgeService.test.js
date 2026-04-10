const localScannerBridgeService = require('./localScannerBridgeService');
const nmapScanService = require('./nmapScanService');

jest.mock('./nmapScanService', () => ({
    isAllowedScanTarget: jest.fn(),
    assertTargetWithinRequesterNetwork: jest.fn(),
}));

describe('localScannerBridgeService', () => {
    const originalJwtSecret = process.env.JWT_SECRET;

    beforeEach(() => {
        jest.clearAllMocks();
        process.env.JWT_SECRET = 'test-local-scanner-bridge-secret';
        delete process.env.LOCAL_SCANNER_BRIDGE_SECRET;
        nmapScanService.isAllowedScanTarget.mockReturnValue(true);
    });

    afterAll(() => {
        process.env.JWT_SECRET = originalJwtSecret;
    });

    it('should issue a short-lived bridge token for valid local target', () => {
        const issued = localScannerBridgeService.issueScanToken({
            assetId: 'asset-1',
            assetName: 'POS Terminal',
            liveScan: {
                target: '192.168.1.15',
                ports: '22,443',
            },
        }, {
            userId: 'user-1',
            ipAddress: '192.168.1.20',
        });

        expect(typeof issued.bridgeToken).toBe('string');
    });

    it('should reject bridge token issuance when target is outside allowed scope', () => {
        nmapScanService.isAllowedScanTarget.mockReturnValue(false);

        expect(() => localScannerBridgeService.issueScanToken({
            liveScan: {
                target: '8.8.8.8',
            },
        }, {
            userId: 'user-1',
            ipAddress: '192.168.1.20',
        })).toThrow('Live scan target must be localhost or a private-network address');
    });

    it('should consume a valid bridge token once', () => {
        const issued = localScannerBridgeService.issueScanToken({
            assetId: 'asset-1',
            liveScan: {
                target: '10.0.0.10',
                ports: '22',
            },
        }, {
            userId: 'user-77',
            ipAddress: '10.0.0.20',
        });

        const consumed = localScannerBridgeService.consumeScanToken(issued.bridgeToken);

        expect(consumed.userId).toBe('user-77');
    });

    it('should reject replay attempts for an already consumed bridge token', () => {
        const issued = localScannerBridgeService.issueScanToken({
            assetId: 'asset-9',
            liveScan: {
                target: '10.0.0.10',
                ports: '22',
            },
        }, {
            userId: 'user-9',
            ipAddress: '10.0.0.20',
        });

        localScannerBridgeService.consumeScanToken(issued.bridgeToken);

        expect(() => localScannerBridgeService.consumeScanToken(issued.bridgeToken)).toThrow('Bridge token has already been used');
    });
});
