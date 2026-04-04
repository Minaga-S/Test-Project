const totpService = require('./totpService');
const { authenticator } = require('otplib');

describe('totpService', () => {
    it('should generate a non-empty secret', () => {
        const secret = totpService.generateSecret();

        expect(secret.length > 0).toBe(true);
    });

    it('should create an otpauth URI', () => {
        const otpAuthUrl = totpService.buildOtpAuthUrl({
            appName: 'HCGS',
            email: 'user@example.com',
            secret: totpService.generateSecret(),
        });

        expect(otpAuthUrl.startsWith('otpauth://totp/')).toBe(true);
    });

    it('should verify a valid token', () => {
        const secret = totpService.generateSecret();
        const token = authenticator.generate(secret);
        const result = totpService.verifyToken(secret, token);

        expect(result).toBe(true);
    });

    it('should reject an invalid token', () => {
        const secret = totpService.generateSecret();
        const result = totpService.verifyToken(secret, '123456');

        expect(result).toBe(false);
    });

    it('should generate a png data URL for QR code', async () => {
        const secret = totpService.generateSecret();
        const otpAuthUrl = totpService.buildOtpAuthUrl({
            appName: 'HCGS',
            email: 'user@example.com',
            secret,
        });
        const qrCode = await totpService.generateQrCodeDataUrl(otpAuthUrl);

        expect(qrCode.startsWith('data:image/png;base64,')).toBe(true);
    });
});
