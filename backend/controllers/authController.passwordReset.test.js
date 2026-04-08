process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';

jest.mock('../services/auditLogService', () => ({
    record: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../utils/logger', () => ({
    info: jest.fn(),
    error: jest.fn(),
}));

jest.mock('../services/totpService', () => ({
    verifyToken: jest.fn(),
    generateSecret: jest.fn(),
    buildOtpAuthUrl: jest.fn(),
    generateQrCodeDataUrl: jest.fn(),
}));

const mockUserModel = {
    findOne: jest.fn(),
    findById: jest.fn(),
    findByIdAndUpdate: jest.fn(),
};

jest.mock('../models/User', () => mockUserModel);

const authController = require('./authController');
const totpService = require('../services/totpService');

function createUser(overrides = {}) {
    return {
        _id: 'user-id',
        email: 'user@example.com',
        isActive: true,
        twoFactorEnabled: true,
        twoFactorSecret: 'totp-secret',
        recoveryCodeHashes: [],
        passwordResetFailedAttempts: 0,
        passwordResetLockUntil: null,
        save: jest.fn().mockResolvedValue(undefined),
        ...overrides,
    };
}

describe('authController password reset flows', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return generic response for forgot password request', async () => {
        mockUserModel.findOne.mockResolvedValue(null);

        const request = { body: { email: 'missing@example.com' } };
        const response = { json: jest.fn() };

        await authController.forgotPassword(request, response, jest.fn());

        expect(response.json).toHaveBeenCalledWith(expect.objectContaining({
            success: true,
        }));
    });

    it('should reject password reset with weak password', async () => {
        const request = {
            body: {
                email: 'user@example.com',
                newPassword: 'weakpass',
                totpCode: '123456',
            },
        };

        const response = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        await authController.resetPassword(request, response, jest.fn());

        expect(response.status).toHaveBeenCalledWith(400);
    });

    it('should reset password when valid authenticator code is provided', async () => {
        const user = createUser();
        mockUserModel.findOne.mockResolvedValue(user);
        totpService.verifyToken.mockReturnValue(true);

        const request = {
            ip: '127.0.0.1',
            body: {
                email: 'user@example.com',
                newPassword: 'StrongPassword123!',
                totpCode: '123456',
            },
        };

        const response = {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
        };

        await authController.resetPassword(request, response, jest.fn());

        expect(response.json).toHaveBeenCalledWith(expect.objectContaining({
            success: true,
        }));
        expect(user.password).toBe('StrongPassword123!');
    });

    it('should return unauthorized on invalid authenticator and recovery codes', async () => {
        const user = createUser();
        mockUserModel.findOne.mockResolvedValue(user);
        totpService.verifyToken.mockReturnValue(false);

        const request = {
            body: {
                email: 'user@example.com',
                newPassword: 'StrongPassword123!',
                totpCode: '123456',
                recoveryCode: 'INVALID-CODE',
            },
        };

        const response = {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
        };

        await authController.resetPassword(request, response, jest.fn());

        expect(response.status).toHaveBeenCalledWith(401);
    });
});

describe('authController two-factor setup labels', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should build 2FA setup with email label and unique issuer', async () => {
        const user = createUser({
            email: 'john@gmail.com',
            twoFactorEnabled: false,
            twoFactorSecret: '',
            twoFactorTempSecret: '',
        });

        mockUserModel.findById.mockResolvedValue(user);
        totpService.generateSecret.mockReturnValue('ABCD1234EFGH5678');
        totpService.buildOtpAuthUrl.mockReturnValue('otpauth://totp/mock');
        totpService.generateQrCodeDataUrl.mockResolvedValue('data:image/png;base64,mock');

        const request = { user: { userId: 'user-id' } };
        const response = { json: jest.fn(), status: jest.fn().mockReturnThis() };

        await authController.setupTwoFactor(request, response, jest.fn());

        expect(totpService.buildOtpAuthUrl).toHaveBeenCalledWith(expect.objectContaining({
            email: 'john@gmail.com',
            appName: 'HCGS',
            accountName: 'john@gmail.com - GH5678',
        }));
    });
});


