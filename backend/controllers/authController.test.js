process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.JWT_EXPIRATION = '24h';
process.env.JWT_REFRESH_EXPIRATION = '7d';

require('../services/auditLogService');
require('../utils/logger');
require('jsonwebtoken');

jest.mock('jsonwebtoken', () => ({
    sign: jest.fn(() => 'signed-token'),
    verify: jest.fn(),
}));

jest.mock('../services/auditLogService', () => ({
    record: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../utils/logger', () => ({
    info: jest.fn(),
    error: jest.fn(),
}));

jest.mock('../services/totpService', () => ({
    generateSecret: jest.fn(),
    buildOtpAuthUrl: jest.fn(),
    generateQrCodeDataUrl: jest.fn(),
    verifyToken: jest.fn(),
}));

const mockUser = jest.fn().mockImplementation((userData) => ({
    ...userData,
    _id: 'user-id',
    save: jest.fn().mockResolvedValue(undefined),
    toJSON() {
        const { save, toJSON, ...user } = this;
        return user;
    },
}));

mockUser.findOne = jest.fn();
mockUser.findById = jest.fn();
mockUser.findByIdAndUpdate = jest.fn();

jest.mock('../models/User', () => mockUser);

const authController = require('./authController');

describe('authController.register', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should register new users as User with the selected department', async () => {
        mockUser.findOne.mockResolvedValue(null);

        const request = {
            body: {
                email: 'newuser@example.com',
                password: 'Password123!',
                fullName: 'New User',
                department: 'Front Office',
                securityQuestions: [
                    { question: 'What city were you born in?', answer: 'Colombo' },
                    { question: 'What is your favorite movie?', answer: 'Inception' },
                    { question: 'What was your childhood nickname?', answer: 'Jay' },
                ],
            },
            ip: '127.0.0.1',
        };

        const response = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        await authController.register(request, response, jest.fn());

        expect(response.json.mock.calls[0][0]).toMatchObject({
            success: true,
            user: {
                role: 'User',
                department: 'Front Office',
            },
        });
    });
});

describe('authController.login security controls', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should lock the account when failed login attempts reach the threshold', async () => {
        const user = {
            _id: 'user-id',
            email: 'locked@example.com',
            isActive: true,
            loginFailedAttempts: 4,
            comparePassword: jest.fn().mockResolvedValue(false),
            save: jest.fn().mockResolvedValue(undefined),
        };

        mockUser.findOne.mockResolvedValue(user);

        const request = {
            body: {
                email: 'locked@example.com',
                password: 'WrongPassword123!',
            },
            ip: '127.0.0.1',
        };

        const response = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        await authController.login(request, response, jest.fn());

        expect(response.status).toHaveBeenCalledWith(423);
    });

    it('should rotate the refresh token version when refreshing a session', async () => {
        const user = {
            _id: 'user-id',
            email: 'rotate@example.com',
            role: 'User',
            permissions: [],
            isActive: true,
            sessionVersion: 2,
            refreshTokenVersion: 3,
            save: jest.fn().mockResolvedValue(undefined),
        };

        mockUser.findById.mockResolvedValue(user);
        require('jsonwebtoken').verify.mockReturnValue({
            userId: 'user-id',
            sessionVersion: 2,
            refreshTokenVersion: 3,
        });

        const request = {
            body: {
                refreshToken: 'refresh-token',
            },
        };

        const response = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };

        await authController.refreshToken(request, response, jest.fn());

        expect(user.refreshTokenVersion).toBe(4);
    });
});
