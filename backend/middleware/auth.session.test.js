const express = require('express');
const request = require('supertest');

jest.mock('jsonwebtoken', () => ({
    verify: jest.fn(),
}));

const jwt = require('jsonwebtoken');

const mockUserModel = {
    findById: jest.fn(),
};

jest.mock('../models/User', () => mockUserModel);

const { authMiddleware } = require('./auth');

function createUserQuery(user) {
    return {
        select: jest.fn().mockResolvedValue(user),
    };
}

describe('authMiddleware session version security', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        process.env.JWT_SECRET = 'test-jwt-secret';
    });

    it('should return 401 when the access token session version is stale', async () => {
        jwt.verify.mockReturnValue({
            userId: 'user-id',
            sessionVersion: 1,
            role: 'User',
            permissions: [],
        });
        mockUserModel.findById.mockReturnValue(createUserQuery({
            isActive: true,
            passwordChangedAt: new Date('2026-01-01T00:00:00Z'),
            permissions: [],
            role: 'User',
            sessionVersion: 2,
        }));

        const app = express();
        app.get('/secured', authMiddleware, (req, res) => res.json({ success: true }));

        const response = await request(app)
            .get('/secured')
            .set('Authorization', 'Bearer stale-token');

        expect(response.status).toBe(401);
    });

    it('should allow a request when the access token session version matches', async () => {
        jwt.verify.mockReturnValue({
            userId: 'user-id',
            sessionVersion: 2,
            role: 'User',
            permissions: [],
        });
        mockUserModel.findById.mockReturnValue(createUserQuery({
            isActive: true,
            passwordChangedAt: new Date('2026-01-01T00:00:00Z'),
            permissions: [],
            role: 'User',
            sessionVersion: 2,
        }));

        const app = express();
        app.get('/secured', authMiddleware, (req, res) => res.json({ success: true }));

        const response = await request(app)
            .get('/secured')
            .set('Authorization', 'Bearer valid-token');

        expect(response.status).toBe(200);
    });
});
