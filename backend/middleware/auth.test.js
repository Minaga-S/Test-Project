const express = require('express');
const request = require('supertest');

const { requirePermission } = require('./auth');

describe('requirePermission middleware', () => {
    it('should return 403 when required permission is missing', async () => {
        const app = express();

        app.get('/secured', (req, res, next) => {
            req.user = { permissions: ['asset:read'] };
            next();
        }, requirePermission('asset:write'), (req, res) => {
            res.json({ success: true });
        });

        const response = await request(app).get('/secured');

        expect(response.status).toBe(403);
        expect(response.body.success).toBe(false);
    });

    it('should allow request when required permission exists', async () => {
        const app = express();

        app.get('/secured', (req, res, next) => {
            req.user = { permissions: ['asset:read', 'asset:write'] };
            next();
        }, requirePermission('asset:write'), (req, res) => {
            res.json({ success: true });
        });

        const response = await request(app).get('/secured');

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
    });
});
