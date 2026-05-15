const request = require('supertest');

const app = require('./server');

describe('server security headers', () => {
    it('should send baseline security headers on the health check', async () => {
        const response = await request(app).get('/health');

        expect(response.status).toBe(200);
        expect(response.headers['x-frame-options']).toBe('DENY');
        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['referrer-policy']).toBe('no-referrer');
        expect(response.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    });
});