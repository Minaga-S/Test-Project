const express = require('express');
const request = require('supertest');
const { body } = require('express-validator');
const { validateRequest } = require('./validateRequest');

describe('validateRequest middleware', () => {
    it('should return 400 when validation fails', async () => {
        const app = express();
        app.use(express.json());
        app.post('/test', [body('email').isEmail().withMessage('Valid email is required'), validateRequest], (req, res) => {
            res.json({ success: true });
        });

        const response = await request(app)
            .post('/test')
            .send({ email: 'invalid' });

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
    });

    it('should pass through when validation succeeds', async () => {
        const app = express();
        app.use(express.json());
        app.post('/test', [body('email').isEmail().withMessage('Valid email is required'), validateRequest], (req, res) => {
            res.json({ success: true });
        });

        const response = await request(app)
            .post('/test')
            .send({ email: 'user@example.com' });

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
    });
});
