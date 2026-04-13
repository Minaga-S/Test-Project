jest.mock('../models/Asset', () => ({
    countDocuments: jest.fn(),
}));

jest.mock('../models/Incident', () => ({
    countDocuments: jest.fn(),
}));

jest.mock('../utils/logger', () => ({
    error: jest.fn(),
    info: jest.fn(),
}));

const Asset = require('../models/Asset');
const Incident = require('../models/Incident');
const dashboardController = require('./dashboardController');

function createResponse() {
    return {
        json: jest.fn(),
        status: jest.fn().mockReturnThis(),
    };
}

describe('dashboardController critical risk metrics', () => {
    beforeEach(() => {
        jest.clearAllMocks();

        Asset.countDocuments.mockImplementation((query = {}) => {
            if (query.createdAt) {
                return Promise.resolve(8);
            }

            return Promise.resolve(10);
        });

        Incident.countDocuments.mockImplementation((query = {}) => {
            if (query.riskLevel === 'Critical') {
                return Promise.resolve(query.status?.$ne === 'Resolved' ? 0 : 1);
            }

            if (query.status === 'Open') {
                return Promise.resolve(query.createdAt ? 2 : 3);
            }

            if (query.status === 'Resolved') {
                return Promise.resolve(query.resolvedAt ? 1 : 1);
            }

            return Promise.resolve(0);
        });
    });

    it('should exclude resolved critical incidents from dashboard metrics', async () => {
        const response = createResponse();

        await dashboardController.getMetrics({ user: { userId: 'user-1' } }, response, jest.fn());

        expect(response.json.mock.calls[0][0].metrics.criticalRisks).toBe(0);
    });

    it('should exclude resolved critical incidents from dashboard overview', async () => {
        const response = createResponse();

        await dashboardController.getOverview({ user: { userId: 'user-1' } }, response, jest.fn());

        expect(response.json.mock.calls[0][0].overview.criticalRisks).toBe(0);
    });
});