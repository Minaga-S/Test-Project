const mockAssetModel = {
    find: jest.fn(),
};

jest.mock('../models/Asset', () => mockAssetModel);

const mockIncidentModel = {
    find: jest.fn(),
};

jest.mock('../models/Incident', () => mockIncidentModel);

jest.mock('../models/RiskAssessment', () => ({
    create: jest.fn(),
    findOneAndUpdate: jest.fn(),
}));

jest.mock('../services/riskCalculationService', () => ({
    calculateRisk: jest.fn(),
    getRiskRecommendation: jest.fn(),
}));

jest.mock('../utils/logger', () => ({
    error: jest.fn(),
}));

const riskController = require('./riskController');

describe('riskController.getRiskForecast', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    function createResponse() {
        return {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
        };
    }

    it('should return empty forecast arrays when no history exists', async () => {
        mockIncidentModel.find.mockReturnValue({
            select: jest.fn(() => ({ sort: jest.fn().mockResolvedValue([]) })),
        });

        const response = createResponse();

        await riskController.getRiskForecast({ user: { userId: 'user-1' } }, response, jest.fn());

        expect(response.json).toHaveBeenCalledWith({
            success: true,
            forecast: {
                historyLabels: [],
                historyScores: [],
                forecastLabels: [],
                forecastScores: [],
                windowSize: 3,
            },
        });
    });

    it('should return 7-point moving average forecast when history exists', async () => {
        const incidents = [
            { createdAt: '2026-04-08T10:00:00.000Z', riskScore: 8 },
            { createdAt: '2026-04-09T10:00:00.000Z', riskScore: 10 },
            { createdAt: '2026-04-10T10:00:00.000Z', riskScore: 12 },
        ];

        mockIncidentModel.find.mockReturnValue({
            select: jest.fn(() => ({ sort: jest.fn().mockResolvedValue(incidents) })),
        });

        const response = createResponse();

        await riskController.getRiskForecast({ user: { userId: 'user-1' } }, response, jest.fn());

        const payload = response.json.mock.calls[0][0];
        expect(payload.success).toBe(true);
        expect(payload.forecast.historyLabels).toHaveLength(3);
        expect(payload.forecast.forecastScores).toHaveLength(7);
    });
});
