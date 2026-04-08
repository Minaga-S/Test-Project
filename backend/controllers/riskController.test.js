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

describe('riskController.getRiskByAsset', () => {
    function createResponse() {
        return {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
        };
    }

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should include assets without incidents in the risk summary', async () => {
        mockAssetModel.find.mockResolvedValue([
            {
                _id: 'asset-1',
                assetName: 'Core Server',
                assetType: 'Server',
                criticality: 'High',
                vulnerabilityProfile: { osName: 'Linux' },
            },
        ]);
        mockIncidentModel.find.mockResolvedValue([]);

        const response = createResponse();

        await riskController.getRiskByAsset({ user: { userId: 'user-1' } }, response, jest.fn());

        expect(response.json.mock.calls[0][0].assetRisks).toEqual([
            expect.objectContaining({
                assetId: 'asset-1',
                assetName: 'Core Server',
                riskLevel: 'High',
                incidents: [],
            }),
        ]);
    });

    it('should raise the displayed risk when an incident is higher than the asset baseline', async () => {
        mockAssetModel.find.mockResolvedValue([
            {
                _id: 'asset-1',
                assetName: 'Workstation',
                assetType: 'Device',
                criticality: 'Low',
                vulnerabilityProfile: {},
            },
        ]);
        mockIncidentModel.find.mockResolvedValue([
            {
                assetId: 'asset-1',
                incidentId: 'INC-1',
                riskScore: 16,
                riskLevel: 'Critical',
                threatType: 'Ransomware',
            },
        ]);

        const response = createResponse();

        await riskController.getRiskByAsset({ user: { userId: 'user-1' } }, response, jest.fn());

        expect(response.json.mock.calls[0][0].assetRisks[0]).toEqual(expect.objectContaining({
            assetId: 'asset-1',
            riskLevel: 'Critical',
            maxRiskScore: 16,
        }));
    });
});
