const mockIncidentModel = {
    find: jest.fn(),
};

jest.mock('../models/Incident', () => mockIncidentModel);

jest.mock('../utils/constants', () => ({
    NIST_FUNCTIONS: ['Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
}));

const mockNistThreatIntelService = {
    getNISTMapping: jest.fn(),
};

jest.mock('../services/nistThreatIntelService', () => mockNistThreatIntelService);

const mockNistMappingService = {
    getAllFunctions: jest.fn(),
    getComplianceReport: jest.fn(),
};

jest.mock('../services/nistMappingService', () => mockNistMappingService);

jest.mock('../services/recommendationService', () => ({
    getThreatIntelRecommendations: jest.fn(),
}));

jest.mock('../utils/logger', () => ({
    error: jest.fn(),
}));

const nistController = require('./nistController');

describe('nistController.getComplianceReport', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    function createResponse() {
        return {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
            setHeader: jest.fn(),
            send: jest.fn(),
        };
    }

    it('should return compliance report JSON payload by default', async () => {
        const incidents = [{ incidentId: 'INC-1', threatType: 'Phishing' }];
        mockIncidentModel.find.mockReturnValue({
            select: jest.fn().mockResolvedValue(incidents),
        });

        mockNistMappingService.getComplianceReport.mockReturnValue({
            functions: { Identify: 1 },
            controls: { 'PR.AC': 1 },
            summary: 'Incidents cover 1/5 NIST functions',
        });

        const response = createResponse();

        await nistController.getComplianceReport({ user: { userId: 'user-1' }, query: {} }, response, jest.fn());

        expect(response.json).toHaveBeenCalledWith(expect.objectContaining({
            success: true,
            incidentCount: 1,
            report: expect.objectContaining({
                summary: 'Incidents cover 1/5 NIST functions',
            }),
        }));
    });

    it('should return CSV content when format is csv', async () => {
        const incidents = [{ incidentId: 'INC-1', threatType: 'Phishing' }];
        mockIncidentModel.find.mockReturnValue({
            select: jest.fn().mockResolvedValue(incidents),
        });

        mockNistMappingService.getComplianceReport.mockReturnValue({
            functions: { Identify: 1 },
            controls: { 'PR.AC': 1 },
            summary: 'Incidents cover 1/5 NIST functions',
        });

        const response = createResponse();

        await nistController.getComplianceReport({ user: { userId: 'user-1' }, query: { format: 'csv' } }, response, jest.fn());

        expect(response.setHeader).toHaveBeenCalledWith('Content-Type', 'text/csv; charset=utf-8');
        expect(response.send).toHaveBeenCalledWith(expect.stringContaining('Section,Key,Value'));
    });
});
