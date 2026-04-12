const mockAuditLogModel = {
    find: jest.fn(),
    countDocuments: jest.fn(),
    aggregate: jest.fn(),
};

jest.mock('../models/AuditLog', () => mockAuditLogModel);

jest.mock('../utils/logger', () => ({
    error: jest.fn(),
}));

const auditLogController = require('./auditLogController');

describe('auditLogController.getAuditLogs', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    function createResponse() {
        return {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
        };
    }

    it('should apply actor filter when scope is me', async () => {
        const logRows = [{ action: 'INCIDENT_CREATE' }];
        const limitMock = jest.fn().mockResolvedValue(logRows);
        const skipMock = jest.fn(() => ({ limit: limitMock }));
        const sortMock = jest.fn(() => ({ skip: skipMock }));

        mockAuditLogModel.find.mockReturnValue({ sort: sortMock });
        mockAuditLogModel.countDocuments.mockResolvedValue(1);

        const response = createResponse();

        await auditLogController.getAuditLogs({
            user: { userId: 'user-1', role: 'User' },
            query: { scope: 'me', page: '1', limit: '10' },
        }, response, jest.fn());

        expect(mockAuditLogModel.find).toHaveBeenCalledWith(expect.objectContaining({ actorUserId: 'user-1' }));
        expect(response.json).toHaveBeenCalledWith(expect.objectContaining({ success: true, total: 1 }));
    });
});

describe('auditLogController.getAuditLogSummary', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    function createResponse() {
        return {
            json: jest.fn(),
            status: jest.fn().mockReturnThis(),
        };
    }

    it('should return grouped action and entity counts', async () => {
        mockAuditLogModel.aggregate
            .mockResolvedValueOnce([{ _id: 'INCIDENT_CREATE', count: 4 }])
            .mockResolvedValueOnce([{ _id: 'Incident', count: 4 }]);

        const response = createResponse();

        await auditLogController.getAuditLogSummary({
            user: { userId: 'admin-1', role: 'Admin' },
        }, response, jest.fn());

        expect(response.json).toHaveBeenCalledWith({
            success: true,
            actions: [{ _id: 'INCIDENT_CREATE', count: 4 }],
            entities: [{ _id: 'Incident', count: 4 }],
        });
    });
});
