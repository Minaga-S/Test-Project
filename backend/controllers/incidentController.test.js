process.env.GEMINI_MODEL = 'gemini-2.5-flash';
process.env.GEMINI_MODEL_VERSION = 'v1beta';

const mockIncidentModel = jest.fn().mockImplementation((incidentData) => ({
    ...incidentData,
    _id: 'incident-db-id',
    save: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../models/Incident', () => mockIncidentModel);

const mockAssetModel = {
    findOne: jest.fn(),
};

jest.mock('../models/Asset', () => mockAssetModel);

jest.mock('../services/threatClassificationService', () => ({
    classifyThreat: jest.fn(),
}));

jest.mock('../services/riskCalculationService', () => ({
    calculateRisk: jest.fn(),
}));

jest.mock('../services/recommendationService', () => ({
    generateRecommendations: jest.fn(),
}));

jest.mock('../services/nistMappingService', () => ({
    getNISTMapping: jest.fn(),
}));

jest.mock('../services/assetSecurityContextService', () => ({
    buildForAsset: jest.fn(),
}));

jest.mock('../services/scanHistoryService', () => ({
    getLatestScanHistory: jest.fn(),
}));

jest.mock('../services/auditLogService', () => ({
    record: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../services/pushNotificationService', () => ({
    notifyIncidentCreated: jest.fn().mockResolvedValue({ sent: 1, failed: 0 }),
    notifyPushTest: jest.fn(),
}));

jest.mock('../utils/validators', () => ({
    validateIncident: jest.fn(),
}));

jest.mock('../utils/constants', () => ({
    generateIncidentId: jest.fn(() => 'INC-12345'),
}));

jest.mock('../utils/logger', () => ({
    info: jest.fn(),
    error: jest.fn(),
}));

const threatService = require('../services/threatClassificationService');
const riskService = require('../services/riskCalculationService');
const recommendationService = require('../services/recommendationService');
const nistService = require('../services/nistMappingService');
const assetSecurityContextService = require('../services/assetSecurityContextService');
const scanHistoryService = require('../services/scanHistoryService');
const pushNotificationService = require('../services/pushNotificationService');
const { validateIncident } = require('../utils/validators');
const incidentController = require('./incidentController');

describe('incidentController.createIncident', () => {
    beforeEach(() => {
        jest.clearAllMocks();

        validateIncident.mockReturnValue({ isValid: true, errors: [] });
        mockAssetModel.findOne.mockResolvedValue({ _id: 'asset-id', assetName: 'Asset A', assetType: 'Server', location: 'HQ' });
        scanHistoryService.getLatestScanHistory.mockResolvedValue(null);
        threatService.classifyThreat.mockResolvedValue({
            threatType: 'Malware',
            threatCategory: 'Security',
            confidence: 90,
            likelihood: 'High',
            impact: 'High',
        });
        riskService.calculateRisk.mockReturnValue({ score: 90, level: 'Critical' });
        nistService.getNISTMapping.mockReturnValue({ functions: ['Detect'], controls: ['DE.CM-1'] });
        recommendationService.generateRecommendations.mockResolvedValue(['Isolate host']);
    });

    function createRequest(clientSecurityContext) {
        return {
            body: {
                assetId: 'asset-id',
                description: 'A detailed incident description with enough length.',
                incidentTime: '2025-01-01T10:00:00.000Z',
                guestAffected: false,
                paymentsAffected: false,
                sensitiveDataInvolved: false,
                clientSecurityContext,
            },
            user: { userId: 'user-1' },
            ip: '127.0.0.1',
        };
    }

    function createResponse() {
        return {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };
    }

    it('should populate incident cveMatches from clientSecurityContext when persisted matches are empty', async () => {
        assetSecurityContextService.buildForAsset.mockReturnValue({
            cve: { matches: [] },
            dataSources: { cve: 'NIST Pending' },
            enrichment: {},
        });

        const clientSecurityContext = {
            cve: {
                matches: [{ cveId: 'CVE-2024-0001', severity: 'HIGH' }],
            },
            enrichment: {
                source: 'NIST NVD API',
                confidence: 'High',
            },
        };

        const response = createResponse();

        await incidentController.createIncident(createRequest(clientSecurityContext), response, jest.fn());

        expect(response.json.mock.calls[0][0].incident.cveMatches).toEqual(clientSecurityContext.cve.matches);
    });

    it('should keep persisted cveMatches when scan-history context already has matches', async () => {
        const persistedMatches = [{ cveId: 'CVE-2023-1111', severity: 'MEDIUM' }];
        assetSecurityContextService.buildForAsset.mockReturnValue({
            cve: { matches: persistedMatches },
            dataSources: { cve: 'NIST Enriched' },
            enrichment: {},
        });

        const clientSecurityContext = {
            cve: {
                matches: [{ cveId: 'CVE-2024-9999', severity: 'CRITICAL' }],
            },
        };

        const response = createResponse();

        await incidentController.createIncident(createRequest(clientSecurityContext), response, jest.fn());

        expect(response.json.mock.calls[0][0].incident.cveMatches).toEqual(persistedMatches);
    });

    it('should keep client-reported open ports when persisted security context has none', async () => {
        assetSecurityContextService.buildForAsset.mockReturnValue({
            cve: { matches: [] },
            liveScan: { observedOpenPorts: [] },
            dataSources: { scan: 'Live scan pending', cve: 'NIST Pending' },
            enrichment: {},
        });

        const clientSecurityContext = {
            liveScan: {
                target: '192.168.204.128',
                observedOpenPorts: [21, 22, 23, 80],
            },
        };

        const response = createResponse();

        await incidentController.createIncident(createRequest(clientSecurityContext), response, jest.fn());

        expect(response.json.mock.calls[0][0].incident.securityContext.liveScan.observedOpenPorts).toEqual([21, 22, 23, 80]);
    });

    it('should send a browser push notification when an incident is created', async () => {
        const response = createResponse();

        await incidentController.createIncident(createRequest(), response, jest.fn());

        expect(pushNotificationService.notifyIncidentCreated).toHaveBeenCalledWith('user-1', expect.any(Object), expect.any(Object));
    });
});
