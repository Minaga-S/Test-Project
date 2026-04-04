jest.mock('../models/User', () => {
    const mockUser = jest.fn().mockImplementation((userData) => ({
        ...userData,
        save: jest.fn().mockResolvedValue(undefined),
    }));

    mockUser.countDocuments = jest.fn();
    return mockUser;
});

jest.mock('../models/ThreatKnowledgeBase', () => ({
    findOneAndUpdate: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../utils/constants', () => ({
    THREAT_KNOWLEDGE_BASE: [
        {
            threatType: 'Phishing',
        },
    ],
}));

const User = require('../models/User');
const { seedDatabase } = require('./seedDatabase');

describe('seedDatabase', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        User.countDocuments.mockResolvedValue(0);
    });

    it('should seed a single admin test account', async () => {
        await seedDatabase();

        expect(User.mock.calls).toEqual([
            [{
                email: 'admin@test.com',
                password: 'Admin123456',
                fullName: 'Admin User',
                role: 'Admin',
                department: 'Management',
            }],
        ]);
    });
});
