const mockSendNotification = jest.fn();
const mockGenerateVapidKeys = jest.fn(() => ({ publicKey: 'public-key', privateKey: 'private-key' }));

jest.mock('web-push', () => ({
    generateVAPIDKeys: mockGenerateVapidKeys,
    setVapidDetails: jest.fn(),
    sendNotification: mockSendNotification,
}));

const mockPushSubscriptionModel = {
    find: jest.fn(),
    updateOne: jest.fn(),
    deleteOne: jest.fn(),
};

jest.mock('../models/PushSubscription', () => mockPushSubscriptionModel);

jest.mock('../utils/logger', () => ({
    error: jest.fn(),
}));

const pushNotificationService = require('./pushNotificationService');

describe('pushNotificationService', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should return the configured public key', () => {
        expect(pushNotificationService.getPublicKey()).toBe('public-key');
    });

    it('should save a push subscription for the user', async () => {
        mockPushSubscriptionModel.updateOne.mockResolvedValue({ acknowledged: true });

        await pushNotificationService.saveSubscription(
            'user-1',
            {
                endpoint: 'https://example.com/push/1',
                keys: { p256dh: 'key-1', auth: 'auth-1' },
            },
            'Browser',
            'Example User Agent'
        );

        expect(mockPushSubscriptionModel.updateOne).toHaveBeenCalledWith(
            { userId: 'user-1', endpoint: 'https://example.com/push/1' },
            expect.any(Object),
            { upsert: true }
        );
    });

    it('should remove expired subscriptions when push delivery returns 410', async () => {
        mockPushSubscriptionModel.find.mockReturnValue({
            sort: jest.fn().mockResolvedValue([
                { _id: 'sub-1', endpoint: 'https://example.com/push/1', keys: { p256dh: 'key', auth: 'auth' } },
            ]),
        });
        mockSendNotification.mockRejectedValue(Object.assign(new Error('expired'), { statusCode: 410 }));
        mockPushSubscriptionModel.deleteOne.mockResolvedValue({ acknowledged: true });

        await pushNotificationService.notifyPushTest('user-1');

        expect(mockPushSubscriptionModel.deleteOne).toHaveBeenCalledWith({ _id: 'sub-1' });
    });
});