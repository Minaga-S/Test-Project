const pushNotificationService = require('../services/pushNotificationService');
const logger = require('../utils/logger');

class PushNotificationController {
    async getPublicKey(req, res, next) {
        try {
            res.json({
                success: true,
                publicKey: pushNotificationService.getPublicKey(),
            });
        } catch (error) {
            logger.error(`Get push public key error: ${error.message}`);
            next(error);
        }
    }

    async subscribe(req, res, next) {
        try {
            const subscription = req.body.subscription || {};
            const deviceName = req.body.deviceName || 'Browser';
            const savedSubscription = await pushNotificationService.saveSubscription(
                req.user.userId,
                subscription,
                deviceName,
                req.headers['user-agent'] || ''
            );

            res.status(201).json({
                success: true,
                message: 'Push notifications enabled',
                subscription: savedSubscription,
            });
        } catch (error) {
            logger.error(`Subscribe push error: ${error.message}`);
            next(error);
        }
    }

    async unsubscribe(req, res, next) {
        try {
            const endpoint = String(req.body.endpoint || '').trim();
            await pushNotificationService.removeSubscription(req.user.userId, endpoint);

            res.json({
                success: true,
                message: 'Push notifications disabled',
            });
        } catch (error) {
            logger.error(`Unsubscribe push error: ${error.message}`);
            next(error);
        }
    }

    async testNotification(req, res, next) {
        try {
            const result = await pushNotificationService.notifyPushTest(req.user.userId);

            res.json({
                success: true,
                message: result.sent > 0 ? 'Test notification sent' : 'No active push subscriptions found',
                result,
            });
        } catch (error) {
            logger.error(`Push test error: ${error.message}`);
            next(error);
        }
    }
}

module.exports = new PushNotificationController();
