const express = require('express');
const { body } = require('express-validator');
const pushNotificationController = require('../controllers/pushNotificationController');
const { validateRequest } = require('../middleware/validateRequest');

const router = express.Router();

const withController = (controller, methodName) => (req, res, next) => controller[methodName](req, res, next);

const subscriptionValidation = [
    body('subscription.endpoint').isString().trim().notEmpty().withMessage('Subscription endpoint is required'),
    body('subscription.keys.p256dh').isString().trim().notEmpty().withMessage('Subscription key is required'),
    body('subscription.keys.auth').isString().trim().notEmpty().withMessage('Subscription auth secret is required'),
    body('deviceName').optional().isString().trim(),
    validateRequest,
];

const unsubscribeValidation = [
    body('endpoint').isString().trim().notEmpty().withMessage('Subscription endpoint is required'),
    validateRequest,
];

router.get('/public-key', withController(pushNotificationController, 'getPublicKey'));
router.post('/subscriptions', subscriptionValidation, withController(pushNotificationController, 'subscribe'));
router.delete('/subscriptions', unsubscribeValidation, withController(pushNotificationController, 'unsubscribe'));
router.post('/test', withController(pushNotificationController, 'testNotification'));

module.exports = router;
