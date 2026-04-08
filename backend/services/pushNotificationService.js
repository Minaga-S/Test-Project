const webPush = require('web-push');
const PushSubscription = require('../models/PushSubscription');
const logger = require('../utils/logger');

const fallbackKeys = webPush.generateVAPIDKeys();
const vapidPublicKey = process.env.VAPID_PUBLIC_KEY || fallbackKeys.publicKey;
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY || fallbackKeys.privateKey;
const vapidSubject = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';

webPush.setVapidDetails(vapidSubject, vapidPublicKey, vapidPrivateKey);

function getPublicKey() {
    return vapidPublicKey;
}

function toSubscriptionPayload(subscription, deviceName = 'Browser', userAgent = '') {
    return {
        endpoint: subscription.endpoint,
        expirationTime: subscription.expirationTime || null,
        keys: {
            p256dh: subscription.keys?.p256dh || '',
            auth: subscription.keys?.auth || '',
        },
        deviceName: String(deviceName || 'Browser').trim() || 'Browser',
        userAgent: String(userAgent || '').trim(),
        updatedAt: new Date(),
    };
}

function isExpiredPushError(error) {
    const statusCode = error?.statusCode || error?.status || 0;
    return statusCode === 404 || statusCode === 410;
}

async function saveSubscription(userId, subscription, deviceName = 'Browser', userAgent = '') {
    if (!subscription?.endpoint) {
        throw new Error('Subscription endpoint is required');
    }

    const payload = toSubscriptionPayload(subscription, deviceName, userAgent);
    await PushSubscription.updateOne(
        { userId, endpoint: subscription.endpoint },
        {
            $set: {
                ...payload,
                userId,
            },
            $setOnInsert: {
                createdAt: new Date(),
            },
        },
        { upsert: true }
    );

    return payload;
}

async function removeSubscription(userId, endpoint) {
    if (!endpoint) {
        return;
    }

    await PushSubscription.deleteOne({ userId, endpoint });
}

async function getSubscriptions(userId) {
    return PushSubscription.find({ userId }).sort({ updatedAt: -1 });
}

async function sendToSubscriptions(subscriptions, payload) {
    const payloadText = JSON.stringify(payload);
    const deliveries = await Promise.allSettled(
        subscriptions.map(async (subscription) => {
            const pushSubscription = {
                endpoint: subscription.endpoint,
                expirationTime: subscription.expirationTime || null,
                keys: subscription.keys,
            };

            try {
                await webPush.sendNotification(pushSubscription, payloadText);
                return { endpoint: subscription.endpoint, sent: true };
            } catch (error) {
                if (isExpiredPushError(error)) {
                    await PushSubscription.deleteOne({ _id: subscription._id });
                } else {
                    logger.error(`Push notification error for ${subscription.endpoint}: ${error.message}`);
                }

                return { endpoint: subscription.endpoint, sent: false };
            }
        })
    );

    return deliveries.map((result) => (result.status === 'fulfilled' ? result.value : { sent: false }));
}

async function notifyUser(userId, payload) {
    const subscriptions = await getSubscriptions(userId);
    if (subscriptions.length === 0) {
        return { sent: 0, failed: 0 };
    }

    const results = await sendToSubscriptions(subscriptions, payload);
    const sent = results.filter((result) => result.sent).length;

    return {
        sent,
        failed: results.length - sent,
    };
}

async function notifyIncidentCreated(userId, incident, asset) {
    const title = `${incident.riskLevel || 'Low'} incident reported`;
    const body = `${asset?.assetName || 'An asset'} was reported with ${incident.threatType || 'a security issue'}.`;

    return notifyUser(userId, {
        title,
        body,
        url: '/incident-logs.html',
        tag: `incident-${incident.incidentId || incident._id || Date.now()}`,
        data: {
            incidentId: incident.incidentId || String(incident._id || ''),
            assetId: String(incident.assetId || ''),
        },
    });
}

async function notifyPushTest(userId) {
    return notifyUser(userId, {
        title: 'HCGS browser push test',
        body: 'This notification confirms your browser push subscription is active.',
        url: '/settings.html',
        tag: 'push-test',
    });
}

module.exports = {
    getPublicKey,
    saveSubscription,
    removeSubscription,
    getSubscriptions,
    notifyUser,
    notifyIncidentCreated,
    notifyPushTest,
};
