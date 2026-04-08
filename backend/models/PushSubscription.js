const mongoose = require('mongoose');

const PushSubscriptionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    endpoint: {
        type: String,
        required: true,
        trim: true,
    },
    expirationTime: {
        type: Date,
        default: null,
    },
    keys: {
        p256dh: {
            type: String,
            required: true,
            trim: true,
        },
        auth: {
            type: String,
            required: true,
            trim: true,
        },
    },
    deviceName: {
        type: String,
        default: 'Browser',
        trim: true,
    },
    userAgent: {
        type: String,
        default: '',
        trim: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
});

PushSubscriptionSchema.index({ userId: 1, endpoint: 1 }, { unique: true });
PushSubscriptionSchema.index({ userId: 1, updatedAt: -1 });

module.exports = mongoose.model('PushSubscription', PushSubscriptionSchema);
