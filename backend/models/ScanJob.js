// NOTE: Data model: stores agent scan jobs queued for local execution.

const mongoose = require('mongoose');

const ScanJobSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    assetId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Asset',
    },
    status: {
        type: String,
        enum: ['Pending', 'Running', 'Completed', 'Failed'],
        default: 'Pending',
    },
    target: {
        type: String,
        required: true,
        trim: true,
    },
    ports: {
        type: String,
        default: '1-65535',
        trim: true,
    },
    frequency: {
        type: String,
        enum: ['Once', 'Daily', 'Weekly'],
        default: 'Once',
    },
    agentId: {
        type: String,
        default: null,
        trim: true,
    },
    scanStartedAt: {
        type: Date,
        default: null,
    },
    scanCompletedAt: {
        type: Date,
        default: null,
    },
    nmapResult: {
        type: Object,
        default: null,
    },
    cveResult: {
        type: Object,
        default: null,
    },
    error: {
        type: String,
        default: null,
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

ScanJobSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('ScanJob', ScanJobSchema);
