// NOTE: Data model: stores persisted scan jobs and their derived security context.

const mongoose = require('mongoose');

const ScanHistorySchema = new mongoose.Schema({
    assetId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Asset',
        required: true,
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    assetSnapshot: {
        type: Object,
        default: {},
    },
    status: {
        type: String,
        enum: ['Pending', 'Completed', 'Failed', 'Skipped'],
        default: 'Pending',
    },
    target: {
        type: String,
        default: '',
        trim: true,
    },
    ports: {
        type: String,
        default: '',
        trim: true,
    },
    command: {
        type: String,
        default: '',
        trim: true,
    },
    startedAt: {
        type: Date,
        default: Date.now,
    },
    completedAt: {
        type: Date,
        default: null,
    },
    scanDurationMs: {
        type: Number,
        default: 0,
    },
    nmapResult: {
        type: Object,
        default: {},
    },
    cveResult: {
        type: Object,
        default: {},
    },
    securityContext: {
        type: Object,
        default: {},
    },
    errorMessage: {
        type: String,
        default: '',
        trim: true,
    },
    initiatedBy: {
        type: String,
        default: 'system',
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

ScanHistorySchema.index({ userId: 1, assetId: 1, createdAt: -1 });
ScanHistorySchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('ScanHistory', ScanHistorySchema);