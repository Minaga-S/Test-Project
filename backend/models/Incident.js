const mongoose = require('mongoose');
const { INCIDENT_STATUS } = require('../utils/constants');

const IncidentSchema = new mongoose.Schema({
    incidentId: {
        type: String,
        unique: true,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    assetId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Asset',
        required: true,
    },
    asset: {
        type: Object,
    },
    threatType: String,
    threatCategory: String,
    confidence: Number,
    likelihood: {
        type: Number,
        min: 1,
        max: 4,
    },
    impact: {
        type: Number,
        min: 1,
        max: 4,
    },
    riskScore: Number,
    riskLevel: {
        type: String,
        enum: ['Low', 'Medium', 'High', 'Critical'],
    },
    status: {
        type: String,
        enum: INCIDENT_STATUS,
        default: 'Open',
    },
    nistFunctions: [String],
    nistControls: [String],
    recommendations: [String],
    notes: [String],
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    guestAffected: Boolean,
    sensitiveDataInvolved: Boolean,
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
    resolvedAt: Date,
    resolvedBy: mongoose.Schema.Types.ObjectId,
});

module.exports = mongoose.model('Incident', IncidentSchema);