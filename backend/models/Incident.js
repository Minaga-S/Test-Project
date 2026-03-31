// NOTE: Data model: defines how records are stored and validated in MongoDB.

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
        minlength: 20,
        trim: true,
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
    incidentTime: {
        type: Date,
        default: null,
    },
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
    aiModel: {
        type: String,
        default: '',
    },
    aiVersion: {
        type: String,
        default: '',
    },
    aiAnalyzedAt: {
        type: Date,
        default: null,
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
    isDeleted: {
        type: Boolean,
        default: false,
    },
    deletedAt: {
        type: Date,
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
    resolvedAt: Date,
    resolvedBy: mongoose.Schema.Types.ObjectId,
});

IncidentSchema.index({ incidentId: 1 }, { unique: true });
IncidentSchema.index({ userId: 1 });
IncidentSchema.index({ assetId: 1 });
IncidentSchema.index({ createdAt: -1 });
IncidentSchema.index({ riskLevel: 1 });
IncidentSchema.index({ userId: 1, status: 1, createdAt: -1 });

IncidentSchema.pre(/^find/, function(next) {
    if (!Object.prototype.hasOwnProperty.call(this.getFilter(), 'isDeleted')) {
        this.where({ isDeleted: false });
    }
    next();
});

IncidentSchema.pre('countDocuments', function(next) {
    if (!Object.prototype.hasOwnProperty.call(this.getFilter(), 'isDeleted')) {
        this.where({ isDeleted: false });
    }
    next();
});

module.exports = mongoose.model('Incident', IncidentSchema);


