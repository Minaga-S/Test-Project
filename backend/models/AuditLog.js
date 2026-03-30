const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
    actorUserId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    },
    action: {
        type: String,
        required: true,
        trim: true,
    },
    entityType: {
        type: String,
        required: true,
        trim: true,
    },
    entityId: {
        type: String,
        trim: true,
    },
    before: {
        type: Object,
        default: null,
    },
    after: {
        type: Object,
        default: null,
    },
    meta: {
        type: Object,
        default: {},
    },
    ipAddress: {
        type: String,
        default: '',
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

AuditLogSchema.index({ actorUserId: 1, createdAt: -1 });
AuditLogSchema.index({ entityType: 1, entityId: 1, createdAt: -1 });

module.exports = mongoose.model('AuditLog', AuditLogSchema);
