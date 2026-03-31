// NOTE: Data model: defines how records are stored and validated in MongoDB.

const mongoose = require('mongoose');
const { ASSET_TYPES } = require('../utils/constants');

const AssetSchema = new mongoose.Schema({
    assetName: {
        type: String,
        required: true,
        trim: true,
    },
    assetType: {
        type: String,
        enum: ASSET_TYPES,
        required: true,
    },
    description: {
        type: String,
        default: '',
        trim: true,
    },
    location: {
        type: String,
        default: '',
        trim: true,
    },
    status: {
        type: String,
        enum: ['Active', 'Inactive'],
        default: 'Active',
    },
    criticality: {
        type: String,
        enum: ['Low', 'Medium', 'High', 'Critical'],
        default: 'Medium',
    },
    owner: {
        type: String,
        default: '',
        trim: true,
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
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
});

AssetSchema.index({ userId: 1 });
AssetSchema.index({ userId: 1, createdAt: -1 });

AssetSchema.pre(/^find/, function(next) {
    if (!Object.prototype.hasOwnProperty.call(this.getFilter(), 'isDeleted')) {
        this.where({ isDeleted: false });
    }
    next();
});

AssetSchema.pre('countDocuments', function(next) {
    if (!Object.prototype.hasOwnProperty.call(this.getFilter(), 'isDeleted')) {
        this.where({ isDeleted: false });
    }
    next();
});

module.exports = mongoose.model('Asset', AssetSchema);

