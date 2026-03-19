const mongoose = require('mongoose');
const { ASSET_TYPES } = require('../utils/constants');

const AssetSchema = new mongoose.Schema({
    assetName: {
        type: String,
        required: true,
    },
    assetType: {
        type: String,
        enum: ASSET_TYPES,
        required: true,
    },
    description: String,
    location: String,
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
    owner: String,
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
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

module.exports = mongoose.model('Asset', AssetSchema);