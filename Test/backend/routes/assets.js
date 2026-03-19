const express = require('express');
const Asset = require('../models/Asset');
const { validateAsset } = require('../utils/validators');
const logger = require('../utils/logger');

const router = express.Router();

// Create asset
router.post('/', async (req, res) => {
    try {
        const validation = validateAsset(req.body);
        if (!validation.isValid) {
            return res.status(400).json({ success: false, errors: validation.errors });
        }

        const asset = new Asset({
            ...req.body,
            userId: req.user.userId,
        });
        await asset.save();

        res.status(201).json({ success: true, asset });
    } catch (error) {
        logger.error('Create asset error:', error.message);
        res.status(500).json({ success: false, message: 'Error creating asset' });
    }
});

// Get all assets
router.get('/', async (req, res) => {
    try {
        const assets = await Asset.find({ userId: req.user.userId });
        res.json({ success: true, assets });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching assets' });
    }
});

// Get asset by ID
router.get('/:id', async (req, res) => {
    try {
        const asset = await Asset.findOne({ _id: req.params.id, userId: req.user.userId });
        if (!asset) {
            return res.status(404).json({ success: false, message: 'Asset not found' });
        }
        res.json({ success: true, asset });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching asset' });
    }
});

// Update asset
router.put('/:id', async (req, res) => {
    try {
        const asset = await Asset.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.userId },
            { ...req.body, updatedAt: new Date() },
            { new: true }
        );
        if (!asset) {
            return res.status(404).json({ success: false, message: 'Asset not found' });
        }
        res.json({ success: true, asset });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating asset' });
    }
});

// Delete asset
router.delete('/:id', async (req, res) => {
    try {
        const asset = await Asset.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
        if (!asset) {
            return res.status(404).json({ success: false, message: 'Asset not found' });
        }
        res.json({ success: true, message: 'Asset deleted' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error deleting asset' });
    }
});

// Search assets
router.get('/search', async (req, res) => {
    try {
        const query = req.query.query || '';
        const assets = await Asset.find({
            userId: req.user.userId,
            $or: [
                { assetName: { $regex: query, $options: 'i' } },
                { description: { $regex: query, $options: 'i' } },
            ],
        });
        res.json({ success: true, assets });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error searching assets' });
    }
});

module.exports = router;