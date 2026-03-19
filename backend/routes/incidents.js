const express = require('express');
const Incident = require('../models/Incident');
const Asset = require('../models/Asset');
const { generateIncidentId, calculateRiskLevel } = require('../utils/constants');
const { analyzeThreatWithAI, generateRecommendations } = require('../config/ai-config');
const logger = require('../utils/logger');

const router = express.Router();

// Create incident
router.post('/', async (req, res) => {
    try {
        const { assetId, description } = req.body;

        const asset = await Asset.findOne({ _id: assetId, userId: req.user.userId });
        if (!asset) {
            return res.status(404).json({ success: false, message: 'Asset not found' });
        }

        // Analyze threat with AI
        const analysis = await analyzeThreatWithAI(description);

        // Calculate risk
        const { level, score } = calculateRiskLevel(analysis.likelihood, analysis.impact);

        // Generate recommendations
        const recommendations = await generateRecommendations(analysis.threatType, analysis);

        const incident = new Incident({
            incidentId: generateIncidentId(),
            description,
            assetId,
            asset: asset.toObject(),
            threatType: analysis.threatType,
            threatCategory: analysis.threatCategory,
            confidence: analysis.confidence,
            likelihood: analysis.likelihood,
            impact: analysis.impact,
            riskScore: score,
            riskLevel: level,
            nistFunctions: analysis.nistFunctions || [],
            nistControls: analysis.nistControls || [],
            recommendations,
            userId: req.user.userId,
            guestAffected: req.body.guestAffected,
            sensitiveDataInvolved: req.body.sensitiveDataInvolved,
        });

        await incident.save();

        res.status(201).json({ success: true, incident });

    } catch (error) {
        logger.error('Create incident error:', error.message);
        res.status(500).json({ success: false, message: 'Error creating incident' });
    }
});

// Get all incidents
router.get('/', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId }).sort({ createdAt: -1 });
        res.json({ success: true, incidents });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching incidents' });
    }
});

// Get incident by ID
router.get('/:id', async (req, res) => {
    try {
        const incident = await Incident.findOne({ _id: req.params.id, userId: req.user.userId });
        if (!incident) {
            return res.status(404).json({ success: false, message: 'Incident not found' });
        }
        res.json({ success: true, incident });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching incident' });
    }
});

// Update incident status
router.put('/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const updateData = { status, updatedAt: new Date() };

        if (status === 'Resolved') {
            updateData.resolvedAt = new Date();
            updateData.resolvedBy = req.user.userId;
        }

        const incident = await Incident.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.userId },
            updateData,
            { new: true }
        );

        if (!incident) {
            return res.status(404).json({ success: false, message: 'Incident not found' });
        }

        res.json({ success: true, incident });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating incident' });
    }
});

// Add note to incident
router.post('/:id/notes', async (req, res) => {
    try {
        const { note } = req.body;
        const incident = await Incident.findOne({ _id: req.params.id, userId: req.user.userId });

        if (!incident) {
            return res.status(404).json({ success: false, message: 'Incident not found' });
        }

        incident.notes.push(note);
        incident.updatedAt = new Date();
        await incident.save();

        res.json({ success: true, incident });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error adding note' });
    }
});

module.exports = router;