const express = require('express');
const Incident = require('../models/Incident');
const { calculateRiskLevel } = require('../utils/constants');

const router = express.Router();

// Calculate risk
router.post('/calculate', (req, res) => {
    try {
        const { likelihood, impact } = req.body;
        const result = calculateRiskLevel(likelihood, impact);
        res.json({ success: true, risk: result });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error calculating risk' });
    }
});

// Get risk matrix
router.get('/matrix', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId });

        const points = incidents.map(inc => ({
            x: inc.likelihood,
            y: inc.impact,
            r: 15,
            label: inc.incidentId,
        }));

        res.json({ success: true, points });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error generating risk matrix' });
    }
});

// Get risk trends
router.get('/trends', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId }).sort({ createdAt: 1 });

        const trends = incidents.map(inc => ({
            date: inc.createdAt,
            score: inc.riskScore,
        }));

        const labels = trends.map(t => new Date(t.date).toLocaleDateString());
        const data = trends.map(t => t.score);

        res.json({ success: true, labels, data });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching risk trends' });
    }
});

// Get risk by asset
router.get('/by-asset', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId });

        const assetRisks = {};
        incidents.forEach(inc => {
            const assetName = inc.asset?.assetName || 'Unknown';
            if (!assetRisks[assetName]) {
                assetRisks[assetName] = { assetName, riskLevel: 'Low', incidents: 0 };
            }
            assetRisks[assetName].incidents++;
            assetRisks[assetName].riskLevel = inc.riskLevel;
        });

        const result = Object.values(assetRisks);
        res.json({ success: true, assetRisks: result });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching asset risks' });
    }
});

module.exports = router;