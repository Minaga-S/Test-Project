const express = require('express');
const Incident = require('../models/Incident');
const Asset = require('../models/Asset');

const router = express.Router();

// Get dashboard metrics
router.get('/metrics', async (req, res) => {
    try {
        const totalAssets = await Asset.countDocuments({ userId: req.user.userId });
        const openIncidents = await Incident.countDocuments({ userId: req.user.userId, status: 'Open' });
        const criticalRisks = await Incident.countDocuments({ userId: req.user.userId, riskLevel: 'Critical' });
        const resolvedIssues = await Incident.countDocuments({ userId: req.user.userId, status: 'Resolved' });

        res.json({
            success: true,
            metrics: {
                totalAssets,
                openIncidents,
                criticalRisks,
                resolvedIssues,
            },
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching metrics' });
    }
});

// Risk distribution chart
router.get('/charts/risk-distribution', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId });

        const distribution = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
        };

        incidents.forEach(inc => {
            distribution[inc.riskLevel]++;
        });

        res.json({
            success: true,
            labels: Object.keys(distribution),
            data: Object.values(distribution),
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching chart data' });
    }
});

// Threat categories chart
router.get('/charts/threat-categories', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId });

        const threatCounts = {};
        incidents.forEach(inc => {
            threatCounts[inc.threatType] = (threatCounts[inc.threatType] || 0) + 1;
        });

        res.json({
            success: true,
            labels: Object.keys(threatCounts),
            data: Object.values(threatCounts),
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching chart data' });
    }
});

// Vulnerable assets chart
router.get('/charts/vulnerable-assets', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId });

        const assetVulnerability = {};
        incidents.forEach(inc => {
            const assetName = inc.asset?.assetName || 'Unknown';
            assetVulnerability[assetName] = (assetVulnerability[assetName] || 0) + 1;
        });

        res.json({
            success: true,
            labels: Object.keys(assetVulnerability),
            data: Object.values(assetVulnerability),
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching chart data' });
    }
});

// Recent incidents
router.get('/recent-incidents', async (req, res) => {
    try {
        const incidents = await Incident.find({ userId: req.user.userId })
            .sort({ createdAt: -1 })
            .limit(5);

        res.json({ success: true, incidents });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching incidents' });
    }
});

module.exports = router;