const express = require('express');
const { NIST_FUNCTIONS, NIST_CONTROLS, THREAT_KNOWLEDGE_BASE } = require('../utils/constants');
const Incident = require('../models/Incident');

const router = express.Router();

// Get NIST functions
router.get('/functions', (req, res) => {
    res.json({ success: true, functions: NIST_FUNCTIONS });
});

// Get NIST controls for threat type
router.get('/controls/:threatType', (req, res) => {
    try {
        const threat = THREAT_KNOWLEDGE_BASE.find(t => t.threatType === req.params.threatType);
        const controls = threat ? threat.nistControls : [];
        res.json({ success: true, controls });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching controls' });
    }
});

// Get NIST mapping for incident
router.get('/mapping/:incidentId', async (req, res) => {
    try {
        const incident = await Incident.findOne({ _id: req.params.incidentId, userId: req.user.userId });
        if (!incident) {
            return res.status(404).json({ success: false, message: 'Incident not found' });
        }

        res.json({
            success: true,
            mapping: {
                functions: incident.nistFunctions,
                controls: incident.nistControls,
            },
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching mapping' });
    }
});

// Get recommendations for threat
router.get('/recommendations/:threatType', (req, res) => {
    try {
        const threat = THREAT_KNOWLEDGE_BASE.find(t => t.threatType === req.params.threatType);
        const recommendations = threat ? threat.mitigationSteps : [];
        res.json({ success: true, recommendations });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching recommendations' });
    }
});

module.exports = router;