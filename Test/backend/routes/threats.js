const express = require('express');
const { THREAT_KNOWLEDGE_BASE } = require('../utils/constants');
const { analyzeThreatWithAI } = require('../config/ai-config');

const router = express.Router();

// Analyze threat
router.post('/analyze', async (req, res) => {
    try {
        const { description } = req.body;
        const analysis = await analyzeThreatWithAI(description);
        res.json({ success: true, analysis });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error analyzing threat' });
    }
});

// Get threat knowledge base
router.get('/knowledge-base', (req, res) => {
    res.json({ success: true, knowledgeBase: THREAT_KNOWLEDGE_BASE });
});

// Get threat categories
router.get('/categories', (req, res) => {
    const categories = [...new Set(THREAT_KNOWLEDGE_BASE.map(t => t.threatCategory))];
    res.json({ success: true, categories });
});

module.exports = router;