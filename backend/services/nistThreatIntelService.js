/**
 * NIST Threat Intelligence Service
 * 
 * Fetches threat intelligence from NIST CVE API and external threat databases.
 * Maps CVEs to threat types and provides threat context for AI analysis.
 * 
 * NOTE: Service layer: contains core business logic for threat intelligence.
 */

const axios = require('axios');
const logger = require('../utils/logger');
const nistCveService = require('./nistCveService');

const NIST_CVE_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CVE_MITIGATIONS_CACHE = new Map();
const THREAT_CACHE = new Map();
const CACHE_TTL_MS = Number(process.env.THREAT_INTEL_CACHE_TTL_MS || 3600000); // 1 hour

/**
 * Threat type patterns - map CVE characteristics to threat types
 */
const THREAT_PATTERNS = {
    'Malware': {
        patterns: ['worm', 'trojan', 'bot', 'backdoor', 'rootkit', 'spyware'],
        keywords: ['execute arbitrary code', 'remote code execution', 'injection'],
        severity: ['HIGH', 'CRITICAL'],
    },
    'Ransomware': {
        patterns: ['ransomware', 'crypto', 'encryption'],
        keywords: ['encrypt', 'lock', 'ransom', 'payment', 'restore'],
        severity: ['HIGH', 'CRITICAL'],
    },
    'Data Breach': {
        patterns: ['disclosure', 'leak', 'exposure', 'information'],
        keywords: ['sensitive data', 'user information', 'credential', 'exposure'],
        severity: ['MEDIUM', 'HIGH', 'CRITICAL'],
    },
    'DDoS': {
        patterns: ['denial', 'dos', 'ddos', 'flood'],
        keywords: ['resource exhaustion', 'availability', 'bypass'],
        severity: ['MEDIUM', 'HIGH', 'CRITICAL'],
    },
    'Unauthorized Access': {
        patterns: ['authentication', 'authorization', 'bypass', 'escalation'],
        keywords: ['privilege escalation', 'authentication bypass', 'access control'],
        severity: ['MEDIUM', 'HIGH', 'CRITICAL'],
    },
    'Phishing': {
        patterns: ['phishing', 'social engineering', 'credential theft'],
        keywords: ['user interaction', 'malicious link', 'attachment'],
        severity: ['LOW', 'MEDIUM', 'HIGH'],
    },
};

/**
 * NIST CSF Function mapping - map threat types to appropriate NIST functions
 */
const THREAT_TO_NIST = {
    'Malware': {
        functions: ['Protect', 'Detect', 'Respond'],
        controls: ['PR.PT', 'PR.MA', 'DE.CM', 'RS.MI'],
    },
    'Ransomware': {
        functions: ['Protect', 'Detect', 'Respond', 'Recover'],
        controls: ['PR.DS', 'PR.IP', 'DE.CM', 'RS.RP', 'RC.RP'],
    },
    'Data Breach': {
        functions: ['Protect', 'Detect', 'Respond'],
        controls: ['PR.DS', 'PR.AC', 'DE.CM', 'RS.IM'],
    },
    'DDoS': {
        functions: ['Detect', 'Respond'],
        controls: ['DE.CM', 'RS.RP'],
    },
    'Unauthorized Access': {
        functions: ['Identify', 'Protect', 'Detect'],
        controls: ['ID.AM', 'PR.AC', 'DE.CM'],
    },
    'Phishing': {
        functions: ['Protect', 'Detect'],
        controls: ['PR.AT', 'PR.AC', 'DE.CM'],
    },
};

class NISTThreatIntelService {
    /**
     * Classify a threat based on CVE data and description
     */
    async classifyThreatFromCVEs(cveList, description) {
        try {
            if (!Array.isArray(cveList) || cveList.length === 0) {
                return this.classifyFromDescription(description);
            }

            const threatSignals = this.analyzeCVEsForThreats(cveList);
            return this.selectTopThreat(threatSignals, description);
        } catch (error) {
            logger.error(`Error classifying threat from CVEs: ${error.message}`);
            return this.classifyFromDescription(description);
        }
    }

    /**
     * Analyze CVEs to identify threat types
     */
    analyzeCVEsForThreats(cveList) {
        const threatScores = {};

        for (const cve of cveList) {
            const cveId = cve.id || cve.cveID;
            const description = (cve.description || cve.summary || '').toLowerCase();
            const severity = cve.severity || 'UNKNOWN';
            const baseScore = parseFloat(cve.baseScore || 0);

            // Score each threat type based on CVE characteristics
            for (const [threatType, patterns] of Object.entries(THREAT_PATTERNS)) {
                let score = 0;

                // Check pattern matches
                if (patterns.patterns.some(p => description.includes(p))) {
                    score += 30;
                }

                // Check keyword matches
                const keywordMatches = patterns.keywords.filter(k => description.includes(k));
                score += keywordMatches.length * 15;

                // Factor in severity
                if (patterns.severity.includes(severity)) {
                    score += 20;
                }

                // CVSS score bonus for high-risk CVEs
                if (baseScore >= 9.0) score += 25;
                else if (baseScore >= 7.0) score += 15;
                else if (baseScore >= 5.0) score += 5;

                if (score > 0) {
                    threatScores[threatType] = (threatScores[threatType] || 0) + score;
                }
            }
        }

        // Normalize and return sorted results
        return Object.entries(threatScores)
            .map(([type, score]) => ({
                threatType: type,
                score: Math.min(100, score),
                confidence: Math.min(95, 50 + (score / 100) * 45),
            }))
            .sort((a, b) => b.score - a.score);
    }

    /**
     * Classify threat from user description only
     */
    classifyFromDescription(description) {
        const desc = String(description || '').toLowerCase();
        let bestMatch = null;
        let bestScore = 0;

        for (const [threatType, patterns] of Object.entries(THREAT_PATTERNS)) {
            let score = 0;

            patterns.patterns.forEach(p => {
                if (desc.includes(p)) score += 30;
            });

            patterns.keywords.forEach(k => {
                if (desc.includes(k)) score += 20;
            });

            if (score > bestScore) {
                bestScore = score;
                bestMatch = threatType;
            }
        }

        return {
            threatType: bestMatch || 'Unknown',
            score: bestScore,
            confidence: Math.max(40, (bestScore / 50) * 100),
        };
    }

    /**
     * Select the top threat from analyzed signals
     */
    selectTopThreat(threatSignals, description) {
        if (threatSignals.length === 0) {
            return this.classifyFromDescription(description);
        }

        // Blend CVE-based classification with description-based one
        const descriptionBased = this.classifyFromDescription(description);
        const topCVEBased = threatSignals[0];

        // If description mentions specific threat, prefer it; otherwise use CVE data
        if (descriptionBased.confidence > 60) {
            return {
                ...topCVEBased,
                threatType: descriptionBased.threatType,
                confidence: Math.max(topCVEBased.confidence, descriptionBased.confidence),
                source: 'cve_and_description',
            };
        }

        return {
            ...topCVEBased,
            source: 'cve',
        };
    }

    /**
     * Get NIST mapping for a threat type
     */
    getNISTMapping(threatType) {
        const mapping = THREAT_TO_NIST[threatType];

        if (!mapping) {
            return {
                functions: ['Protect', 'Detect', 'Respond'],
                controls: ['PR.AC', 'DE.CM', 'RS.RP'],
            };
        }

        return mapping;
    }

    /**
     * Get all threat types this service can identify
     */
    getAllThreatTypes() {
        return Object.keys(THREAT_PATTERNS);
    }

    /**
     * Get threat characteristics for risk scoring
     */
    getThreatCharacteristics(threatType) {
        const patterns = THREAT_PATTERNS[threatType];
        if (!patterns) {
            return {
                defaultLikelihood: 2,
                defaultImpact: 2,
                affectedAssetTypes: ['System'],
            };
        }

        // Map threat type to typical likelihood and impact
        const characteristics = {
            'Malware': { likelihood: 3, impact: 3, assets: ['Server', 'Device', 'POS'] },
            'Ransomware': { likelihood: 2, impact: 4, assets: ['Server', 'Database', 'Device'] },
            'Data Breach': { likelihood: 2, impact: 4, assets: ['Database', 'Server', 'Device'] },
            'DDoS': { likelihood: 2, impact: 3, assets: ['Server', 'WiFi'] },
            'Unauthorized Access': { likelihood: 3, impact: 3, assets: ['Database', 'Server', 'Device'] },
            'Phishing': { likelihood: 3, impact: 2, assets: ['Device', 'Email'] },
        };

        return characteristics[threatType] || {
            likelihood: 2,
            impact: 2,
            assets: ['System'],
        };
    }

    /**
     * Enrich threat data with NIST controls
     */
    enrichWithNISTControls(threatType) {
        const mapping = this.getNISTMapping(threatType);
        const characteristics = this.getThreatCharacteristics(threatType);

        return {
            threatType,
            nistFunctions: mapping.functions,
            nistControls: mapping.controls,
            ...characteristics,
        };
    }

    /**
     * Clear cache for testing/refresh
     */
    clearCache() {
        THREAT_CACHE.clear();
        CVE_MITIGATIONS_CACHE.clear();
    }
}

module.exports = new NISTThreatIntelService();


