/**
 * Application Constants
 */

const ASSET_TYPES = [
    'POS',
    'Server',
    'WiFi',
    'Database',
    'Device',
    'Other',
];

const THREAT_TYPES = [
    'Phishing',
    'Malware',
    'Ransomware',
    'DDoS',
    'Unauthorized Access',
    'Data Breach',
    'Social Engineering',
    'Network Attack',
];

const RISK_LEVELS = {
    'Low': { min: 1, max: 4 },
    'Medium': { min: 5, max: 8 },
    'High': { min: 9, max: 12 },
    'Critical': { min: 13, max: 16 },
};

const INCIDENT_STATUS = [
    'Open',
    'InProgress',
    'Resolved',
];

const NIST_FUNCTIONS = [
    'Identify',
    'Protect',
    'Detect',
    'Respond',
    'Recover',
];

const NIST_CONTROLS = {
    'Identify': ['ID.AM', 'ID.BE', 'ID.GV', 'ID.RA', 'ID.RM', 'ID.SC'],
    'Protect': ['PR.AC', 'PR.AT', 'PR.DS', 'PR.IP', 'PR.MA', 'PR.PT'],
    'Detect': ['DE.AE', 'DE.CM'],
    'Respond': ['RS.RP', 'RS.CO', 'RS.AN', 'RS.MI', 'RS.IM'],
    'Recover': ['RC.RP', 'RC.IM'],
};

const THREAT_KNOWLEDGE_BASE = [
    {
        threatType: 'Phishing',
        threatCategory: 'Social Engineering',
        affectedAssetTypes: ['Device', 'Email'],
        nistFunctions: ['Protect', 'Detect'],
        nistControls: ['PR.AC', 'DE.CM'],
        mitigationSteps: [
            'Implement email filtering and anti-phishing tools',
            'Conduct regular phishing awareness training',
            'Enable multi-factor authentication',
            'Monitor email for suspicious activities',
        ],
    },
    {
        threatType: 'Malware',
        threatCategory: 'Malicious Software',
        affectedAssetTypes: ['POS', 'Server', 'Device'],
        nistFunctions: ['Protect', 'Detect', 'Respond'],
        nistControls: ['PR.PT', 'DE.CM', 'RS.IM'],
        mitigationSteps: [
            'Install and update antivirus/anti-malware software',
            'Keep operating systems and applications patched',
            'Restrict admin access and user permissions',
            'Regular system scans and monitoring',
        ],
    },
    {
        threatType: 'Ransomware',
        threatCategory: 'Malicious Software',
        affectedAssetTypes: ['Server', 'Database', 'Device'],
        nistFunctions: ['Protect', 'Detect', 'Respond', 'Recover'],
        nistControls: ['PR.DS', 'DE.CM', 'RS.RP', 'RC.RP'],
        mitigationSteps: [
            'Implement regular backups (offline and offsite)',
            'Deploy advanced threat protection',
            'Restrict user privileges and file access',
            'Create an incident response plan',
        ],
    },
    {
        threatType: 'DDoS',
        threatCategory: 'Network Attack',
        affectedAssetTypes: ['WiFi', 'Server'],
        nistFunctions: ['Detect', 'Respond'],
        nistControls: ['DE.CM', 'RS.RP'],
        mitigationSteps: [
            'Use DDoS mitigation services',
            'Implement rate limiting on network',
            'Monitor network traffic for anomalies',
            'Have an incident response plan',
        ],
    },
    {
        threatType: 'Unauthorized Access',
        threatCategory: 'Access Control',
        affectedAssetTypes: ['Database', 'Server', 'Device'],
        nistFunctions: ['Identify', 'Protect', 'Detect'],
        nistControls: ['ID.AM', 'PR.AC', 'DE.CM'],
        mitigationSteps: [
            'Implement strong password policies',
            'Enable multi-factor authentication',
            'Conduct regular access reviews',
            'Monitor access logs for suspicious activity',
        ],
    },
];

function calculateRiskLevel(likelihood, impact) {
    const riskScore = likelihood * impact;
    
    for (const [level, range] of Object.entries(RISK_LEVELS)) {
        if (riskScore >= range.min && riskScore <= range.max) {
            return { level, score: riskScore };
        }
    }
    
    return { level: 'Low', score: riskScore };
}

function generateIncidentId() {
    const date = new Date();
    const timestamp = date.getTime().toString().slice(-6);
    const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    return `INC-${timestamp}-${random}`;
}

module.exports = {
    ASSET_TYPES,
    THREAT_TYPES,
    RISK_LEVELS,
    INCIDENT_STATUS,
    NIST_FUNCTIONS,
    NIST_CONTROLS,
    THREAT_KNOWLEDGE_BASE,
    calculateRiskLevel,
    generateIncidentId,
};