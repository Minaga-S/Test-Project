/**
 * Application Constants
 */
// NOTE: Utility helpers: shared reusable functions/constants used across modules.


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

const DEPARTMENTS = [
    'Management',
    'Front Office',
    'Reservations',
    'Housekeeping',
    'Food and Beverage',
    'Finance',
    'Human Resources',
    'Security',
    'Maintenance',
    'Sales and Marketing',
    'IT and Systems',
    'Operations',
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
    DEPARTMENTS,
    calculateRiskLevel,
    generateIncidentId,
};

