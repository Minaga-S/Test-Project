/**
 * NIST Cybersecurity Framework Mapping Service
 */

const { THREAT_KNOWLEDGE_BASE, NIST_FUNCTIONS, NIST_CONTROLS } = require('../utils/constants');
const logger = require('../utils/logger');

class NISTMappingService {
    /**
     * Get NIST mapping for threat type
     */
    getNISTMapping(threatType) {
        try {
            const threatEntry = THREAT_KNOWLEDGE_BASE.find(t => t.threatType === threatType);

            if (!threatEntry) {
                logger.warn(`No NIST mapping found for threat: ${threatType}`);
                return {
                    functions: this.getDefaultFunctions(),
                    controls: this.getDefaultControls(),
                };
            }

            return {
                functions: threatEntry.nistFunctions || [],
                controls: threatEntry.nistControls || [],
                recommendations: threatEntry.mitigationSteps || [],
            };

        } catch (error) {
            logger.error('NIST mapping error:', error.message);
            return {
                functions: this.getDefaultFunctions(),
                controls: this.getDefaultControls(),
            };
        }
    }

    /**
     * Get default NIST functions
     */
    getDefaultFunctions() {
        return ['Protect', 'Detect', 'Respond'];
    }

    /**
     * Get default NIST controls
     */
    getDefaultControls() {
        return ['PR.AC', 'DE.CM', 'RS.RP'];
    }

    /**
     * Get all NIST functions
     */
    getAllFunctions() {
        return NIST_FUNCTIONS;
    }

    /**
     * Get controls for function
     */
    getControlsForFunction(functionName) {
        return NIST_CONTROLS[functionName] || [];
    }

    /**
     * Get function description
     */
    getFunctionDescription(functionName) {
        const descriptions = {
            'Identify': 'Establish baseline and monitor IT assets and cybersecurity risks',
            'Protect': 'Implement safeguards to ensure delivery of critical services',
            'Detect': 'Develop and implement monitoring and detection capabilities',
            'Respond': 'Implement response procedures to address cybersecurity events',
            'Recover': 'Implement recovery procedures to restore normal operations',
        };

        return descriptions[functionName] || 'Unknown function';
    }

    /**
     * Map threat to NIST framework
     */
    mapThreatToNIST(threatType) {
        const mapping = this.getNISTMapping(threatType);

        return {
            threatType,
            functions: mapping.functions.map(f => ({
                name: f,
                description: this.getFunctionDescription(f),
            })),
            controls: mapping.controls.map(c => ({
                code: c,
                description: this.getControlDescription(c),
            })),
            recommendations: mapping.recommendations || [],
        };
    }

    /**
     * Get control description
     */
    getControlDescription(controlCode) {
        const controlDescriptions = {
            'PR.AC': 'Access Control - Manage access to systems and assets',
            'PR.AT': 'Awareness & Training - Support organizational cybersecurity awareness',
            'PR.DS': 'Data Security - Protect data from unauthorized access',
            'PR.IP': 'Information Protection - Implement protective measures',
            'PR.MA': 'Maintenance - Manage systems and hardware',
            'PR.PT': 'Protective Technology - Deploy protective technologies',
            'DE.AE': 'Anomalies & Events - Monitor systems for anomalies',
            'DE.CM': 'Continuous Monitoring - Monitor networks and systems',
            'RS.RP': 'Response Planning - Prepare incident response procedures',
            'RS.CO': 'Communications - Execute incident response',
            'RS.AN': 'Analysis - Investigate incidents',
            'RS.MI': 'Mitigation - Perform incident mitigation',
            'RS.IM': 'Improvements - Improve incident handling',
            'RC.RP': 'Recovery Planning - Establish recovery strategies',
            'RC.IM': 'Improvements - Improve recovery capabilities',
            'ID.AM': 'Asset Management - Catalog and inventory assets',
            'ID.BE': 'Business Environment - Understand business context',
            'ID.GV': 'Governance - Establish governance structure',
            'ID.RA': 'Risk Assessment - Assess cybersecurity risks',
            'ID.RM': 'Risk Management - Develop risk management strategy',
            'ID.SC': 'Supply Chain - Manage supply chain risk',
        };

        return controlDescriptions[controlCode] || 'Control description not available';
    }

    /**
     * Get compliance report
     */
    getComplianceReport(incidents) {
        const functionCoverage = {};
        const controlCoverage = {};

        NIST_FUNCTIONS.forEach(func => {
            functionCoverage[func] = 0;
        });

        incidents.forEach(incident => {
            const mapping = this.getNISTMapping(incident.threatType);

            mapping.functions.forEach(func => {
                functionCoverage[func]++;
            });

            mapping.controls.forEach(control => {
                controlCoverage[control] = (controlCoverage[control] || 0) + 1;
            });
        });

        return {
            functions: functionCoverage,
            controls: controlCoverage,
            totalIncidents: incidents.length,
        };
    }
}

module.exports = new NISTMappingService();