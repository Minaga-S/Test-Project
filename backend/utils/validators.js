/**
 * Input Validators
 */
// NOTE: Utility helpers: shared reusable functions/constants used across modules.


function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password && password.length >= 8;
}

function validateAsset(assetData) {
    const errors = {};

    if (!assetData.assetName || !assetData.assetName.trim()) {
        errors.assetName = 'Asset name is required';
    }

    if (!assetData.assetType) {
        errors.assetType = 'Asset type is required';
    }

    if (!assetData.criticality) {
        errors.criticality = 'Criticality level is required';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors,
    };
}

function validateIncident(incidentData) {
    const errors = {};

    if (!incidentData.assetId) {
        errors.assetId = 'Asset ID is required';
    }

    if (!incidentData.description || incidentData.description.trim().length < 20) {
        errors.description = 'Description must be at least 20 characters';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors,
    };
}

module.exports = {
    validateEmail,
    validatePassword,
    validateAsset,
    validateIncident,
};
